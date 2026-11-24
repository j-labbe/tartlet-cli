import assert from "node:assert/strict";
import { createServer } from "node:https";
import { get } from "node:https";
import { connect } from "node:net";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomBytes, createHash } from "node:crypto";
import { Readable, PassThrough } from "node:stream";
import { WebSocketServer, createWebSocketStream } from "ws";
import ssh2 from "ssh2";
import { signJws, CloudAccessTokenClaimsSchema, AuthorizeSshKeyRequestSchema, AuthorizeSshKeyResponseSchema, verifyCloudAccessToken } from "@tartlet/protocol";
import { localTrust } from "../dist/http.js";
import { installSftp } from "./sftp.mjs";
import { generatePair } from "../dist/keypair.js";

const exec = promisify(execFile), token = () => randomBytes(32).toString("base64url");
const { Server, utils } = ssh2;
export async function certificates() {
  const directory = await mkdtemp(path.join(tmpdir(), "tartlet-test-cert-")), key = path.join(directory, "key.pem"), cert = path.join(directory, "cert.pem");
  await exec("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,IP:::1,DNS:localhost", "-addext", "basicConstraints=critical,CA:TRUE"]);
  return { directory, key: await readFile(key), cert: await readFile(cert), close: () => rm(directory, { recursive: true, force: true }) };
}
function authClient(client, state) {
  client.on("authentication", (context) => {
    if (context.method !== "publickey") { context.reject(); return; }
    const line = [...state.authorized].find((entry) => Buffer.from(entry.split(" ")[1], "base64").equals(context.key.data));
    if (!line) { context.reject(); return; }
    const key = utils.parseKey(line);
    if (context.signature && !key.verify(context.blob, context.signature, context.hashAlgo)) { context.reject(); return; }
    state.authentications++; context.accept();
  });
  client.on("ready", () => sessions(client, state));
  client.on("error", () => {});
}
function sessions(client, state) {
  client.on("session", (accept) => {
    const session = accept();
    session.on("pty", (accept) => { state.ptys++; accept(); });
    session.on("window-change", (accept) => accept?.());
    session.on("exec", (accept, _reject, info) => {
      state.commands.push(info.command); const channel = accept();
      channel.stderr.write("test-stderr\n"); channel.write(`ran:${info.command}\n`); channel.exit(info.command === "exit 7" ? 7 : 0); channel.end();
    });
    session.on("shell", (accept) => {
      state.shells++; const channel = accept(); channel.write("shell-ready\n");
      channel.on("data", () => { channel.exit(0); channel.end(); });
      channel.on("end", () => { channel.exit(0); channel.end(); });
    });
    session.on("sftp", (accept) => installSftp(accept(), state.files));
  });
  client.on("tcpip", (accept) => { const channel = accept(); channel.on("data", (data) => channel.write(data)); });
}
async function listening(server, host = "127.0.0.1") {
  await new Promise((resolve) => server.listen(0, host, resolve));
  return server.address().port;
}
async function readBody(req) { const chunks = []; for await (const chunk of req) chunks.push(chunk); return Buffer.concat(chunks).toString(); }
const send = (res, status, value) => res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(value));
async function issue(f) {
  if (!f.cloud) {
    const access_token = token(), refresh_token = token(); f.state.tokens.add(access_token); f.state.refresh.add(refresh_token);
    return { access_token, refresh_token, expires_in: 3600, token_type: "Bearer" };
  }
  const now = Math.floor(Date.now() / 1000);
  const claims = CloudAccessTokenClaimsSchema.parse({ typ: "tartlet-cloud-access", iss: f.endpoint.origin, aud: f.endpoint.origin, sub: `acct_${"a".repeat(26)}`, iat: now, nbf: now, exp: now + 600 });
  return { access_token: await signJws({ private_key: f.signing.privateKey, kid: "test", payload: claims }), expires_in: 600, token_type: "Bearer" };
}
async function tokenRequest(f, body, res) {
  switch (body.get("grant_type")) {
    case "urn:ietf:params:oauth:grant-type:device_code": {
      assert.equal(body.get("device_code"), f.state.device);
      const pending = f.state.deviceErrors.shift();
      if (pending) return send(res, 400, { error: pending });
      return send(res, 200, await issue(f));
    }
    case "refresh_token":
      assert.ok(f.state.refresh.delete(body.get("refresh_token"))); f.state.refreshes++;
      return send(res, 200, await issue(f));
    case "authorization_code": {
      const pending = f.state.codes.get(body.get("code"));
      assert.ok(pending); assert.equal(body.get("redirect_uri"), pending.redirect); assert.equal(body.get("client_id"), pending.client);
      assert.equal(createHash("sha256").update(body.get("code_verifier")).digest("base64url"), pending.challenge);
      f.state.codes.delete(body.get("code")); return send(res, 200, await issue(f));
    }
    default: return send(res, 400, { error: "unsupported_grant_type" });
  }
}
function metadata(f) {
  const origin = f.endpoint.origin;
  return { issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, registration_endpoint: `${origin}/register`, device_authorization_endpoint: `${origin}/device`, jwks_uri: `${origin}/jwks`, code_challenge_methods_supported: ["S256"], ...f.state.metadata };
}
async function oauthRequest(f, req, res, url, raw) {
  switch (url.pathname) {
    case "/.well-known/oauth-authorization-server": case "/.well-known/openid-configuration": return send(res, 200, metadata(f));
    case "/jwks": return send(res, 200, { keys: [{ ...await crypto.subtle.exportKey("jwk", f.signing.publicKey), kid: "test" }] });
    case "/register": {
      const client = JSON.parse(raw); assert.equal(client.token_endpoint_auth_method, "none"); f.state.registrations.push(client);
      return send(res, 201, { client_id: token(), token_endpoint_auth_method: "none" });
    }
    case "/authorize": {
      assert.equal(url.searchParams.get("code_challenge_method"), "S256");
      const code = token(), redirect = url.searchParams.get("redirect_uri");
      f.state.codes.set(code, { redirect, client: url.searchParams.get("client_id"), challenge: url.searchParams.get("code_challenge") });
      const callback = new URL(redirect); callback.searchParams.set("code", code); callback.searchParams.set("state", url.searchParams.get("state"));
      return res.writeHead(302, { Location: callback.href }).end();
    }
    case "/token": return tokenRequest(f, new URLSearchParams(raw), res);
    case "/device":
      f.state.device = token(); f.state.devices++;
      return send(res, 200, { device_code: f.state.device, user_code: "ABCD-EFGH", verification_uri: `${f.endpoint.origin}/activate`, expires_in: 600, interval: 1 });
    default: return apiRequest(f, req, res, url, raw);
  }
}
async function apiRequest(f, req, res, url, raw) {
  const bearer = req.headers.authorization?.replace(/^Bearer /, "");
  if (f.cloud) {
    await verifyCloudAccessToken({ jws: bearer, public_key: f.signing.publicKey, expected: { iss: f.endpoint.origin, aud: f.endpoint.origin } });
    assert.equal(url.pathname, "/v1/servers"); return send(res, 200, { servers: f.state.servers });
  }
  if (f.state.reason) return send(res, 401, { error: "invalid_token", error_description: f.state.reason });
  if (!f.state.tokens.has(bearer)) return send(res, 401, { error: "invalid_token", error_description: "wrong-audience" });
  if (url.pathname === "/mcp") {
    const message = JSON.parse(raw);
    if (message.method === "initialize") f.state.clientVersions.push(message.params.clientInfo.version);
    const result = message.method === "initialize" ? { protocolVersion: "2025-03-26", serverInfo: { name: "Tartlet", version: "0.2.0" }, capabilities: { tools: {} } } : { content: [], structuredContent: { vms: f.state.vms } };
    return send(res, 200, { jsonrpc: "2.0", id: message.id, result });
  }
  if (url.pathname === "/api/agent/authorize-ssh-key") {
    const body = AuthorizeSshKeyRequestSchema.parse(JSON.parse(raw)); assert.ok(f.state.vms.some((vm) => vm.name === body.vm));
    f.state.authorized.add(body.public_key); f.state.authorizations++;
    return send(res, 200, AuthorizeSshKeyResponseSchema.parse({ expires_at: new Date(Date.now() + 600000).toISOString(), host: "example.com", port: 22, user: "guest", host_key_alias: "vm-example-instance", known_hosts_line: `vm-example-instance ${f.state.wrongHost ? f.otherKey.public : f.hostKey.public}` }));
  }
  return send(res, 404, { error: "not_found" });
}
export async function fake(t, options = {}) {
  const certs = await certificates(), temporary = await mkdtemp(path.join(tmpdir(), "tartlet cli's & %test%-")), directory = path.join(temporary, "profile");
  const hostKey = generatePair(), otherKey = generatePair(), signing = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const state = { tokens: new Set(), refresh: new Set(), refreshes: 0, codes: new Map(), authorized: new Set(), authorizations: 0, authentications: 0, ptys: 0, shells: 0, registrations: [], deviceErrors: [], devices: 0, servers: [], vms: [{ name: "vm-example", label: "example" }], requests: [], commands: [], clientVersions: [], files: new Map(), metadata: {} };
  const ssh = new Server({ hostKeys: [hostKey.private] }, (client) => authClient(client, state));
  const port = await listening(ssh), webSockets = new WebSocketServer({ noServer: true });
  const f = { directory, certs, state, hostKey, otherKey, signing, webSockets, cloud: Boolean(options.cloud) };
  const https = createServer({ cert: certs.cert, key: certs.key }, (req, res) => {
    void (async () => { state.requests.push({ path: req.url, authorization: req.headers.authorization, cookie: req.headers.cookie }); await oauthRequest(f, req, res, new URL(req.url, f.endpoint.origin), await readBody(req)); })().catch((error) => { state.failure = error; send(res, 500, { error: "server_error" }); });
  });
  const clients = new Set();
  https.on("connection", (socket) => { clients.add(socket); socket.on("close", () => clients.delete(socket)); });
  https.on("upgrade", (req, socket, head) => {
    assert.equal(req.headers.cookie, undefined); assert.equal(new URL(req.url, f.endpoint.origin).search, "");
    assert.ok(state.tokens.has(req.headers.authorization?.replace(/^Bearer /, "")));
    state.requests.push({ path: req.url, authorization: req.headers.authorization });
    if (state.tunnelReason) {
      const body = JSON.stringify({ error: { code: "invalid_token", action: "a person must act", message: state.tunnelReason } });
      socket.end(`HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`); return;
    }
    webSockets.handleUpgrade(req, socket, head, (ws) => {
      const stream = createWebSocketStream(ws), upstream = connect(port, "127.0.0.1");
      const close = () => { upstream.destroy(); stream.destroy(); ws.terminate(); };
      upstream.on("error", close); stream.on("error", close); upstream.on("close", close); stream.on("close", close);
      stream.pipe(upstream).pipe(stream);
    });
  });
  const host = options.host ?? "127.0.0.1", authority = host.includes(":") ? `[${host}]` : host;
  f.endpoint = { origin: `https://${authority}:${await listening(https, host)}`, trust: localTrust(certs.cert) };
  t.after(async () => {
    for (const client of clients) client.destroy();
    for (const ws of webSockets.clients) ws.terminate();
    webSockets.close(); https.closeAllConnections();
    await Promise.all([new Promise((resolve) => https.close(resolve)), new Promise((resolve) => ssh.close(resolve))]);
    await rm(temporary, { recursive: true, force: true }); await certs.close(); assert.equal(state.failure, undefined);
  });
  return f;
}
export function testIO(f, input = "") {
  const stdout = new PassThrough(), stderr = new PassThrough(), stdin = Readable.from([input]);
  let output = "", errors = ""; stdout.on("data", (data) => { output += data; }); stderr.on("data", (data) => { errors += data; });
  const io = { stdin, stdout, stderr, say: (value) => stderr.write(`${value}\n`), choose: async () => 0,
    open: async (url) => {
      const callback = await new Promise((resolve, reject) => get(url, { ca: f.certs.cert }, (res) => { res.resume(); resolve(res.headers.location); }).on("error", reject));
      assert.ok(callback); assert.equal((await fetch(callback)).status, 200);
    },
  };
  return { io, output: () => output, errors: () => errors };
}
