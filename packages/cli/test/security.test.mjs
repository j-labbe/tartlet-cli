import assert from "node:assert/strict";
import { test } from "node:test";
import { randomBytes, generateKeyPairSync } from "node:crypto";
import path from "node:path";
import { spawn } from "node:child_process";
import { get } from "node:http";
import { signJws, CloudAccessTokenClaimsSchema, PublicKeySchema } from "@tartlet/protocol";
import ssh2 from "ssh2";
import { deviceSignIn, discover, loopback, verifyCloudToken } from "../dist/oauth.js";
import { tlsOptions, json, localTrust, sameOriginUrl, requestJson } from "../dist/http.js";
import { configDirectory, windowsPrivate, readState, changeState } from "../dist/storage.js";
import { copyLocation, copyPlan } from "../dist/copy.js";
import { commandArgument, sshConfigValue } from "../dist/proxy.js";
import { keepSecret, safeMessage, networkError } from "../dist/errors.js";
import { encodeEd25519Pair } from "../dist/keypair.js";
import { run } from "../dist/cli.js";
import { fake, testIO } from "./fixture.mjs";

const secret = () => randomBytes(32).toString("base64url");
test("Windows ACL replaces inherited and explicit access with the current account", async () => {
  const directory = "C:\\Example\\Agent 1\\private & data", calls = [];
  await windowsPrivate(directory, async (...args) => { calls.push(args); });
  const [program, args, options] = calls[0], script = Buffer.from(args[3], "base64").toString("utf16le");
  assert.equal(program, "powershell.exe"); assert.equal(options.env.TARTLET_ACL_DIRECTORY, directory);
  assert.match(script, /New-Object System.Security.AccessControl.DirectorySecurity/);
  assert.match(script, /SetAccessRuleProtection\(\$true, \$false\)/); assert.match(script, /WindowsIdentity.*GetCurrent/);
  assert.match(script, /FullControl.*ContainerInherit, ObjectInherit.*Allow/); assert.ok(!script.includes(directory));
  await assert.rejects(windowsPrivate(directory, async () => { throw new Error("ACL denied"); }), /ACL denied/);
});
test("Windows profile and copy paths preserve drive letters and spaces", () => {
  assert.equal(configDirectory("win32", { LOCALAPPDATA: "C:\\Example\\Agent 1\\AppData\\Local" }, "C:\\Example\\Agent 1"), "C:\\Example\\Agent 1\\AppData\\Local\\tartlet");
  assert.deepEqual(copyLocation("C:\\Example\\file.txt", "win32"), { kind: "local", path: "C:\\Example\\file.txt" });
  assert.equal(copyLocation("vm-example:/tmp/file", "win32").kind, "remote");
  assert.throws(() => commandArgument("C:\\Example\\%PATH%", "win32"), /metacharacters/);
  assert.equal(commandArgument("C:\\Example\\Agent 1", "win32"), '"C:/Example/Agent 1"');
  assert.equal(sshConfigValue("C:\\Example\\Agent 1\\known_hosts"), '"C:/Example/Agent 1/known_hosts"');
  assert.throws(() => copyPlan("vm-example:/file", "example:/file"), /one local file/);
});
test("diagnostics redact complete tokens before limiting output", () => {
  const value = keepSecret(secret()), long = keepSecret(randomBytes(4000).toString("base64url"));
  const message = safeMessage(new Error(`${value}\n${long}`));
  assert.equal(message, "[redacted] [redacted]"); assert.ok(!message.includes(value));
  const prefix = keepSecret(secret()), overlapping = keepSecret(`${prefix}${secret()}`);
  assert.ok(safeMessage(new Error(overlapping)) === "[redacted]", "Overlapping credentials must be fully redacted.");
  assert.match(networkError({ code: "ENOTFOUND" }).message, /Turn on Tailscale/);
  assert.match(networkError({ code: "ENETUNREACH" }).message, /network/);
  assert.match(networkError({ code: "ECONNREFUSED" }).message, /server is down/);
});
test("PKCE callback rejects wrong state and non-loopback Host without consuming the login", async () => {
  const state = secret(), callback = await loopback(state, 10000);
  try {
    assert.equal((await fetch(`${callback.redirect}?state=wrong&code=example`)).status, 400);
    assert.equal((await fetch(`${callback.redirect}?state=${encodeURIComponent("é".repeat(state.length))}&code=example`)).status, 400);
    const invalidHost = await new Promise((resolve, reject) => get(`${callback.redirect}?state=${state}&code=example`, { headers: { Host: "example.com" } }, (res) => { res.resume(); resolve(res.statusCode); }).on("error", reject));
    assert.equal(invalidHost, 400);
    const code = secret(); assert.equal((await fetch(`${callback.redirect}?state=${state}&code=${code}`)).status, 200); assert.equal(await callback.code, code);
  } finally { callback.close(); }
});
test("device polling honors pending, slow_down, timeout backoff, and denial", async (t) => {
  const f = await fake(t), io = testIO(f), metadata = await discover(f.endpoint), waits = [];
  f.state.deviceErrors = ["authorization_pending", "slow_down"];
  const input = { endpoint: f.endpoint, metadata, device: true, cloud: false, io: io.io };
  await deviceSignIn(input, "test-client", async (ms) => { waits.push(ms); });
  assert.deepEqual(waits, [1000, 1000, 6000]);
  f.state.deviceErrors = ["access_denied"];
  await assert.rejects(deviceSignIn(input, "test-client", async () => {}), /access_denied/);
  const backoff = []; let polls = 0;
  await deviceSignIn(input, "test-client", async (ms) => { backoff.push(ms); }, async (request) => {
    if (polls++ === 0) throw networkError({ code: "ETIMEDOUT" });
    return requestJson(request);
  });
  assert.deepEqual(backoff, [1000, 2000]);
});
test("OAuth metadata cannot send credentials outside the saved HTTPS origin", async (t) => {
  const f = await fake(t); f.state.metadata = { token_endpoint: "https://example.com/token" };
  await assert.rejects(discover(f.endpoint), /outside its saved HTTPS origin/);
  assert.throws(() => sameOriginUrl(f.endpoint.origin, "http://example.com/token"), /outside/);
});
test("HTTPS CA pin tampering fails before any request", async (t) => {
  const f = await fake(t), before = f.state.requests.length;
  assert.throws(() => tlsOptions({ ...f.endpoint.trust, root_sha256: "0".repeat(64) }), /does not match its pin/);
  const wrong = await fake(t);
  await assert.rejects(json({ endpoint: { ...f.endpoint, trust: localTrust(wrong.certs.cert) }, url: `${f.endpoint.origin}/.well-known/oauth-authorization-server` }, { safeParse: () => ({ success: true }) }));
  assert.equal(f.state.requests.length, before);
});
test("cloud tokens require the protocol signature, audience, and expiry", async (t) => {
  const cloud = await fake(t, { cloud: true }), metadata = await discover(cloud.endpoint, true), now = Math.floor(Date.now() / 1000);
  const claims = { typ: "tartlet-cloud-access", iss: cloud.endpoint.origin, aud: cloud.endpoint.origin, sub: `acct_${"a".repeat(26)}`, iat: now, nbf: now, exp: now + 600 };
  const sign = (payload, key = cloud.signing.privateKey) => signJws({ payload: CloudAccessTokenClaimsSchema.parse(payload), private_key: key, kid: "test" });
  await verifyCloudToken(cloud.endpoint, metadata, await sign(claims));
  await assert.rejects(verifyCloudToken(cloud.endpoint, metadata, await sign({ ...claims, iss: "https://example.com", aud: "https://example.com" })), /expected fields/);
  await assert.rejects(verifyCloudToken(cloud.endpoint, metadata, await sign({ ...claims, iat: now - 1000, nbf: now - 1000, exp: now - 400 })), /expired/);
  const other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  await assert.rejects(verifyCloudToken(cloud.endpoint, metadata, await sign(claims, other.privateKey)), /signature/);
});
test("Ed25519 keys retain a leading zero public byte and work with the SSH parser", () => {
  let chosen;
  for (let index = 0; index < 8192; index++) {
    const pair = generateKeyPairSync("ed25519"), jwk = pair.publicKey.export({ format: "jwk" });
    if (Buffer.from(jwk.x, "base64url")[0] === 0) { chosen = pair; break; }
  }
  assert.ok(chosen);
  const pair = encodeEd25519Pair(chosen), parsed = ssh2.utils.parseKey(pair.private);
  assert.ok(!(parsed instanceof Error)); assert.ok(parsed.isPrivateKey()); assert.equal(PublicKeySchema.parse(pair.public), pair.public);
  const data = randomBytes(128); assert.ok(parsed.verify(data, parsed.sign(data)));
});
test("file key selection and ssh-agent selection sign with the chosen key", { skip: process.platform === "win32" }, async (t) => {
  const f = await fake(t), io = testIO(f);
  await run(["login", "--server", f.endpoint.origin, "--ca", path.join(f.certs.directory, "cert.pem")], { directory: f.directory, io: io.io });
  await run(["link", "--generate"], { directory: f.directory, io: io.io });
  const choice = (await readState(f.directory)).key;
  await run(["link", choice.public_path, "--identity", choice.private_path], { directory: f.directory, io: io.io });
  const socket = path.join(f.directory, "agent.sock"), child = spawn("ssh-agent", ["-D", "-a", socket]);
  let errors = ""; child.stderr.on("data", (chunk) => { errors += chunk; });
  const prior = process.env.SSH_AUTH_SOCK; process.env.SSH_AUTH_SOCK = socket;
  t.after(() => { child.kill("SIGTERM"); if (prior === undefined) delete process.env.SSH_AUTH_SOCK; else process.env.SSH_AUTH_SOCK = prior; });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`SSH agent did not start: ${errors}`)), 5000);
    child.stdout.once("data", () => { clearTimeout(timeout); resolve(); }); child.once("error", reject);
  });
  await new Promise((resolve, reject) => {
    const add = spawn("ssh-add", [choice.private_path], { env: process.env }); add.on("error", reject); add.on("close", (code) => code === 0 ? resolve() : reject(new Error("Cannot add test key.")));
  });
  const { fingerprint } = await import("../dist/keys.js");
  await run(["link", "--agent", fingerprint(choice.public_key)], { directory: f.directory, io: io.io });
  const commandIO = testIO(f);
  assert.equal(await run(["ssh", "vm-example", "--", "true"], { directory: f.directory, io: commandIO.io }), 0);
  assert.equal((await readState(f.directory)).key.kind, "agent");
  await changeState(f.directory, async (state) => { state.key.public_key = PublicKeySchema.parse(f.otherKey.public); });
  await assert.rejects(run(["ssh", "vm-example", "--", "true"], { directory: f.directory, io: commandIO.io }), /authentication methods failed/);
});
test("help is usable without network or a configuration folder", async () => {
  const io = testIO({}); assert.equal(await run(["--help"], { directory: "/not-used", io: io.io }), 0); assert.match(io.output(), /Usage: tartlet/);
});
