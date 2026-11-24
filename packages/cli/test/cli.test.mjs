import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { PassThrough } from "node:stream";
import { run } from "../dist/cli.js";
import { login, connectedProfile } from "../dist/profiles.js";
import { readState, changeState } from "../dist/storage.js";
import { authorize } from "../dist/access.js";
import { ssh } from "../dist/ssh.js";
import { fake, testIO } from "./fixture.mjs";

async function signedIn(t) {
  const f = await fake(t), io = testIO(f);
  await run(["login", "--server", f.endpoint.origin, "--ca", path.join(f.certs.directory, "cert.pem")], { directory: f.directory, io: io.io });
  return { f, io };
}
test("browser PKCE sign-in saves a private pinned profile and no cloud credentials", async (t) => {
  const { f, io } = await signedIn(t), state = await readState(f.directory), profile = state.profiles[0];
  assert.equal(profile.origin, f.endpoint.origin); assert.equal(profile.trust.root_sha256, f.endpoint.trust.root_sha256);
  assert.equal(f.state.registrations[0].token_endpoint_auth_method, "none"); assert.equal(io.output(), "");
  assert.ok(!io.errors().includes(profile.tokens.access_token));
  assert.equal((await stat(f.directory)).mode & 0o777, 0o700); assert.equal((await stat(path.join(f.directory, "profiles.json"))).mode & 0o777, 0o600);
});
test("device sign-in uses the server grant and prints only the verification code", async (t) => {
  const f = await fake(t), io = testIO(f);
  await run(["login", "--server", f.endpoint.origin, "--ca", path.join(f.certs.directory, "cert.pem"), "--device"], { directory: f.directory, io: io.io });
  assert.equal(f.state.devices, 1); assert.match(io.errors(), /ABCD-EFGH/); assert.ok(!io.errors().includes(f.state.device));
  assert.equal(f.state.registrations[0].redirect_uris.length, 0);
});
test("cloud PKCE verifies its signed access token and then signs in to the chosen server", async (t) => {
  const f = await fake(t), cloud = await fake(t, { cloud: true }), serverIO = testIO(f), cloudIO = testIO(cloud);
  cloud.state.servers = [{ server_id: `srv_${"a".repeat(26)}`, org_id: `org_${"a".repeat(26)}`, name: "Server 1", addresses: [{ kind: "tailnet", host: "127.0.0.1", port: Number(new URL(f.endpoint.origin).port) }], online: true }];
  const io = { ...serverIO.io, open: (url) => new URL(url).origin === cloud.endpoint.origin ? cloudIO.io.open(url) : serverIO.io.open(url) };
  await login({ directory: f.directory, ca: path.join(f.certs.directory, "cert.pem"), device: false, io, cloud: cloud.endpoint });
  assert.equal(cloud.state.registrations.length, 0); assert.equal(f.state.registrations.length, 1);
  const profile = (await readState(f.directory)).profiles[0]; assert.equal(profile.server_id, cloud.state.servers[0].server_id);
  const cloudBearer = cloud.state.requests.find((request) => request.path === "/v1/servers").authorization;
  assert.ok(!f.state.requests.some((request) => request.authorization === cloudBearer));
  assert.ok(!(await readFile(path.join(f.directory, "profiles.json"), "utf8")).includes(cloudBearer.slice(7)));
});
test("cloud metadata cannot replace a saved server origin or trust pin", async (t) => {
  const { f, io } = await signedIn(t), cloud = await fake(t, { cloud: true }), cloudIO = testIO(cloud);
  const server_id = `srv_${"a".repeat(26)}`;
  await changeState(f.directory, async (state) => { state.profiles[0].server_id = server_id; });
  cloud.state.servers = [{ server_id, org_id: `org_${"a".repeat(26)}`, name: "Server 1", addresses: [{ kind: "lan", host: "example.com" }], online: false }];
  await login({ directory: f.directory, device: false, io: { ...io.io, open: (url) => new URL(url).origin === cloud.endpoint.origin ? cloudIO.io.open(url) : io.io.open(url) }, cloud: cloud.endpoint });
  assert.equal((await readState(f.directory)).profiles[0].origin, f.endpoint.origin);
  assert.equal((await readState(f.directory)).profiles[0].trust.root_sha256, f.endpoint.trust.root_sha256);
});
test("cloud discovery preserves a root CA profile first saved by direct login", async (t) => {
  const { f, io } = await signedIn(t), cloud = await fake(t, { cloud: true }), cloudIO = testIO(cloud);
  cloud.state.servers = [{ server_id: `srv_${"a".repeat(26)}`, org_id: `org_${"a".repeat(26)}`, name: "Server 1", addresses: [{ kind: "lan", host: "127.0.0.1", port: Number(new URL(f.endpoint.origin).port) }], online: true }];
  await login({ directory: f.directory, device: false, io: { ...io.io, open: (url) => new URL(url).origin === cloud.endpoint.origin ? cloudIO.io.open(url) : io.io.open(url) }, cloud: cloud.endpoint });
  const state = await readState(f.directory); assert.equal(state.profiles.length, 1);
  assert.equal(state.profiles[0].trust.root_sha256, f.endpoint.trust.root_sha256); assert.equal(state.profiles[0].server_id, cloud.state.servers[0].server_id);
});
test("refresh token rotation is serialized across concurrent connections", async (t) => {
  const { f } = await signedIn(t);
  await changeState(f.directory, async (state) => { state.profiles[0].expires_at = Date.now() - 1; });
  const profiles = await Promise.all([connectedProfile(f.directory), connectedProfile(f.directory), connectedProfile(f.directory)]);
  assert.equal(f.state.refreshes, 1); assert.equal(new Set(profiles.map((entry) => entry.tokens.access_token)).size, 1);
});
test("ssh resolves a label, authorizes on each connect, and carries stdout, stderr and status", async (t) => {
  const { f } = await signedIn(t), first = testIO(f), second = testIO(f);
  assert.equal(await run(["ssh", "example", "--", "printf", "hello"], { directory: f.directory, io: first.io }), 0);
  assert.equal(await run(["ssh", "vm-example", "--", "exit 7"], { directory: f.directory, io: second.io }), 7);
  assert.equal(first.output(), "ran:printf hello\n"); assert.equal(first.errors(), "test-stderr\n");
  assert.equal(f.state.authorizations, 2); assert.equal(f.state.authorized.size, 1);
  const tunnels = f.state.requests.filter((request) => request.path.startsWith("/api/agent/tunnel/"));
  assert.equal(tunnels.length, 2); assert.ok(tunnels.every((request) => request.authorization.startsWith("Bearer ") && !request.path.includes("?") && !request.cookie));
});
test("interactive SSH requests a PTY and restores the terminal", async (t) => {
  const { f } = await signedIn(t), io = testIO(f, "exit\n"), raw = [];
  io.io.stdin.isTTY = true; io.io.stdin.isRaw = false; io.io.stdin.setRawMode = (value) => { raw.push(value); };
  const access = await authorize(f.directory, "vm-example", { label: false });
  assert.equal(await ssh(access, [], io.io), 0); assert.equal(f.state.ptys, 1); assert.deepEqual(raw, [true, false]); assert.match(io.output(), /shell-ready/);
});
test("cp uploads and downloads exact file bytes with one authorization per connect", async (t) => {
  const { f, io } = await signedIn(t), input = path.join(f.directory, "input.bin"), output = path.join(f.directory, "output.bin"), bytes = randomBytes(200000);
  await writeFile(input, bytes);
  await run(["cp", input, "example:/tmp/input.bin"], { directory: f.directory, io: io.io });
  await run(["cp", "example:/tmp/input.bin", output], { directory: f.directory, io: io.io });
  assert.deepEqual(await readFile(output), bytes); assert.equal(f.state.authorizations, 2);
  assert.equal(createHash("sha256").update(f.state.files.get("/tmp/input.bin")).digest("hex"), createHash("sha256").update(bytes).digest("hex"));
});
test("ssh refuses a different host key before authentication", async (t) => {
  const { f, io } = await signedIn(t); f.state.wrongHost = true;
  await assert.rejects(run(["ssh", "vm-example", "--", "true"], { directory: f.directory, io: io.io }), /verification failed|Host denied/i);
  assert.equal(f.state.authentications, 0);
});
test("server 401 reasons remain named and tokens are absent from diagnostics", async (t) => {
  const { f, io } = await signedIn(t);
  for (const reason of ["expired", "revoked", "wrong-audience", "bad-signature", "malformed"]) {
    f.state.reason = reason;
    await assert.rejects(run(["ssh", "vm-example", "--", "true"], { directory: f.directory, io: io.io }), new RegExp(reason));
  }
});
test("link and unlink change only the local key selection", async (t) => {
  const { f, io } = await signedIn(t), before = f.state.requests.length;
  await run(["link", "--generate"], { directory: f.directory, io: io.io });
  const key = (await readState(f.directory)).key; assert.equal(key.kind, "file");
  assert.equal((await stat(key.private_path)).mode & 0o777, 0o600);
  await run(["unlink"], { directory: f.directory, io: io.io });
  assert.equal((await readState(f.directory)).key, undefined); assert.equal(f.state.requests.length, before);
});
test("native SSH uses the generated private config and strict known_hosts pin", { skip: process.platform === "win32" }, async (t) => {
  const { f } = await signedIn(t), io = testIO(f);
  await run(["proxy", "vm-example", "--config"], { directory: f.directory, io: io.io });
  const config = io.output().trim(), text = await readFile(config, "utf8"), knownHosts = path.join(path.dirname(config), "known_hosts");
  assert.match(text, /StrictHostKeyChecking yes/); assert.notEqual((await readFile(knownHosts))[0], 0xef);
  const result = await child(["-F", config, "vm-example", "printf native"]);
  assert.equal(result.code, 0, result.stderr); assert.equal(result.stdout, "ran:printf native\n"); assert.equal(f.state.authorizations, 2);
});
test("native SSH refuses a different pinned host key", { skip: process.platform === "win32" }, async (t) => {
  const { f } = await signedIn(t), io = testIO(f); f.state.wrongHost = true;
  await run(["proxy", "vm-example", "--config"], { directory: f.directory, io: io.io });
  const result = await child(["-F", io.output().trim(), "vm-example", "true"]);
  assert.equal(result.code, 255); assert.match(result.stderr, /Host key verification failed|IDENTIFICATION HAS CHANGED/i);
});
export function child(args) {
  return new Promise((resolve, reject) => {
    const process = spawn("ssh", args), stdout = new PassThrough(), stderr = new PassThrough(); let output = "", errors = "";
    stdout.on("data", (chunk) => { output += chunk; }); stderr.on("data", (chunk) => { errors += chunk; });
    process.stdout.pipe(stdout); process.stderr.pipe(stderr); process.stdin.end(); process.on("error", reject);
    const timer = setTimeout(() => { process.kill("SIGKILL"); reject(new Error("Native SSH timed out.")); }, 20000);
    process.on("close", (code) => { clearTimeout(timer); resolve({ code, stdout: output, stderr: errors }); });
  });
}
test("a failed WebSocket upgrade preserves the server's named 401 reason", async (t) => {
  const { f, io } = await signedIn(t); f.state.tunnelReason = "revoked";
  await assert.rejects(run(["ssh", "vm-example", "--", "true"], { directory: f.directory, io: io.io }), /HTTP 401: invalid_token. revoked/);
});
test("cloud device sign-in obtains the directory token and a separate server grant", async (t) => {
  const f = await fake(t), cloud = await fake(t, { cloud: true }), io = testIO(f);
  cloud.state.servers = [{ server_id: `srv_${"a".repeat(26)}`, org_id: `org_${"a".repeat(26)}`, name: "Server 1", addresses: [{ kind: "lan", host: "127.0.0.1", port: Number(new URL(f.endpoint.origin).port) }], online: true }];
  await login({ directory: f.directory, ca: path.join(f.certs.directory, "cert.pem"), device: true, io: io.io, cloud: cloud.endpoint });
  assert.equal(cloud.state.devices, 1); assert.equal(f.state.devices, 1);
  assert.equal(cloud.state.registrations.length, 0); assert.equal(f.state.registrations.length, 1);
  const token = cloud.state.requests.find((request) => request.path === "/v1/servers").authorization;
  assert.ok(!f.state.requests.some((request) => request.authorization === token));
});
