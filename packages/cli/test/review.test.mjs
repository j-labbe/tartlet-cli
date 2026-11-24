import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, rm, utimes, cp, writeFile, readFile, readdir, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { PassThrough } from "node:stream";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { ProfileSchema, privateDirectory, privateWrite, readState, withLock } from "../dist/storage.js";
import { login } from "../dist/profiles.js";
import { run } from "../dist/cli.js";
import { authorize, resolveVm } from "../dist/access.js";
import { nativeConfig, proxy, commandArgument } from "../dist/proxy.js";
import { networkError } from "../dist/errors.js";
import { fake, testIO } from "./fixture.mjs";

const exec = promisify(execFile);
async function temporary(t, prefix = "tartlet-review-") {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  t.after(() => rm(directory, { recursive: true, force: true })); return directory;
}
async function signedIn(t, options) {
  const f = await fake(t, options), io = testIO(f);
  await login({ directory: f.directory, server: f.endpoint.origin, ca: path.join(f.certs.directory, "cert.pem"), device: false, io: io.io });
  return { f, io };
}
async function bounded(promise, message, timeout = 5000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeout); })]); }
  finally { clearTimeout(timer); }
}
async function openProxy(t, options) {
  const { f, io } = await signedIn(t, options), access = await authorize(f.directory, "vm-example", { label: false });
  const stdin = new PassThrough(), stdout = new PassThrough(); stdout.resume();
  const opened = once(f.webSockets, "headers");
  const running = proxy(access, { ...io.io, stdin, stdout });
  void running.catch(() => {});
  t.after(async () => { stdin.end(); await bounded(running, "The proxy did not clean up.").catch(() => {}); stdin.destroy(); stdout.destroy(); });
  await bounded(opened, "The proxy did not open a tunnel.");
  return { f, stdin, stdout, running };
}
test("a clean tunnel disconnect ends the proxy while stdin remains open", async (t) => {
  const { f, stdin, stdout, running } = await openProxy(t);
  for (const socket of f.webSockets.clients) socket.close(1000);
  await bounded(running, "A clean server disconnect must finish the proxy.");
  assert.equal(stdin.writableEnded, false); assert.equal(stdout.writableEnded, true);
});
test("stdin EOF flushes queued bytes before closing the proxy", async (t) => {
  const received = [], bytes = randomBytes(2 * 1024 * 1024); let closed;
  const { stdin, stdout, running } = await openProxy(t, { tunnel(socket) {
    socket.on("message", (data) => received.push(data)); closed = once(socket, "close");
  } });
  stdin.end(bytes);
  await bounded(running, "Input EOF must finish the proxy.");
  const [code] = await bounded(closed, "The tunnel must close after the input is sent.");
  assert.deepEqual(Buffer.concat(received), bytes); assert.equal(code, 1005); assert.equal(stdout.writableEnded, true);
});
test("native proxy commands carry the config folder as a quoted argument", async (t) => {
  const { f } = await signedIn(t), access = await authorize(f.directory, "vm-example", { label: false });
  for (const platform of ["darwin", "win32"]) {
    const text = nativeConfig(access, "known_hosts", "C:\\Example\\Agent 1 & %data%", "C:\\Example\\Node Path\\node.exe", "C:\\Example\\CLI Path\\main.js", platform);
    const line = text.split("\n").find((value) => value.trimStart().startsWith("ProxyCommand "));
    assert.ok(line); assert.ok(!/ProxyCommand (?:env|set) /.test(line));
    assert.match(line, /--config-dir/); assert.ok(!line.includes("TARTLET_CONFIG_DIR="));
  }
  assert.equal(commandArgument("C:\\Example\\Agent 1 & %data%\\", "win32"), '"C:\\Example\\Agent 1 & %data%\\\\"');
});
test("--config-dir selects the private folder without an environment variable", async (t) => {
  const directory = path.join(await temporary(t), "selected folder"), io = testIO({});
  assert.equal(await run(["unlink", "--config-dir", directory], { io: io.io }), 0);
  assert.equal(JSON.parse(await readFile(path.join(directory, "profiles.json"), "utf8")).version, 1);
});
test("IPv6 server login saves a schema-valid default profile name", async (t) => {
  const f = await fake(t, { host: "::1" }), io = testIO(f);
  const profile = await login({ directory: f.directory, server: f.endpoint.origin, ca: path.join(f.certs.directory, "cert.pem"), device: false, io: io.io });
  assert.ok(ProfileSchema.safeParse(profile).success); assert.match(profile.name, /^[A-Za-z0-9]/);
  assert.equal((await readState(f.directory)).active, profile.name);
});
test("a bad profile name fails before OAuth starts", async (t) => {
  const f = await fake(t), io = testIO(f);
  await assert.rejects(login({ directory: f.directory, server: f.endpoint.origin, profile: "bad name", ca: path.join(f.certs.directory, "cert.pem"), device: false, io: io.io }));
  assert.equal(f.state.requests.length, 0, "An invalid profile name must not start sign-in.");
});
test("certificate failures explain the server and CA login flags", () => {
  const expected = "The server's HTTPS certificate is not trusted. If your administrator gave you a root certificate, run `tartlet login --server <url> --ca <root.pem>`.";
  for (const code of ["SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "DEPTH_ZERO_SELF_SIGNED_CERT", "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_HAS_EXPIRED"]) assert.equal(networkError({ code }).message, expected);
});
test("cloud certificate errors do not suggest a server CA override", () => {
  for (const code of ["SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "DEPTH_ZERO_SELF_SIGNED_CERT", "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_HAS_EXPIRED"]) {
    const error = networkError({ code }, "https://app.tartlet.io");
    assert.match(error.message, /cloud.*certificate/i); assert.ok(!error.message.includes("--ca")); assert.ok(!error.message.includes("--server"));
  }
});
test("cloud connectivity errors do not suggest Tailscale", () => {
  const error = networkError({ code: "ENOTFOUND" }, "https://app.tartlet.io");
  assert.ok(!error.message.includes("Tailscale")); assert.match(error.message, /cloud|internet/i);
});
test("bad VM input has a plain message before any request", async (t) => {
  const { f } = await signedIn(t), profile = (await readState(f.directory)).profiles[0], before = f.state.requests.length;
  await assert.rejects(resolveVm(profile, "bad/name"), { message: "A VM name or task label has up to 63 lowercase letters, numbers or dashes, and starts with a letter or number." });
  assert.equal(f.state.requests.length, before);
});
test("a stale profile lock is recovered automatically", async (t) => {
  const directory = await temporary(t), lock = path.join(directory, "profiles.lock");
  await mkdir(lock); const stale = new Date(Date.now() - 65000); await utimes(lock, stale, stale);
  assert.equal(await bounded(withLock(directory, "profiles", async () => "recovered"), "An old lock must be recovered."), "recovered");
});
test("a busy profile lock names the path for last-resort removal", async (t) => {
  const directory = await temporary(t), lock = path.join(directory, "profiles.lock");
  await mkdir(lock); await writeFile(path.join(lock, "manual"), "occupied");
  const now = Date.now(); let calls = 0;
  t.mock.method(Date, "now", () => now + (calls++ === 0 ? 0 : 31000));
  await assert.rejects(withLock(directory, "profiles", async () => assert.fail("A busy lock must not be entered.")), (error) => {
    assert.ok(error.message.includes(lock)); assert.match(error.message, /delete/i); assert.match(error.message, /no .*command.*running/i); return true;
  });
});
test("an existing Windows folder is protected before writing a private file", async (t) => {
  const directory = path.join(await temporary(t), "existing"), file = path.join(directory, "profile.json");
  await mkdir(directory); let protectedFolder = false;
  await privateDirectory(directory, "win32", async () => {
    await assert.rejects(readFile(file), { code: "ENOENT" }); protectedFolder = true;
  });
  assert.equal(protectedFolder, true); await privateWrite(file, "{}\n");
});
test("Windows folder permissions are set at creation and not on reads", async (t) => {
  const directory = path.join(await temporary(t), "private"), calls = [];
  const protect = async (folder) => { calls.push(folder); };
  await privateDirectory(directory, "win32", protect);
  await privateDirectory(directory, "win32", protect);
  await privateDirectory(directory, "win32", protect);
  assert.deepEqual(calls, [directory]);
  const [marker] = await readdir(directory); assert.ok(marker, "Successful ACL setup must leave a marker.");
  await rm(path.join(directory, marker));
  await privateDirectory(directory, "win32", protect); assert.deepEqual(calls, [directory, directory]);
});
test("failed Windows permission setup is retried before using the folder", async (t) => {
  const directory = path.join(await temporary(t), "private"); let calls = 0;
  const protect = async () => { if (++calls === 1) throw new Error("ACL denied"); };
  await assert.rejects(privateDirectory(directory, "win32", protect), /ACL denied/);
  await privateDirectory(directory, "win32", protect); assert.equal(calls, 2);
});
test("an existing Windows folder retries a failed ACL without losing its files", async (t) => {
  const directory = path.join(await temporary(t), "existing"), file = path.join(directory, "existing.txt");
  await mkdir(directory); await writeFile(file, "keep"); let calls = 0;
  const protect = async () => { if (++calls === 1) throw new Error("ACL denied"); };
  await assert.rejects(privateDirectory(directory, "win32", protect), /ACL denied/);
  assert.equal(await readFile(file, "utf8"), "keep"); assert.deepEqual(await readdir(directory), ["existing.txt"]);
  await privateDirectory(directory, "win32", protect); assert.equal(calls, 2);
});
test("Windows private folders and their files grant access only to the current account", { skip: process.platform !== "win32" }, async (t) => {
  const directory = path.join(await temporary(t), "private & %data%"), file = path.join(directory, "profile.json");
  await mkdir(directory); await privateWrite(file, "{}\n");
  const script = `$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$paths = ConvertFrom-Json $env:TARTLET_TEST_PATHS
$checks = foreach ($path in $paths) {
  $acl = Get-Acl -LiteralPath $path
  $allowed = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Allow' })
  $other = @($allowed | Where-Object { $_.IdentityReference.Value -ne $sid })
  [pscustomobject]@{ protected = $acl.AreAccessRulesProtected; only_current = ($allowed.Count -gt 0 -and $other.Count -eq 0) }
}
ConvertTo-Json -InputObject @($checks) -Compress`;
  const { stdout } = await exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { windowsHide: true, env: { ...process.env, TARTLET_TEST_PATHS: JSON.stringify([directory, file]) } });
  const checks = JSON.parse(stdout); assert.equal(checks[0].protected, true);
  assert.ok(checks.every((value) => value.only_current));
});
test("an older live-owner lock keeps profile updates serialized", async (t) => {
  const directory = await temporary(t), lock = path.join(directory, "profiles.lock");
  let release = () => {}, started = () => {}, secondEntered = false;
  const gate = new Promise((resolve) => { release = resolve; }), ready = new Promise((resolve) => { started = resolve; });
  const first = withLock(directory, "profiles", async () => {
    const [owner] = await readdir(lock), stale = new Date(Date.now() - 65000);
    await utimes(path.join(lock, owner), stale, stale); started(); await gate;
  });
  try {
    await bounded(Promise.race([ready, first]), "The first profile update did not start.");
    const second = withLock(directory, "profiles", async () => { secondEntered = true; });
    await delay(150); assert.equal(secondEntered, false); release(); await Promise.all([first, second]);
    assert.equal(secondEntered, true);
  } finally { release(); await first; }
});
async function copiedVersion(t) {
  const directory = await temporary(t), modules = fileURLToPath(new URL("../../../node_modules", import.meta.url));
  await cp(fileURLToPath(new URL("../dist", import.meta.url)), path.join(directory, "dist"), { recursive: true });
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ type: "module", version: "0.2.1" }));
  await symlink(modules, path.join(directory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
  return directory;
}
test("the reported version comes from the installed package", async (t) => {
  const directory = await copiedVersion(t);
  const result = await exec(process.execPath, [path.join(directory, "dist/main.js"), "--version"]);
  assert.equal(result.stdout, "0.2.1\n");
});
test("MCP identifies the installed package version", async (t) => {
  const directory = await copiedVersion(t), { f } = await signedIn(t), profile = (await readState(f.directory)).profiles[0];
  const copied = await import(pathToFileURL(path.join(directory, "dist/access.js")).href);
  assert.equal(await copied.resolveVm(profile, "vm-example"), "vm-example");
  assert.deepEqual(f.state.clientVersions, ["0.2.1"]);
});
