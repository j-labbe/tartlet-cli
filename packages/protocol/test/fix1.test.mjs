import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import { fileURLToPath } from "node:url";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const sign = (payload, extra = {}) => p.signJws({ payload, private_key: keys.privateKey, ...extra });
const approvalExpected = { mode: "initial", server_public_key: f.rawPublicKey, nonce: f.nonce, approver_iss: f.person.iss };
const verifyApproval = (jws, expected = approvalExpected) => p.verifyEnrollmentApproval({ jws, public_key: keys.publicKey, expected, now: 1000 });
const proofOptions = (jws) => ({ jws, public_key: keys.publicKey, expected: { server_id: f.serverId, nonce: f.nonce, origin: f.proof.origin }, now: 1000 });
const rootFile = (name) => readFile(new URL(`../../../${name}`, import.meta.url), "utf8");
const packageFile = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");
function rsa(bits) {
  const modulus = Buffer.alloc(Math.ceil(bits / 8), 255);
  modulus[0] = 2 ** (bits - 8 * (modulus.length - 1)) - 1;
  const positive = modulus[0] >= 128 ? Buffer.concat([Buffer.from([0]), modulus]) : modulus;
  return f.sshKey("ssh-rsa", [Buffer.from([1, 0, 1]), positive]);
}

test("fix1.1 rejects key lines over 8 KiB before decoding", () => {
  const boundary = `${f.publicKey} ${"a".repeat(8192 - f.publicKey.length - 1)}`;
  assert.equal(p.parsePublicKey(boundary).public_key, f.publicKey);
  assert.throws(() => p.parsePublicKey(`${boundary}a`));
  assert.throws(() => p.parsePublicKey(`${f.publicKey} ${"é".repeat(4096)}`));
});
test("fix1.1 rejects RSA above 16384 bits quickly", { timeout: 1000 }, () => {
  assert.equal(p.parsePublicKey(rsa(16384)).type, "ssh-rsa");
  assert.throws(() => p.parsePublicKey(rsa(16385)));
});
test("fix1.1 rejects fields longer than the remaining key buffer", () => {
  const broken = Buffer.concat([f.field("ssh-rsa"), Buffer.from([255, 255, 255, 255])]);
  assert.throws(() => p.parsePublicKey(`ssh-rsa ${broken.toString("base64")}`));
});
test("fix1.2 requires canonical padded base64", () => {
  const jwk = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
  const key = f.sshKey("ecdsa-sha2-nistp256", ["nistp256", Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")])]);
  assert.equal(key.endsWith("="), true);
  assert.throws(() => p.parsePublicKey(key.replace(/=+$/, "")));
  const canonical = `${key.split(" ")[0]} ${Buffer.from(key.split(" ")[1], "base64").toString("base64")}`;
  assert.equal(p.parsePublicKey(`${key} example-comment`).public_key, canonical);
});

const hostile = ["-oProxyCommand=x", "a$(id);`x`'\"", "host:22", "host:443", "host:0", "[::1]:8443", "host.example.com.", "vm'1", "vm\x001", "#alias"];
for (const value of hostile) {
  test(`fix1.3 rejects unsafe host ${JSON.stringify(value)}`, () => assert.equal(p.HostSchema.safeParse(value).success, false));
}
for (const value of ["example.com", "HOST-1.example.com", "127.0.0.1", "192.0.2.1", "::1", "2001:db8::1", "::ffff:c000:201", "a".repeat(63)]) {
  test(`fix1.3 accepts DNS or IP ${value}`, () => assert.equal(p.HostSchema.safeParse(value).success, true));
}
for (const value of ["user@host", "@host", "host\x7f", "bad_label.example", "-bad.example", "bad-.example", "a..example", "1.2.3.256", "127.1", "0x7f000001", "192.000.2.1", "2001:DB8::1", "2001:0db8::1", "[::1]", "::ffff:192.0.2.1", `${"a".repeat(64)}.com`, Array(5).fill("a".repeat(63)).join(".")]) {
  test(`fix1.3 rejects noncanonical host ${JSON.stringify(value)}`, () => assert.equal(p.HostSchema.safeParse(value).success, false));
}
for (const value of [...hostile.filter((value) => value !== "host.example.com."), "Guest", "guest name", "a".repeat(33)]) {
  test(`fix1.3 rejects unsafe SSH user ${JSON.stringify(value)}`, () => {
    assert.equal(p.SshConnectionSchema.safeParse({ ...f.ssh, user: value }).success, false);
    assert.equal(p.AuthorizeSshKeyResponseSchema.safeParse({ ...f.connection, user: value, expires_at: f.later }).success, false);
    assert.equal(p.VmSchema.safeParse({ ...f.vm, login: value }).success, false);
  });
}
for (const value of [...hostile.filter((value) => value !== "host.example.com."), "a".repeat(129)]) {
  test(`fix1.3 rejects unsafe host alias ${JSON.stringify(value)}`, () => {
    const known_hosts_line = `${value} ${f.publicKey}`;
    assert.equal(p.SshConnectionSchema.safeParse({ ...f.ssh, host_key_alias: value, known_hosts_line }).success, false);
  });
}
for (const alias of ["#alias", "-alias", "vm\x001", "vm\x7f1", "vm\u00851"]) {
  test(`fix1.3 rejects known-hosts control/comment/option ${JSON.stringify(alias)}`, () => assert.equal(p.KnownHostsLineSchema.safeParse(`${alias} ${f.publicKey}`).success, false));
}
test("fix1.3 accepts bounded SSH users and aliases", () => {
  const user = `_${"a".repeat(31)}`;
  const alias = `A${"a".repeat(127)}`;
  assert.equal(p.SshConnectionSchema.safeParse({ ...f.ssh, user, host_key_alias: alias, known_hosts_line: `${alias} ${f.publicKey}` }).success, true);
});

test("fix1.4 public verification API excludes the generic verifier", () => {
  assert.equal(Object.hasOwn(p, "verifyJws"), false);
});
test("fix1.4 declarations do not export VerifyJwsOptions", () => {
  const filename = fileURLToPath(new URL("../dist/index.d.ts", import.meta.url));
  const program = ts.createProgram([filename], { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext });
  const source = program.getSourceFile(filename);
  assert.ok(source, "Public declarations must exist.");
  const symbol = program.getTypeChecker().getSymbolAtLocation(source);
  assert.ok(symbol, "Public declarations must have a module symbol.");
  const names = program.getTypeChecker().getExportsOfModule(symbol).map((entry) => entry.name);
  assert.equal(names.includes("VerifyJwsOptions"), false);
  assert.equal(names.includes("verifyJws"), false);
});
test("fix1.4 artifact verifiers reject empty expected context at every level", async () => {
  await assert.rejects(async () => p.verifyServerProof({ ...proofOptions(await sign(f.proof)), expected: {} }));
  await assert.rejects(async () => verifyApproval(await sign(f.approval), { ...approvalExpected, approver_iss: {} }));
});
test("fix1.5 initial enrollment verifies unknown server, org and approver subject", async () => {
  const sub = `acct_${"f".repeat(26)}`;
  const payload = { ...f.approval, approver: { ...f.person, sub } };
  const verified = await verifyApproval(await sign(payload));
  assert.deepEqual(verified, payload);
  assert.equal(verified.approver.sub, sub);
});
test("fix1.5 reenrollment pins server and org but accepts a new verified approver subject", async () => {
  const expected = { ...approvalExpected, mode: "reenroll", server_id: f.serverId, org_id: f.orgId };
  assert.equal((await verifyApproval(await sign(f.approval), expected)).server_id, f.serverId);
  for (const mismatch of [{ server_id: `srv_${"b".repeat(26)}` }, { org_id: `org_${"c".repeat(26)}` }, { approver_iss: "https://other.example.com" }, { nonce: f.rawPublicKey }, { server_public_key: f.nonce }]) {
    await assert.rejects(async () => verifyApproval(await sign(f.approval), { ...expected, ...mismatch }));
  }
});
test("fix1.5 approval never accepts subject constraints from the caller", async () => {
  await assert.rejects(async () => verifyApproval(await sign(f.approval), { ...approvalExpected, approver_sub: "person-1" }));
  await assert.rejects(async () => verifyApproval(await sign(f.approval), { ...approvalExpected, approver: f.person }));
});
test("fix1.6 reads strict unverified headers solely to choose a local kid", async () => {
  assert.equal(typeof p.readUnverifiedJwsHeader, "function");
  const jws = await sign(f.proof, { kid: "rotation-2" });
  assert.deepEqual(p.readUnverifiedJwsHeader(jws), { alg: "EdDSA", kid: "rotation-2" });
  const [header, body, signature] = jws.split(".");
  const tampered = `${header}.${body}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  assert.deepEqual(p.readUnverifiedJwsHeader(tampered), { alg: "EdDSA", kid: "rotation-2" });
  await assert.rejects(p.verifyServerProof(proofOptions(tampered)));
  for (const value of ["", "a.b", "e30.e30.AA.extra", `${Buffer.from(JSON.stringify({ alg: "EdDSA", jku: "https://attacker.example.com" })).toString("base64url")}.e30.AA`, `${Buffer.from('{"alg":"HS256"}').toString("base64url")}.e30.AA`]) assert.throws(() => p.readUnverifiedJwsHeader(value));
});
for (const value of ["https://server.example.com:0", "https://@server.example.com", "https://:@server.example.com", "https://user@server.example.com", "https://server.example.com\x00", "https://server.example.com\u0085", "https://server.example.com\\", "https://server.example.com\t", "https://server.example.com."]) {
  test(`fix1.7 rejects unsafe origin ${JSON.stringify(value)}`, () => assert.throws(() => p.normalizeOrigin(value)));
}
for (const email of ["jörg@example.com", "a@münchen.example"]) {
  test(`fix1.8 accepts international email ${email}`, () => assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, email }).success, true));
}
test("fix1.8 bounds email at 254 characters", () => {
  const email = `a@${Array(3).fill("a".repeat(63)).join(".")}.${"a".repeat(60)}`;
  assert.equal(email.length, 254);
  assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, email }).success, true);
  assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, email: `${email}a` }).success, false);
});

const limitCases = [
  ["person sub", (value) => p.PersonIdentitySchema.safeParse({ ...f.person, sub: value }), 255],
  ["device response code", (value) => p.EnrollmentStartResponseSchema.safeParse({ device_code: value, user_code: "ABCD-2345", verification_uri: "https://cloud.example.com/verify", expires_in: 600, interval: 5 }), 128],
  ["device poll code", (value) => p.EnrollmentPollRequestSchema.safeParse({ device_code: value, proof: f.compact }), 128],
  ["device signed code", (value) => p.EnrollmentPollPayloadSchema.safeParse({ ...f.poll, device_code: value }), 128],
  ["cursor", (value) => p.CursorSchema.safeParse(value), 128],
  ["kid", (value) => p.JwsHeaderSchema.safeParse({ alg: "EdDSA", kid: value }), 64],
  ["error code", (value) => p.ProtocolFailureSchema.safeParse({ ...f.failure, code: value }), 64],
  ["error message", (value) => p.ProtocolFailureSchema.safeParse({ ...f.failure, message: value }), 1024],
  ["image ID", (value) => p.VmSchema.safeParse({ ...f.vm, image_id: value }), 128],
  ["replica storage key", (value) => p.VmHomeSchema.safeParse({ kind: "volume", health: "healthy", mode: "durable", copy_count: 1, safety: "Example", copies: [{ host: "host.example.com", role: "primary", replica: value }] }), 128],
  ["mount name", (value) => p.VmHomeSchema.safeParse({ kind: "nas", path: "/synthetic/home", mount_name: value }), 255],
  ["server name", (value) => p.EnrollmentStartRequestSchema.safeParse({ server_public_key: f.rawPublicKey, server_name: value, addresses: [{ kind: "lan", host: "server.example.com" }], nonce: f.nonce }), 64],
  ["command", (value) => p.RunCommandRequestSchema.safeParse({ client_request_id: "request-1", vm: "vm-1", command: value }), 16384],
];
for (const [name, parse, limit] of limitCases) {
  test(`fix1.nit bounds ${name}`, () => {
    assert.equal(parse("a".repeat(limit)).success, true);
    assert.equal(parse("a".repeat(limit + 1)).success, false);
  });
}
test("fix1.nit command cap counts UTF-8 bytes", () => {
  const request = { client_request_id: "request-1", vm: "vm-1", command: "é".repeat(8192) };
  assert.equal(p.RunCommandRequestSchema.safeParse(request).success, true);
  assert.equal(p.RunCommandRequestSchema.safeParse({ ...request, command: `${request.command}a` }).success, false);
});
test("fix1.nit bounds catch-up batches at 100", () => {
  const base = { type: "catch_up", next_cursor: "cursor-1", complete: true, upstream_synced_at: 990 };
  assert.equal(p.CatchUpMessageSchema.safeParse({ ...base, cutoffs: Array(100).fill(f.cutoff) }).success, true);
  assert.equal(p.CatchUpMessageSchema.safeParse({ ...base, cutoffs: Array(101).fill(f.cutoff) }).success, false);
});
for (const value of ["https://user:pass@issuer.example.com", "https://@issuer.example.com", "https://:@issuer.example.com"]) {
  test(`fix1.nit rejects issuer and verification userinfo ${value}`, () => {
    assert.equal(p.PersonIdentitySchema.safeParse({ ...f.person, iss: value }).success, false);
    assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, iss: value }).success, false);
    assert.equal(p.EnrollmentStartResponseSchema.safeParse({ device_code: "device", user_code: "ABCD-2345", verification_uri: value, expires_in: 600, interval: 5 }).success, false);
  });
}
for (const field of ["code", "message"]) {
  test(`fix1.nit error ${field} is nonempty`, () => assert.equal(p.ProtocolFailureSchema.safeParse({ ...f.failure, [field]: "" }).success, false));
}
for (const version of ["1.2.3-01", "1.2.3-alpha.01", "1.2.3-00.beta"]) {
  test(`fix1.nit rejects numeric prerelease leading zeros ${version}`, () => assert.equal(p.CliVersionSchema.safeParse(version).success, false));
}
test("fix1.nit accepts nonnumeric prerelease and numeric build identifiers", () => {
  for (const value of ["1.2.3-0", "1.2.3-0a", "1.2.3-alpha.0+001", "1.2.3+001"]) assert.equal(p.CliVersionSchema.safeParse(value).success, true);
});
test("fix1.nit public npm package metadata", async () => {
  const metadata = JSON.parse(await packageFile("package.json"));
  assert.deepEqual(metadata.repository, { type: "git", url: "https://github.com/j-labbe/tartlet-cli", directory: "packages/protocol" });
  assert.deepEqual(metadata.publishConfig, { access: "public" });
  assert.equal(metadata.exports["."].default, "./dist/index.js");
});
test("fix1.nit CI uses main pushes, pull requests and disposable checkout credentials", async () => {
  const workflow = await rootFile(".github/workflows/ci.yml");
  assert.match(workflow, /push:\n\s+branches: \[main\]/);
  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /persist-credentials: false/);
  for (const line of workflow.split("\n").filter((line) => line.includes("uses:"))) assert.match(line, /@[a-f0-9]{40}\b/);
});
test("fix1.nit both licenses contain terms and copyright without appendix placeholders", async () => {
  const root = await rootFile("LICENSE");
  assert.equal(await packageFile("LICENSE"), root);
  assert.match(root, /END OF TERMS AND CONDITIONS/);
  assert.match(root, /Copyright Tartlet contributors/);
  assert.doesNotMatch(root, /APPENDIX|\[yyyy\]|\[name of copyright owner\]/);
});
test("fix1.nit README warns that issuers must sign using this package", async () => {
  const readme = await packageFile("README.md");
  assert.match(readme, /issuers must sign with this package/i);
  assert.match(readme, /typ: "JWT"/);
});
test("fix1.nit signature base64url must have canonical trailing bits", async () => {
  const jws = await sign(f.proof);
  const [header, body, signature] = jws.split(".");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const index = alphabet.indexOf(signature.at(-1));
  const malleated = `${signature.slice(0, -1)}${alphabet[index + 1]}`;
  assert.deepEqual(Buffer.from(malleated, "base64url"), Buffer.from(signature, "base64url"));
  await assert.rejects(p.verifyServerProof(proofOptions(`${header}.${body}.${malleated}`)));
});
test("fix1.nit swapped signing and verifying key types are rejected", async () => {
  await assert.rejects(p.signJws({ payload: f.proof, private_key: keys.publicKey }));
  const jws = await sign(f.proof);
  await assert.rejects(p.verifyServerProof({ ...proofOptions(jws), public_key: keys.privateKey }));
});

test("fix1.4 built JWS declarations expose no generic verifier", async () => {
  const declaration = await packageFile("dist/jws.d.ts");
  assert.doesNotMatch(declaration, /verifyJws|VerifyJwsOptions/);
});

test("fix1.nit bounds issuer and verification URL storage keys", () => {
  const prefix = "https://issuer.example.com/";
  const issuer = `${prefix}${"a".repeat(2048 - prefix.length)}`;
  assert.equal(p.PersonIdentitySchema.safeParse({ ...f.person, iss: issuer }).success, true);
  assert.equal(p.PersonIdentitySchema.safeParse({ ...f.person, iss: `${issuer}a` }).success, false);
  assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, iss: `${issuer}a` }).success, false);
  const response = { device_code: "device", user_code: "ABCD-2345", verification_uri: issuer, expires_in: 600, interval: 5 };
  assert.equal(p.EnrollmentStartResponseSchema.safeParse(response).success, true);
  assert.equal(p.EnrollmentStartResponseSchema.safeParse({ ...response, verification_uri: `${issuer}a` }).success, false);
});
