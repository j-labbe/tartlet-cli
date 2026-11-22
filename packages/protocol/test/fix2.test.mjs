import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

function compact(length, header = Buffer.from('{"alg":"EdDSA"}').toString("base64url")) {
  return `${header}.${"A".repeat(length - header.length - 4)}.AA`;
}
const enrollmentResponse = { device_code: "example-device-code", user_code: "ABCD-2345", verification_uri: "https://cloud.example.com/verify", expires_in: 600, interval: 5 };

test("fix2.1 VM metadata accepts worker names without relaxing dialled hosts", () => {
  const home = { kind: "host", host: "mac_mini", path: "/synthetic/home", mount_name: "home" };
  const volume = { kind: "volume", health: "healthy", mode: "durable", copy_count: 1, safety: "Example safety", copies: [{ host: "mac_mini", role: "primary" }] };
  assert.equal(p.VmSchema.safeParse({ ...f.vm, host: "mac_mini" }).success, true);
  assert.equal(p.VmHomeSchema.safeParse(home).success, true);
  assert.equal(p.VmHomeSchema.safeParse(volume).success, true);
  assert.equal(p.SshConnectionSchema.safeParse({ ...f.ssh, host: "mac_mini" }).success, false);
  assert.equal(p.AuthorizeSshKeyResponseSchema.safeParse({ ...f.connection, expires_at: f.later, host: "mac_mini" }).success, false);
  assert.equal(p.EnrollmentAddressSchema.safeParse({ kind: "lan", host: "mac_mini" }).success, false);
});
test("fix2.1 worker schema and guard follow the server rule exactly", () => {
  assert.ok(p.WorkerNameSchema, "The worker-name schema must exist.");
  assert.equal(typeof p.isWorkerName, "function");
  for (const value of ["mac_mini", "Mac:1", "a".repeat(128), "A.1_-:"]) {
    assert.equal(p.WorkerNameSchema.parse(value), value);
    assert.equal(p.isWorkerName(value), true);
  }
  for (const value of ["", "-mac", "_mac", "a".repeat(129), "mac/1", "mac\x001", null]) {
    assert.equal(p.WorkerNameSchema.safeParse(value).success, false);
    assert.equal(p.isWorkerName(value), false);
  }
});
for (const [name, email] of [["NUL", "a\x00b@example.com"], ["ESC", "a\x1bb@example.com"]]) {
  test(`fix2.2 identity emails reject ${name}`, () => assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, email }).success, false));
}

test("fix2.nit directly tests the empty-expectation backstop", async () => {
  const { matchesExpected } = await import("../dist/expected-fields.js");
  assert.equal(matchesExpected({ server_id: f.serverId }, {}), false);
  assert.equal(matchesExpected({ approver: f.person }, { approver: {} }), false);
  assert.equal(matchesExpected({ a: { b: { c: 1 } } }, { a: { b: {} } }), false);
  assert.equal(matchesExpected({ approver: f.person }, { approver: { iss: f.person.iss } }), true);
  assert.equal(matchesExpected({ approver: f.person }, { approver: { iss: "https://other.example.com" } }), false);
  assert.equal(matchesExpected({ server_id: f.serverId }, { missing: "value" }), false);
  assert.equal(matchesExpected("value", { field: "value" }), false);
  assert.equal(matchesExpected("value", "value"), true);
  assert.equal(matchesExpected(1, "1"), false);
  assert.equal(Object.hasOwn(p, "matchesExpected"), false);
});

test("fix2.nit compact schema enforces the 16384-character boundary", () => {
  assert.equal(p.JwsCompactSchema.safeParse(compact(16384)).success, true);
  assert.equal(p.JwsCompactSchema.safeParse(compact(16385)).success, false);
});
test("fix2.nit compact parser enforces the boundary before decoding", () => {
  assert.deepEqual(p.readUnverifiedJwsHeader(compact(16384)), { alg: "EdDSA" });
  assert.throws(() => p.readUnverifiedJwsHeader(compact(16385)));
  assert.throws(() => p.readUnverifiedJwsHeader(compact(16385, "A")), (error) => error.issues?.some((issue) => issue.code === "too_big" && issue.maximum === 16384));
});
test("fix2.nit HTTPS URLs reject explicit port zero everywhere", () => {
  for (const value of ["https://issuer.example.com:0", "https://issuer.example.com:000/", "https://[::1]:0"]) {
    assert.equal(p.HttpsUrlSchema.safeParse(value).success, false);
    assert.equal(p.PersonIdentitySchema.safeParse({ ...f.person, iss: value }).success, false);
    assert.equal(p.EnrollmentStartResponseSchema.safeParse({ ...enrollmentResponse, verification_uri: value }).success, false);
  }
  assert.equal(p.HttpsUrlSchema.safeParse("https://issuer.example.com:443").success, true);
  assert.equal(p.HttpsUrlSchema.safeParse("https://issuer.example.com:8443").success, true);
  assert.equal(p.HttpsUrlSchema.safeParse("https://issuer.example.com:bad").success, false);
});

for (const field of ["ssh_options", "command"]) {
  test(`fix2.nit SSH ${field} is documented as display-only`, () => {
    const description = p.SshConnectionSchema.shape[field].description ?? "";
    assert.match(description, /display-only/i);
    assert.match(description, /CLI builds SSH arguments from (?:the )?typed fields only/);
  });
}
for (const [kind, field] of [["ssh", "command"], ["port", "address"]]) {
  test(`fix2.nit ${kind}.${field} is documented as display-only`, () => {
    const variant = p.VmConnectionSchema.shape.connection.options.find((option) => option.shape.kind.value === kind);
    assert.ok(variant, "The connection variant must exist.");
    const description = variant.shape[field].description ?? "";
    assert.match(description, /display-only/i);
    assert.match(description, /CLI builds SSH arguments from (?:the )?typed fields only/);
  });
}
test("fix2.nit command execution input remains runnable stdin content", () => {
  const command = "printf hello";
  const result = p.RunCommandRequestSchema.parse({ client_request_id: "request-1", vm: "vm-1", command });
  assert.equal(result.command, command);
  assert.doesNotMatch(p.RunCommandRequestSchema.shape.command.description ?? "", /display-only/i);
});
test("fix2.nit RSA validation uses the existing bit count without a binary string", (context) => {
  const jwk = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
  const key = f.sshKey("ssh-rsa", [f.mpint(jwk.e), f.mpint(jwk.n)]);
  context.mock.method(BigInt.prototype, "toString", () => { throw new Error("RSA validation must not allocate a binary string."); });
  assert.deepEqual(p.parsePublicKey(key), { type: "ssh-rsa", public_key: key });
});
test("fix2.nit enrollment polling interval is at most 600 seconds", () => {
  assert.equal(p.EnrollmentStartResponseSchema.safeParse({ ...enrollmentResponse, interval: 600 }).success, true);
  assert.equal(p.EnrollmentStartResponseSchema.safeParse({ ...enrollmentResponse, interval: 601 }).success, false);
  assert.equal(p.EnrollmentStartResponseSchema.safeParse({ ...enrollmentResponse, interval: 0 }).success, false);
});
