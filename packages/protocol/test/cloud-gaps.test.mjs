import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

const start = { server_public_key: f.rawPublicKey, server_name: "Server 1", addresses: f.listedServer.addresses, nonce: f.nonce };
const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
const wrong = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
const sign = (payload) => p.signJws({ payload, private_key: keys.privateKey });
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
async function rawSign(payload, header = { alg: "EdDSA" }) {
  const input = `${encode(header)}.${encode(payload)}`;
  const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(input));
  return `${input}.${Buffer.from(signature).toString("base64url")}`;
}
const artifacts = [
  { payload: f.unenroll, verify: p.verifyUnenroll, expected: { server_id: f.serverId, nonce: f.nonce }, lifetime: 60 },
  { payload: f.cloudAccess, verify: p.verifyCloudAccessToken, expected: { iss: f.cloudAccess.iss, aud: f.cloudAccess.aud }, lifetime: 600 },
];
const options = (artifact, jws) => ({ jws, public_key: keys.publicKey, expected: artifact.expected, now: 1000 });

test("cloud account IDs use exactly 26 lowercase base32 characters", () => {
  for (const value of [f.accountId, `acct_${"2".repeat(26)}`, `acct_${"7".repeat(26)}`]) {
    assert.equal(p.CloudAccountIdSchema.parse(value), value);
    assert.equal(p.isCloudAccountId(value), true);
  }
  for (const value of [null, 1, f.serverId, "acct_", `acct_${"a".repeat(25)}`, `${f.accountId}a`, f.accountId.toUpperCase(), `acct_${"0".repeat(26)}`, `acct_${"8".repeat(26)}`, `${f.accountId}\n`]) {
    assert.equal(p.isCloudAccountId(value), false);
  }
});

test("cloud identity and approval subjects require accounts while company OIDC identities stay general", () => {
  for (const sub of [f.accountId, `acct_${"2".repeat(26)}`]) {
    assert.equal(p.IdentityTokenClaimsSchema.parse({ ...f.claims, sub }).sub, sub);
    assert.equal(p.EnrollmentApprovalPayloadSchema.parse({ ...f.approval, approver: { ...f.person, sub } }).approver.sub, sub);
  }
  for (const sub of ["person-1", "oidc-user-1", "123e4567-e89b-12d3-a456-426614174000", "x".repeat(255)]) {
    assert.equal(p.PersonIdentitySchema.parse({ ...f.person, sub }).sub, sub);
    assert.equal(p.IdentityTokenClaimsSchema.safeParse({ ...f.claims, sub }).success, false);
    assert.equal(p.EnrollmentApprovalPayloadSchema.safeParse({ ...f.approval, approver: { ...f.person, sub } }).success, false);
    assert.equal(p.CloudAccessTokenClaimsSchema.safeParse({ ...f.cloudAccess, sub }).success, false);
  }
});

test("enrollment poll helper discriminates success, pending, and terminal responses", () => {
  assert.deepEqual(p.parseEnrollmentPollResponse({ approval: f.compact }), { kind: "success", approval: f.compact });
  const cases = [
    ["authorization_pending", "retry the same call", "pending"],
    ["slow_down", "retry the same call", "pending"],
    ["expired_token", "a person must act", "terminal"],
    ["access_denied", "a person must act", "terminal"],
  ];
  for (const [code, action, kind] of cases) {
    const response = { error: { ...f.failure, code, action } };
    assert.deepEqual(p.EnrollmentPollResponseSchema.parse(response), response);
    assert.deepEqual(p.parseEnrollmentPollResponse(response), { kind, ...response });
    assert.throws(() => p.parseEnrollmentPollResponse({ error: { ...response.error, action: "change your input" } }));
  }
});

test("enrollment poll responses reject mismatched actions, unknown fields, and malformed successes", () => {
  const pending = { ...f.failure, code: "authorization_pending", action: "retry the same call" };
  const invalid = [
    {}, { approval: "bad" }, { approval: f.compact, error: pending }, { approval: f.compact, kind: "success" },
    { error: { ...pending, action: "a person must act" } }, { error: { ...pending, code: "expired_token" } },
    { error: { ...pending, code: "unknown" } }, { error: { ...pending, message: "" } },
    { error: { ...pending, message: "x".repeat(1025) } }, { error: { ...pending, interval: 5 } },
  ];
  for (const value of invalid) assert.throws(() => p.parseEnrollmentPollResponse(value));
  assert.equal(p.EnrollmentPollResponseSchema.safeParse({ error: { ...pending, message: "x".repeat(1024) } }).success, true);
});

test("reenrollment context is optional and binds server and organization IDs", () => {
  assert.deepEqual(p.EnrollmentStartRequestSchema.parse(start), start);
  const reenroll = { server_id: f.serverId, org_id: f.orgId };
  assert.deepEqual(p.EnrollmentStartRequestSchema.parse({ ...start, reenroll }).reenroll, reenroll);
  for (const value of [null, {}, { server_id: f.serverId }, { org_id: f.orgId }, { ...reenroll, org_id: f.serverId }, { ...reenroll, server_id: "bad" }, { ...reenroll, extra: true }]) {
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, reenroll: value }).success, false);
  }
});

test("HTTPS trust accepts WebPKI and only lowercase SHA-256 local CA roots", () => {
  for (const https_trust of [{ kind: "webpki" }, { kind: "local_ca", root_sha256: "0123456789abcdef".repeat(4) }]) {
    assert.deepEqual(p.EnrollmentStartRequestSchema.parse({ ...start, https_trust }).https_trust, https_trust);
  }
  for (const value of [null, { kind: "unknown" }, { kind: "webpki", root_sha256: "a".repeat(64) }, { kind: "local_ca" }, { kind: "local_ca", root_sha256: "A".repeat(64) }, { kind: "local_ca", root_sha256: "g".repeat(64) }, { kind: "local_ca", root_sha256: "a".repeat(63) }, { kind: "local_ca", root_sha256: "a".repeat(65) }, { kind: "local_ca", root_sha256: "a".repeat(64), extra: true }]) {
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, https_trust: value }).success, false);
  }
});

test("enrollment and directory addresses share optional bounded ports", () => {
  for (const port of [undefined, 1, 8443, 65535]) {
    const address = { kind: "lan", host: "2001:db8::1", ...(port === undefined ? {} : { port }) };
    assert.deepEqual(p.EnrollmentAddressSchema.parse(address), address);
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, addresses: [address] }).success, true);
    assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, addresses: [address] }] }).success, true);
  }
  for (const port of [0, -1, 443, 65536, 1.5, "443", null]) {
    const address = { kind: "tailnet", host: "server.example.com", port };
    assert.equal(p.EnrollmentAddressSchema.safeParse(address).success, false);
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, addresses: [address] }).success, false);
    assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, addresses: [address] }] }).success, false);
  }
});

test("un-enroll challenge request is empty and response requires a canonical 32-byte nonce and bounded expiry", () => {
  assert.deepEqual(p.UnenrollChallengeRequestSchema.parse({}), {});
  for (const value of [{ server_id: f.serverId }, { nonce: f.nonce }, null, []]) assert.equal(p.UnenrollChallengeRequestSchema.safeParse(value).success, false);
  for (const expires_in of [1, 60, 120]) assert.deepEqual(p.UnenrollChallengeResponseSchema.parse({ nonce: f.nonce, expires_in }), { nonce: f.nonce, expires_in });
  for (const expires_in of [undefined, 0, -1, 121, 1.5, "120"]) assert.equal(p.UnenrollChallengeResponseSchema.safeParse({ nonce: f.nonce, expires_in }).success, false);
  for (const nonce of ["AA", `${f.nonce}=`, Buffer.alloc(31).toString("base64url"), Buffer.alloc(33).toString("base64url"), `${f.nonce.slice(0, -1)}d`]) {
    assert.equal(p.UnenrollChallengeResponseSchema.safeParse({ nonce, expires_in: 120 }).success, false);
  }
  assert.equal(p.UnenrollChallengeResponseSchema.safeParse({ nonce: f.nonce, expires_in: 120, server_id: f.serverId }).success, false);
});

test("un-enroll request and response use strict proof and literal-success bodies", () => {
  assert.deepEqual(p.UnenrollRequestSchema.parse({ proof: f.compact }), { proof: f.compact });
  assert.deepEqual(p.UnenrollResponseSchema.parse({ unenrolled: true }), { unenrolled: true });
  for (const value of [{}, { proof: "bad" }, { proof: f.compact, server_id: f.serverId }, f.compact]) assert.equal(p.UnenrollRequestSchema.safeParse(value).success, false);
  for (const value of [{}, { unenrolled: false }, { unenrolled: "true" }, { unenrolled: true, server_id: f.serverId }]) assert.equal(p.UnenrollResponseSchema.safeParse(value).success, false);
});

test("server list permits zero through 500 entries and enforces each server's fields", () => {
  const servers = Array.from({ length: 501 }, (_, index) => ({ ...f.listedServer, server_id: `srv_${"a".repeat(24)}${String.fromCharCode(97 + Math.floor(index / 26))}${String.fromCharCode(97 + index % 26)}` }));
  assert.deepEqual(p.ServerListResponseSchema.parse({ servers: [] }), { servers: [] });
  assert.equal(p.ServerListResponseSchema.parse({ servers: servers.slice(0, 500) }).servers.length, 500);
  assert.equal(p.ServerListResponseSchema.safeParse({ servers }).success, false);
  assert.equal(p.ServerListResponseSchema.safeParse({ servers: [], extra: true }).success, false);
  for (const change of [{ server_id: f.orgId }, { org_id: f.serverId }, { name: "" }, { name: "x".repeat(65) }, { online: undefined }, { online: 1 }, { addresses: [] }, { addresses: Array(5).fill(f.listedServer.addresses[0]) }, { addresses: [{ kind: "lan", host: "host.example.com:443" }] }, { extra: true }]) {
    assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, ...change }] }).success, false);
  }
  const addresses = Array.from({ length: 4 }, (_, index) => ({ ...f.listedServer.addresses[0], port: 8443 + index }));
  assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, online: false, name: "x".repeat(64), addresses }] }).success, true);
});

for (const artifact of artifacts) {
  test(`${artifact.payload.typ} verifies only with all exact expected fields`, async () => {
    const jws = await sign(artifact.payload);
    const valid = options(artifact, jws);
    assert.deepEqual(await artifact.verify(valid), artifact.payload);
    await assert.rejects(async () => artifact.verify({ ...valid, expected: {} }));
    await assert.rejects(async () => artifact.verify({ ...valid, expected: { ...artifact.expected, key: "ignored" } }));
    const mismatches = { server_id: `srv_${"b".repeat(26)}`, nonce: f.rawPublicKey, iss: "https://other.example.com", aud: "https://other.example.com" };
    for (const field of Object.keys(artifact.expected)) {
      const { [field]: _omitted, ...missing } = artifact.expected;
      await assert.rejects(async () => artifact.verify({ ...valid, expected: missing }));
      await assert.rejects(async () => artifact.verify({ ...valid, expected: { ...artifact.expected, [field]: mismatches[field] } }));
    }
  });

  test(`${artifact.payload.typ} rejects wrong keys, algorithms, tampering, and clock violations`, async () => {
    const jws = await sign(artifact.payload);
    const valid = options(artifact, jws);
    await assert.rejects(artifact.verify({ ...valid, public_key: wrong.publicKey }));
    await assert.rejects(artifact.verify(options(artifact, await rawSign(artifact.payload, { alg: "HS256" }))));
    const [header, body, signature] = jws.split(".");
    await assert.rejects(artifact.verify({ ...valid, jws: `${header}.${encode({ ...artifact.payload, iat: 999 })}.${signature}` }));
    await assert.rejects(artifact.verify({ ...valid, jws: `${header}.${body}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}` }));
    assert.deepEqual(await artifact.verify({ ...valid, now: artifact.payload.exp + 59 }), artifact.payload);
    await assert.rejects(artifact.verify({ ...valid, now: artifact.payload.exp + 60 }));
    assert.deepEqual(await artifact.verify({ ...valid, now: 940 }), artifact.payload);
    await assert.rejects(artifact.verify({ ...valid, now: 939 }));
  });

  test(`${artifact.payload.typ} rejects invalid lifetime and unknown fields during signing and verification`, async () => {
    for (const payload of [{ ...artifact.payload, exp: 1000 }, { ...artifact.payload, exp: 1000 + artifact.lifetime + 1 }, { ...artifact.payload, extra: true }]) {
      await assert.rejects(sign(payload));
      await assert.rejects(artifact.verify(options(artifact, await rawSign(payload))));
    }
  });
}

test("un-enroll proofs require exactly 60 seconds and a canonical nonce", async () => {
  for (const change of [{ exp: 1059 }, { nonce: "AA" }, { server_id: f.orgId }, { nonce: `${f.nonce.slice(0, -1)}d` }]) {
    const payload = { ...f.unenroll, ...change };
    assert.equal(p.UnenrollPayloadSchema.safeParse(payload).success, false);
    await assert.rejects(p.verifyUnenroll(options(artifacts[0], await rawSign(payload))));
  }
});

test("cloud access tokens target their issuer and enforce subject, lifetime, and not-before", async () => {
  for (const change of [{ exp: 1001 }, { exp: 1600 }, { nbf: 1600 }]) assert.equal(p.CloudAccessTokenClaimsSchema.safeParse({ ...f.cloudAccess, ...change }).success, true);
  for (const change of [{ aud: "https://other.example.com" }, { aud: f.serverId }, { sub: f.person.sub }, { nbf: 1601 }, { nbf: -1 }, { iss: "http://issuer.example.com" }]) {
    const payload = { ...f.cloudAccess, ...change };
    assert.equal(p.CloudAccessTokenClaimsSchema.safeParse(payload).success, false);
    await assert.rejects(p.verifyCloudAccessToken(options(artifacts[1], await rawSign(payload))));
  }
  const valid = { ...f.cloudAccess, nbf: 1060 };
  assert.deepEqual(await p.verifyCloudAccessToken(options(artifacts[1], await sign(valid))), valid);
  await assert.rejects(p.verifyCloudAccessToken(options(artifacts[1], await sign({ ...valid, nbf: 1061 }))));
});

test("protocol package version is 0.2.0 while protocol wire version remains 1", async () => {
  const metadata = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const lock = JSON.parse(await readFile(new URL("../../../package-lock.json", import.meta.url), "utf8"));
  assert.equal(metadata.version, "0.2.0");
  assert.equal(lock.packages["packages/protocol"].version, "0.2.0");
  assert.equal(p.PROTOCOL_VERSION, 1);
});
