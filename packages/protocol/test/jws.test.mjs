import assert from "node:assert/strict";
import test from "node:test";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

const keys = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const wrong = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
async function rawSign(header, payload) {
  const input = `${encode(header)}.${encode(payload)}`;
  const signature = await globalThis.crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(input));
  return `${input}.${Buffer.from(signature).toString("base64url")}`;
}
async function sign(payload, extra = {}) { return p.signJws({ payload, private_key: keys.privateKey, ...extra }); }
const verify = (jws, extra = {}) => p.verifyJws({ jws, public_key: keys.publicKey, schema: p.ServerProofPayloadSchema, expected: { server_id: f.serverId, origin: f.proof.origin, nonce: f.nonce }, now: 1000, ...extra });

test("EdDSA JWS interoperates with independent Web Crypto verification", async () => {
  const jws = await sign(f.proof, { kid: "example-key-1" });
  assert.deepEqual(await verify(jws), f.proof);
  const [header, payload, signature] = jws.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "EdDSA", kid: "example-key-1" });
  assert.equal(await globalThis.crypto.subtle.verify("Ed25519", keys.publicKey, Buffer.from(signature, "base64url"), Buffer.from(`${header}.${payload}`)), true);
  const independent = await rawSign({ alg: "EdDSA" }, f.proof);
  assert.deepEqual(await verify(independent), f.proof);
});
test("rejects wrong key, modified body and modified signature", async () => {
  const jws = await sign(f.proof);
  await assert.rejects(verify(jws, { public_key: wrong.publicKey }));
  const [header, body, signature] = jws.split(".");
  await assert.rejects(verify(`${header}.${encode({ ...f.proof, origin: "https://attacker.example.com" })}.${signature}`));
  const modified = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  await assert.rejects(verify(`${header}.${body}.${modified}`));
});
test("rejects other algorithms and every header-based trust source", async () => {
  for (const header of [{ alg: "none" }, { alg: "HS256" }, { alg: "RS256" }, { alg: "EdDSA", jku: "https://attacker.example.com" }, { alg: "EdDSA", jwk: {} }, { alg: "EdDSA", x5u: "https://attacker.example.com" }, { alg: "EdDSA", crit: ["unknown"] }, { alg: "EdDSA", b64: false }]) await assert.rejects(verify(await rawSign(header, f.proof)));
  const rsa = await globalThis.crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-256" }, false, ["sign", "verify"]);
  await assert.rejects(sign(f.proof, { private_key: rsa.privateKey }));
  await assert.rejects(verify(await sign(f.proof), { public_key: rsa.publicKey }));
});
test("expiry, issuance and not-before enforce the 60-second skew", async () => {
  const jws = await sign(f.proof);
  assert.deepEqual(await verify(jws, { now: 1119 }), f.proof);
  await assert.rejects(verify(jws, { now: 1120 }));
  assert.deepEqual(await verify(jws, { now: 940 }), f.proof);
  await assert.rejects(verify(jws, { now: 939 }));
  const token = await sign({ ...f.claims, nbf: 1061 });
  await assert.rejects(p.verifyJws({ jws: token, public_key: keys.publicKey, schema: p.IdentityTokenClaimsSchema, expected: {}, now: 1000 }));
  const valid = await sign({ ...f.claims, nbf: 1060 });
  assert.equal((await p.verifyJws({ jws: valid, public_key: keys.publicKey, schema: p.IdentityTokenClaimsSchema, expected: {}, now: 1000 })).nbf, 1060);
  await assert.rejects(verify(await rawSign({ alg: "EdDSA" }, { ...f.proof, exp: 1000 })));
});
test("verifies every signed artifact and requires all context expectations", async () => {
  const cases = [
    [f.hello, p.verifyHello, { server_id: f.serverId, nonce: f.nonce }],
    [f.poll, p.verifyEnrollmentPoll, { device_code: f.poll.device_code }],
    [f.approval, p.verifyEnrollmentApproval, { server_id: f.serverId, org_id: f.orgId, server_public_key: f.rawPublicKey, approver: f.person, nonce: f.nonce }],
    [f.proof, p.verifyServerProof, { server_id: f.serverId, origin: f.proof.origin, nonce: f.nonce }],
    [f.claims, p.verifyIdentityToken, { iss: f.claims.iss, aud: f.serverId, nonce: f.nonce, org: f.orgId }],
  ];
  for (const [payload, verifier, expected] of cases) {
    const jws = await sign(payload);
    assert.deepEqual(await verifier({ jws, public_key: keys.publicKey, expected, now: 1000 }), payload);
    await assert.rejects(async () => verifier({ jws, public_key: keys.publicKey, expected: {}, now: 1000 }));
    for (const [field, value] of Object.entries(expected)) {
      const different = typeof value === "string" ? value.replace(/a/g, "b").replace(/7/g, "6") + (field === "origin" || field === "iss" ? ":8443" : "") : { ...value, sub: "another-person" };
      const mismatch = different === value ? `${value}b` : different;
      await assert.rejects(async () => verifier({ jws, public_key: keys.publicKey, expected: { ...expected, [field]: mismatch }, now: 1000 }));
    }
  }
});
test("signed payloads reject unknown fields, excess lifetimes and malformed encodings", async () => {
  for (const payload of [{ ...f.proof, exp: 1061 }, { ...f.approval, exp: 1601 }, { ...f.claims, exp: 1601 }, { ...f.claims, display_name: "Extra" }]) await assert.rejects(sign(payload));
  await assert.rejects(verify(await rawSign({ alg: "EdDSA" }, { ...f.proof, typ: "tartlet-hello" })));
  await assert.rejects(verify(await rawSign({ alg: "EdDSA" }, { ...f.proof, key: "forbidden" })));
  for (const jws of ["", "a.b", "a.b.c.d", "a.b.c", "e30.e30.", "e30=.e30.AA"]) await assert.rejects(verify(jws));
  const jws = await sign(f.proof);
  await assert.rejects(verify(jws, { now: -1 }));
});

test("each artifact verifier rejects every other signed artifact type", async () => {
  const cases = [
    [f.hello, p.verifyHello, { server_id: f.serverId, nonce: f.nonce }],
    [f.poll, p.verifyEnrollmentPoll, { device_code: f.poll.device_code }],
    [f.approval, p.verifyEnrollmentApproval, { server_id: f.serverId, org_id: f.orgId, server_public_key: f.rawPublicKey, approver: f.person, nonce: f.nonce }],
    [f.proof, p.verifyServerProof, { server_id: f.serverId, origin: f.proof.origin, nonce: f.nonce }],
    [f.claims, p.verifyIdentityToken, { iss: f.claims.iss, aud: f.serverId, nonce: f.nonce, org: f.orgId }],
  ];
  for (const [payload] of cases) {
    const jws = await sign(payload);
    for (const [other, verifier, expected] of cases) {
      if (payload.typ === other.typ) continue;
      await assert.rejects(async () => verifier({ jws, public_key: keys.publicKey, expected, now: 1000 }));
    }
  }
  const { typ: _typ, ...withoutType } = f.claims;
  assert.equal(p.IdentityTokenClaimsSchema.safeParse(withoutType).success, false);
});
