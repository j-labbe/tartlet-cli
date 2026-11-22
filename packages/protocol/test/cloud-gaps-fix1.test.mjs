import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

const start = { server_public_key: f.rawPublicKey, server_name: "Server 1", addresses: f.listedServer.addresses, nonce: f.nonce };
const catchUp = { type: "catch_up", cutoffs: [f.cutoff], next_cursor: "cursor-1", complete: true, upstream_synced_at: 990 };
const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);

for (const [name, character] of [["ESC", "\u001b"], ["bidi override", "\u202e"]]) {
  test(`enrollment server names reject ${name} with a clear validation error`, () => {
    const result = p.EnrollmentStartRequestSchema.safeParse({ ...start, server_name: `Server${character}1` });
    assert.equal(result.success, false);
    assert.match(result.error?.message ?? "", /control or formatting characters/);
  });
  test(`directory server names reject ${name} with a clear validation error`, () => {
    const result = p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, name: `Server${character}1` }] });
    assert.equal(result.success, false);
    assert.match(result.error?.message ?? "", /control or formatting characters/);
  });
}

test("server names retain ordinary Unicode text", () => {
  for (const server_name of ["Server 1", "Serveur été", "東京 lab", "Lab 🖥"]) {
    assert.equal(p.EnrollmentStartRequestSchema.parse({ ...start, server_name }).server_name, server_name);
    assert.equal(p.ServerListResponseSchema.parse({ servers: [{ ...f.listedServer, name: server_name }] }).servers[0].name, server_name);
  }
});

test("catch-up messages require the cloud's upstream reconciliation time in both inbound unions", () => {
  const { upstream_synced_at: _omitted, ...missing } = catchUp;
  for (const schema of [p.CatchUpMessageSchema, p.CloudMessageSchema, p.CloudToServerMessageSchema]) {
    assert.equal(schema.safeParse(missing).success, false);
    assert.deepEqual(schema.parse(catchUp), catchUp);
    assert.equal(schema.parse({ ...catchUp, complete: false }).upstream_synced_at, 990);
    for (const value of [-1, 0.5, "990", null, Number.MAX_SAFE_INTEGER + 1]) assert.equal(schema.safeParse({ ...catchUp, upstream_synced_at: value }).success, false);
    assert.equal(schema.parse({ ...catchUp, upstream_synced_at: 0 }).upstream_synced_at, 0);
  }
});

test("catch-up schema documents storing the cloud's reconciliation time instead of the server's clock", () => {
  const description = p.CatchUpMessageSchema.shape.upstream_synced_at?.description ?? "";
  assert.match(description, /last complete upstream reconciliation for the organization/);
  assert.match(description, /no undelivered cut-offs/);
  assert.match(description, /server records this value as its last successful sync, never its own clock/i);
});

test("enrollment and directory addresses omit the default HTTPS port", () => {
  const address = { kind: "tailnet", host: "server.example.com" };
  assert.deepEqual(p.EnrollmentAddressSchema.parse(address), address);
  for (const port of [1, 8443, 65535]) assert.equal(p.EnrollmentAddressSchema.parse({ ...address, port }).port, port);
  assert.equal(p.EnrollmentAddressSchema.safeParse({ ...address, port: 443 }).success, false);
  assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, addresses: [{ ...address, port: 443 }] }).success, false);
  assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, addresses: [{ ...address, port: 443 }] }] }).success, false);
  assert.equal(p.PortSchema.parse(443), 443);
});

test("HTTPS root fingerprint schema and README define hashing DER-encoded root SPKI", async () => {
  const localCa = p.HttpsTrustSchema.options.find((option) => option.shape.kind.value === "local_ca");
  const description = localCa?.shape.root_sha256.description ?? "";
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  for (const text of [description, readme]) {
    assert.match(text, /SHA-256 of the root certificate's DER-encoded SubjectPublicKeyInfo \(SPKI\)/);
    assert.match(text, /lowercase hex/);
  }
});

test("server directory rejects duplicate server IDs", () => {
  const duplicate = { ...f.listedServer, org_id: `org_${"c".repeat(26)}`, name: "Server 2", online: false };
  assert.equal(p.ServerListResponseSchema.safeParse({ servers: [f.listedServer, duplicate] }).success, false);
  const distinct = { ...duplicate, server_id: `srv_${"b".repeat(26)}` };
  assert.equal(p.ServerListResponseSchema.parse({ servers: [f.listedServer, distinct] }).servers.length, 2);
});

test("server directory rejects duplicate address triples with and without an explicit port", () => {
  for (const address of [{ kind: "lan", host: "server.example.com" }, { kind: "tailnet", host: "server.example.com", port: 8443 }]) {
    const server = { ...f.listedServer, addresses: [address, { ...address }] };
    assert.equal(p.ServerListResponseSchema.safeParse({ servers: [server] }).success, false);
  }
  const addresses = [
    { kind: "lan", host: "server.example.com" },
    { kind: "tailnet", host: "server.example.com" },
    { kind: "lan", host: "server.example.com", port: 8443 },
    { kind: "lan", host: "other.example.com" },
  ];
  assert.deepEqual(p.ServerListResponseSchema.parse({ servers: [{ ...f.listedServer, addresses }] }).servers[0].addresses, addresses);
});

test("cloud access expectations reject a mismatched issuer and audience before inspecting the JWS", async () => {
  await assert.rejects(async () => p.verifyCloudAccessToken({
    jws: "bad", public_key: keys.publicKey, expected: { iss: f.cloudAccess.iss, aud: "https://other.example.com" }, now: 1000,
  }), /Expected cloud access audience must match its issuer/);
});

test("extended enrollment approver rejects unknown keys in schemas, signing, and verification", async () => {
  const payload = { ...f.approval, approver: { ...f.approval.approver, extra: true } };
  assert.equal(p.EnrollmentApprovalPayloadSchema.safeParse(payload).success, false);
  await assert.rejects(p.signJws({ payload, private_key: keys.privateKey }));
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const input = `${header}.${body}`;
  const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(input));
  const jws = `${input}.${Buffer.from(signature).toString("base64url")}`;
  await assert.rejects(p.verifyEnrollmentApproval({
    jws, public_key: keys.publicKey, expected: { mode: "initial", server_public_key: f.rawPublicKey, nonce: f.nonce, approver_iss: f.person.iss }, now: 1000,
  }));
});
