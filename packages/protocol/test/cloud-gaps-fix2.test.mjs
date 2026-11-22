import assert from "node:assert/strict";
import test from "node:test";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

const start = { server_public_key: f.rawPublicKey, server_name: "Server 1", addresses: f.listedServer.addresses, nonce: f.nonce };

test("enrollment rejects duplicate address triples through the shared addresses schema", () => {
  for (const address of [{ kind: "lan", host: "server.example.com" }, { kind: "tailnet", host: "server.example.com", port: 8443 }]) {
    const addresses = [address, { ...address }];
    assert.equal(p.EnrollmentStartRequestSchema.shape.addresses.safeParse(addresses).success, false);
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, addresses }).success, false);
  }
});

test("enrollment and directory detect duplicate hosts regardless of case", () => {
  for (const address of [{ kind: "lan", host: "Server.Example.COM" }, { kind: "tailnet", host: "Server.Example.COM", port: 8443 }]) {
    const addresses = [address, { ...address, host: "server.example.com" }];
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, addresses }).success, false);
    assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, addresses }] }).success, false);
  }
});

test("directory detects case-insensitive duplicates independently of enrollment parsing", () => {
  const addresses = [{ kind: "lan", host: "SERVER.example.com", port: 8443 }, { kind: "lan", host: "server.EXAMPLE.com", port: 8443 }];
  assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, addresses }] }).success, false);
});

test("shared uniqueness preserves distinct address triples and original host spelling", () => {
  const addresses = [
    { kind: "lan", host: "Server.Example.COM" },
    { kind: "tailnet", host: "server.example.com" },
    { kind: "lan", host: "SERVER.example.com", port: 8443 },
    { kind: "lan", host: "other.example.com" },
  ];
  assert.deepEqual(p.EnrollmentStartRequestSchema.parse({ ...start, addresses }).addresses, addresses);
  assert.deepEqual(p.ServerListResponseSchema.parse({ servers: [{ ...f.listedServer, addresses }] }).servers[0].addresses, addresses);
});

test("cloud sync time is recorded only after a complete batch, under the cursor-saving rule", () => {
  const description = p.CatchUpMessageSchema.shape.upstream_synced_at.description ?? "";
  assert.match(description, /only after handling a batch with complete: true/);
  assert.match(description, /same rule as saving the cursor/);
});

for (const [name, character] of [["line separator", "\u2028"], ["paragraph separator", "\u2029"], ["unpaired high surrogate", "\ud800"], ["unpaired low surrogate", "\udc00"]]) {
  test(`enrollment server names reject ${name}`, () => {
    assert.equal(p.EnrollmentStartRequestSchema.safeParse({ ...start, server_name: `Server${character}1` }).success, false);
  });
  test(`directory server names reject ${name}`, () => {
    assert.equal(p.ServerListResponseSchema.safeParse({ servers: [{ ...f.listedServer, name: `Server${character}1` }] }).success, false);
  });
}

test("server names retain valid surrogate pairs", () => {
  const server_name = "Lab \ud83d\udda5";
  assert.equal(p.EnrollmentStartRequestSchema.parse({ ...start, server_name }).server_name, server_name);
  assert.equal(p.ServerListResponseSchema.parse({ servers: [{ ...f.listedServer, name: server_name }] }).servers[0].name, server_name);
});
