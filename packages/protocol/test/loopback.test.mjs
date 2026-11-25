import assert from "node:assert/strict";
import test from "node:test";
import { EnrollmentAddressSchema, EnrollmentStartRequestSchema } from "../dist/index.js";
import * as f from "./fixtures.mjs";

test("loopback enrollment is localhost HTTP with an explicit port and no HTTPS trust", () => {
  for (const port of [1, 80, 443, 8080, 65535]) {
    const address = { kind: "loopback", host: "localhost", port };
    assert.deepEqual(EnrollmentAddressSchema.parse(address), address);
    assert.equal(EnrollmentStartRequestSchema.safeParse({ server_public_key: f.rawPublicKey, server_name: "Server 1", nonce: f.nonce, addresses: [address] }).success, true);
  }
});

test("loopback addresses cannot change host, omit the port, or set a scheme", () => {
  for (const change of [{ host: "127.0.0.1" }, { host: "::1" }, { host: "other.example.com" }, { host: "localhost.example.com" }, { host: "LOCALHOST" }, { port: undefined }, { port: 0 }, { port: 65536 }, { port: "8080" }, { scheme: "https" }]) {
    assert.equal(EnrollmentAddressSchema.safeParse({ kind: "loopback", host: "localhost", port: 8080, ...change }).success, false);
  }
  assert.equal(EnrollmentAddressSchema.safeParse({ kind: "lan", host: "server.example.com", port: 443 }).success, false);
});
