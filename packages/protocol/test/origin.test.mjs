import assert from "node:assert/strict";
import test from "node:test";
import { CanonicalOriginSchema, normalizeOrigin } from "@tartlet/protocol";

test("canonicalizes HTTPS origins without paths or default ports", () => {
  const cases = [
    ["https://SERVER.Example.com:443/", "https://server.example.com"],
    ["HTTPS://Server.Example.com:8443/", "https://server.example.com:8443"],
    ["https://[2001:db8::1]:443", "https://[2001:db8::1]"],
    ["https://127.0.0.1:8443", "https://127.0.0.1:8443"],
    ["https://例え.example", "https://xn--r8jz45g.example"],
  ];
  for (const [input, expected] of cases) {
    assert.equal(normalizeOrigin(input), expected);
    assert.equal(CanonicalOriginSchema.parse(expected), expected);
  }
});
test("rejects non-HTTPS, credentials and non-origin URL components", () => {
  for (const value of ["http://server.example.com", "wss://server.example.com", "https://user:pass@server.example.com", "https://server.example.com/path", "https://server.example.com/a/..", "https://server.example.com?x=1", "https://server.example.com/#x", " https://server.example.com", "https://server.example.com\n", "https://server.example.com\\path", "not an origin"]) assert.throws(() => normalizeOrigin(value));
  assert.equal(CanonicalOriginSchema.safeParse("https://server.example.com/").success, false);
  assert.equal(CanonicalOriginSchema.safeParse("https://server.example.com:443").success, false);
});
