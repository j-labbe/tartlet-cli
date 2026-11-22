import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { parsePublicKey, PublicKeySchema } from "@tartlet/protocol";
import { field, mpint, publicKey, sshKey } from "./fixtures.mjs";

function ecdsaKey(curve, name) {
  const jwk = generateKeyPairSync("ec", { namedCurve: curve }).publicKey.export({ format: "jwk" });
  return sshKey(`ecdsa-sha2-${name}`, [name, Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")])]);
}
function rsaKey(bits) {
  const jwk = generateKeyPairSync("rsa", { modulusLength: bits }).publicKey.export({ format: "jwk" });
  return sshKey("ssh-rsa", [mpint(jwk.e), mpint(jwk.n)]);
}

test("Ed25519 parsing strips identifying comments", () => {
  assert.deepEqual(parsePublicKey(`  ${publicKey} person@example.com host-1  `), { type: "ssh-ed25519", public_key: publicKey });
  assert.equal(PublicKeySchema.parse(`${publicKey} example comment`), publicKey);
});
for (const [curve, name] of [["prime256v1", "nistp256"], ["secp384r1", "nistp384"], ["secp521r1", "nistp521"]]) {
  test(`accepts a real ${name} key`, () => {
    const key = ecdsaKey(curve, name);
    assert.equal(parsePublicKey(key).public_key, key);
  });
}
test("RSA accepts 2048+ and rejects undersized keys", () => {
  for (const bits of [2048, 3072]) assert.equal(PublicKeySchema.safeParse(rsaKey(bits)).success, true);
  assert.equal(PublicKeySchema.safeParse(rsaKey(1024)).success, false);
});
test("SSH parsing rejects options, multiline input, wrong algorithms and corrupt blobs", () => {
  const invalid = [
    `restrict ${publicKey}`, `command="example" ${publicKey}`, `${publicKey}\n${publicKey}`, `${publicKey}\r`,
    `${publicKey} comment\n`, "ssh-dss AAAA", "sk-ssh-ed25519@openssh.com AAAA", "ssh-ed25519 !!!!", "ssh-ed25519 A",
    sshKey("ssh-ed25519", [Buffer.alloc(31)]), sshKey("ssh-ed25519", [Buffer.alloc(33)]),
    `ssh-rsa ${publicKey.split(" ")[1]}`, `${publicKey}AAAA`,
    sshKey("ecdsa-sha2-nistp256", ["nistp384", Buffer.alloc(65)]),
    sshKey("ecdsa-sha2-nistp256", ["nistp256", Buffer.concat([Buffer.from([4]), Buffer.alloc(64)])]),
    sshKey("ecdsa-sha2-nistp256", ["nistp256", Buffer.alloc(33, 2)]),
    sshKey("ssh-rsa", [Buffer.from([1]), Buffer.alloc(257, 127)]),
    sshKey("ssh-rsa", [Buffer.from([3]), Buffer.from([128])]),
    sshKey("ssh-rsa", [Buffer.from([0, 3]), Buffer.alloc(257, 127)]),
  ];
  for (const value of invalid) assert.equal(PublicKeySchema.safeParse(value).success, false, value.slice(0, 60));
  const truncated = Buffer.concat([field("ssh-ed25519"), Buffer.from([255, 255, 255, 255])]);
  assert.throws(() => parsePublicKey(`ssh-ed25519 ${truncated.toString("base64")}`));
  assert.throws(() => parsePublicKey(sshKey("ssh-ed25519", [Buffer.alloc(32), "trailing"])));
});
