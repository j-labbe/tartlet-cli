import { generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { z } from "zod";

function field(value: Buffer | string): Buffer {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value), length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length); return Buffer.concat([length, bytes]);
}
export function encodeEd25519Pair(pair: { publicKey: KeyObject; privateKey: KeyObject }) {
  const { x, d } = z.object({ x: z.string(), d: z.string() }).parse(pair.privateKey.export({ format: "jwk" }));
  const publicBytes = Buffer.from(x, "base64url"), seed = Buffer.from(d, "base64url"), type = "ssh-ed25519";
  const publicBlob = Buffer.concat([field(type), field(publicBytes)]), check = randomBytes(4);
  const contents = Buffer.concat([check, check, field(type), field(publicBytes), field(Buffer.concat([seed, publicBytes])), field("")]);
  const padding = Buffer.from(Array.from({ length: (8 - contents.length % 8) % 8 }, (_, index) => index + 1)), count = Buffer.alloc(4); count.writeUInt32BE(1);
  const encoded = Buffer.concat([Buffer.from("openssh-key-v1\0"), field("none"), field("none"), field(""), count, field(publicBlob), field(Buffer.concat([contents, padding]))]).toString("base64");
  return { public: `${type} ${publicBlob.toString("base64")}`, private: `-----BEGIN OPENSSH PRIVATE KEY-----\n${encoded.match(/.{1,70}/g)?.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n` };
}
// ssh2's generator drops leading zero bytes from Ed25519 public keys.
export function generatePair() { return encodeEd25519Pair(generateKeyPairSync("ed25519")); }
