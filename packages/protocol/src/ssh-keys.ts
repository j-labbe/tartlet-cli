import { z } from "zod";

const MAX_KEY_LINE_BYTES = 8192;
const MAX_RSA_BITS = 16384;

class SshReader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  field(): Uint8Array {
    if (this.offset + 4 > this.bytes.length) throw new Error("Incomplete SSH key field.");
    const length = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0);
    this.offset += 4;
    if (length > this.bytes.length - this.offset) throw new Error("Incomplete SSH key field.");
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  end(): void {
    if (this.offset !== this.bytes.length) throw new Error("Unexpected SSH key data.");
  }
}

function decodeKey(value: string): { bytes: Uint8Array; canonical: string } {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("Invalid SSH key encoding.");
  const binary = atob(value);
  const canonical = btoa(binary);
  if (canonical !== value) throw new Error("Noncanonical SSH key encoding.");
  return { bytes: Uint8Array.from(binary, (char) => char.charCodeAt(0)), canonical };
}

function unsignedInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  return value;
}

function positiveMpint(bytes: Uint8Array): { value: bigint; bits: number } {
  const first = bytes[0];
  if (first === undefined || first >= 128) throw new Error("SSH integers must be positive.");
  if (first === 0 && (bytes[1] ?? 0) < 128) throw new Error("Noncanonical SSH integer.");
  const offset = first === 0 ? 1 : 0;
  const bits = (bytes.length - offset - 1) * 8 + Math.floor(Math.log2(bytes[offset] ?? 0)) + 1;
  if (bits > MAX_RSA_BITS) throw new Error("RSA integers cannot exceed 16384 bits.");
  return { value: unsignedInteger(bytes), bits };
}

const curves = {
  nistp256: {
    size: 32,
    p: BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
  },
  nistp384: {
    size: 48,
    p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
    b: BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
  },
  nistp521: {
    size: 66,
    p: (1n << 521n) - 1n,
    b: BigInt("0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
  },
};
const CurveSchema = z.enum(["nistp256", "nistp384", "nistp521"]);
const KeyTypeSchema = z.enum(["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"]);
export type PublicKeyType = z.infer<typeof KeyTypeSchema>;
export interface ParsedPublicKey { type: PublicKeyType; public_key: string }

function validatePoint(curveName: z.infer<typeof CurveSchema>, point: Uint8Array): void {
  const { size, p, b } = curves[curveName];
  if (point.length !== 1 + 2 * size || point[0] !== 4) throw new Error("Invalid uncompressed NIST public key.");
  const x = unsignedInteger(point.slice(1, 1 + size));
  const y = unsignedInteger(point.slice(1 + size));
  if (x >= p || y >= p || (y * y - x * x * x + 3n * x - b) % p !== 0n) throw new Error("Public key is not on the NIST curve.");
}

function validateRsa(reader: SshReader): void {
  const exponentBytes = reader.field();
  const modulusBytes = reader.field();
  const { value: modulus, bits: modulusBits } = positiveMpint(modulusBytes);
  const { value: exponent } = positiveMpint(exponentBytes);
  if (exponent < 3n || exponent % 2n !== 1n || exponent >= modulus) throw new Error("Invalid RSA exponent.");
  if (modulusBits < 2048 || modulus % 2n !== 1n) throw new Error("RSA keys must have at least 2048 bits.");
}

function validateKey(type: PublicKeyType, reader: SshReader): void {
  switch (type) {
    case "ssh-ed25519":
      if (reader.field().length !== 32) throw new Error("Ed25519 public keys must have 32 bytes.");
      return;
    case "ssh-rsa": return validateRsa(reader);
    case "ecdsa-sha2-nistp256":
    case "ecdsa-sha2-nistp384":
    case "ecdsa-sha2-nistp521": {
      const curve = CurveSchema.parse(new TextDecoder("utf-8", { fatal: true }).decode(reader.field()));
      if (type !== `ecdsa-sha2-${curve}`) throw new Error("SSH key type and curve differ.");
      return validatePoint(curve, reader.field());
    }
    default: { const exhaustive: never = type; return exhaustive; }
  }
}

export function parsePublicKey(value: string): ParsedPublicKey {
  if (value.length > MAX_KEY_LINE_BYTES || new TextEncoder().encode(value).byteLength > MAX_KEY_LINE_BYTES) throw new Error("SSH public key lines cannot exceed 8 KiB.");
  if (/[\r\n]/.test(value)) throw new Error("An SSH public key must occupy one line.");
  const [rawType, encoded] = value.trim().split(/[ \t]+/);
  const type = KeyTypeSchema.parse(rawType);
  if (encoded === undefined) throw new Error("Missing SSH public key data.");
  const { bytes, canonical } = decodeKey(encoded);
  const reader = new SshReader(bytes);
  if (new TextDecoder("utf-8", { fatal: true }).decode(reader.field()) !== type) throw new Error("SSH key types differ.");
  validateKey(type, reader);
  reader.end();
  return { type, public_key: `${type} ${canonical}` };
}

export const PublicKeySchema = z.string().transform((value, context) => {
  try { return parsePublicKey(value).public_key; }
  catch {
    context.addIssue({ code: "custom", message: "Expected one Ed25519, NIST ECDSA or RSA 2048+ public key without options." });
    return z.NEVER;
  }
});
