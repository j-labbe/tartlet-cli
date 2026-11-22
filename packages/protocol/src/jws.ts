import { z } from "zod";
import { CLOCK_SKEW_SECONDS, SignedPayloadSchema } from "./artifacts.js";
import type { SignedPayload } from "./artifacts.js";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import { UnixTimeSchema } from "./primitives.js";

export const JwsHeaderSchema = z.strictObject({ alg: z.literal("EdDSA"), kid: z.string().min(1).optional() });
export type JwsHeader = z.infer<typeof JwsHeaderSchema>;
const ClockClaimsSchema = z.looseObject({ iat: UnixTimeSchema, exp: UnixTimeSchema, nbf: UnixTimeSchema.optional() });
const RecordSchema = z.record(z.string(), z.unknown());

function encodeJson(value: unknown): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}
function decodeJson(value: string): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(value)));
}
function checkKey(key: CryptoKey, type: "public" | "private"): void {
  if (key.type !== type || key.algorithm.name !== "Ed25519") throw new Error("A trusted Ed25519 key of the required type is required.");
}
function checkTime(payload: unknown, now: number): void {
  const claims = ClockClaimsSchema.parse(payload);
  UnixTimeSchema.parse(now);
  if (claims.exp <= claims.iat) throw new Error("JWS expiry must follow issuance.");
  if (now >= claims.exp + CLOCK_SKEW_SECONDS) throw new Error("JWS has expired.");
  if (claims.iat > now + CLOCK_SKEW_SECONDS) throw new Error("JWS was issued in the future.");
  if (claims.nbf !== undefined && claims.nbf > now + CLOCK_SKEW_SECONDS) throw new Error("JWS is not yet valid.");
}
function matchesExpected(actual: unknown, expected: unknown): boolean {
  const record = RecordSchema.safeParse(expected);
  if (!record.success) return Object.is(actual, expected);
  const value = RecordSchema.safeParse(actual);
  if (!value.success) return false;
  return Object.entries(record.data).every(([key, field]) => Object.hasOwn(value.data, key) && matchesExpected(value.data[key], field));
}

export async function signJws(options: { payload: SignedPayload; private_key: CryptoKey; kid?: string }): Promise<string> {
  checkKey(options.private_key, "private");
  const payload = SignedPayloadSchema.parse(options.payload);
  const header = JwsHeaderSchema.parse({ alg: "EdDSA", ...(options.kid === undefined ? {} : { kid: options.kid }) });
  const input = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = await globalThis.crypto.subtle.sign("Ed25519", options.private_key, new TextEncoder().encode(input));
  return `${input}.${encodeBase64Url(new Uint8Array(signature))}`;
}

export interface VerifyJwsOptions<T> {
  jws: string;
  public_key: CryptoKey;
  schema: z.ZodType<T>;
  expected: Partial<T>;
  now?: number;
}

export async function verifyJws<T>(options: VerifyJwsOptions<T>): Promise<T> {
  checkKey(options.public_key, "public");
  const segments = options.jws.split(".");
  const [header, body, signature] = segments;
  if (segments.length !== 3 || !header || !body || !signature) throw new Error("Expected a compact JWS.");
  JwsHeaderSchema.parse(decodeJson(header));
  const valid = await globalThis.crypto.subtle.verify("Ed25519", options.public_key, decodeBase64Url(signature), new TextEncoder().encode(`${header}.${body}`));
  if (!valid) throw new Error("Invalid JWS signature.");
  const raw = decodeJson(body);
  checkTime(raw, options.now ?? Math.floor(Date.now() / 1000));
  const payload = options.schema.parse(raw);
  if (!matchesExpected(payload, options.expected)) throw new Error("JWS does not match the expected fields.");
  return payload;
}
