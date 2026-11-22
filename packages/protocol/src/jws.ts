import { z } from "zod";
import { JwsCompactSchema } from "./cloud.js";
import { SignedPayloadSchema } from "./artifacts.js";
import type { SignedPayload } from "./artifacts.js";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";

export const JwsHeaderSchema = z.strictObject({ alg: z.literal("EdDSA"), kid: z.string().min(1).max(64).optional() });
export type JwsHeader = z.infer<typeof JwsHeaderSchema>;
function encodeJson(value: unknown): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}
function decodeJson(value: string): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(value)));
}
function checkKey(key: CryptoKey, type: "public" | "private"): void {
  if (key.type !== type || key.algorithm.name !== "Ed25519") throw new Error(`Pass a trusted Ed25519 ${type} key.`);
}
export async function signJws(options: { payload: SignedPayload; private_key: CryptoKey; kid?: string }): Promise<string> {
  checkKey(options.private_key, "private");
  const payload = SignedPayloadSchema.parse(options.payload);
  const header = JwsHeaderSchema.parse({ alg: "EdDSA", ...(options.kid === undefined ? {} : { kid: options.kid }) });
  const input = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = await globalThis.crypto.subtle.sign("Ed25519", options.private_key, new TextEncoder().encode(input));
  return `${input}.${encodeBase64Url(new Uint8Array(signature))}`;
}

function compactParts(jws: string): { header: string; body: string; signature: string } {
  JwsCompactSchema.parse(jws);
  const [header = "", body = "", signature = ""] = jws.split(".");
  return { header, body, signature };
}

/** Read the unverified JWS header so you can pick a trusted local key by kid. This does not verify the token or its claims. */
export function readUnverifiedJwsHeader(jws: string): JwsHeader {
  return JwsHeaderSchema.parse(decodeJson(compactParts(jws).header));
}
