import { z } from "zod";
import { isBase64Url32 } from "./encoding.js";

function hasSafeHttpsAuthority(value: string): boolean {
  const authority = /^https:\/\/([^/?#]*)/i.exec(value)?.[1];
  try { return authority !== undefined && !authority.includes("@") && !/[\p{Cc}\\\s]/u.test(value) && new URL(value).port !== "0"; }
  catch { return false; }
}
function isCanonicalHost(value: string): boolean {
  if (value.length > 253) return false;
  try {
    if (value.includes(":")) return new URL(`https://[${value}]`).hostname === `[${value}]`;
    const labels = value.split(".");
    if (!labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) return false;
    return new URL(`https://${value}`).hostname.toLowerCase() === value.toLowerCase();
  } catch { return false; }
}

export const HttpsUrlSchema = z.url({ protocol: /^https$/ }).max(2048).refine(hasSafeHttpsAuthority, "HTTPS URLs cannot contain userinfo, control characters, backslashes, or whitespace.");
export const NonceSchema = z.string().length(43).refine(isBase64Url32, "Expected 32 bytes in canonical base64url.");
export const ServerPublicKeySchema = z.string().length(43).refine(isBase64Url32, "Expected a raw 32-byte Ed25519 public key in base64url.");
export const UnixTimeSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const TimestampSchema = z.iso.datetime({ offset: true });
export const CursorSchema = z.string().min(1).max(128);
export const DeviceCodeSchema = z.string().min(1).max(128);
export const PersonIdentitySchema = z.strictObject({ iss: HttpsUrlSchema, sub: z.string().min(1).max(255) });
export const HostSchema = z.string().min(1).max(253).refine(isCanonicalHost, "Expected a DNS name, a dotted IPv4 address, or a canonical lowercase IPv6 address with no brackets or port.");
export const SshUserSchema = z.string().regex(/^[a-z_][a-z0-9_.-]{0,31}$/);
export const HostKeyAliasSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
export const PortSchema = z.number().int().min(1).max(65535);
export type PersonIdentity = z.infer<typeof PersonIdentitySchema>;
