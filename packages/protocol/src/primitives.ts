import { z } from "zod";
import { isBase64Url32 } from "./encoding.js";

export const NonceSchema = z.string().refine(isBase64Url32, "Expected 32 bytes in canonical base64url.");
export const ServerPublicKeySchema = z.string().refine(isBase64Url32, "Expected a raw 32-byte Ed25519 public key in base64url.");
export const UnixTimeSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const TimestampSchema = z.iso.datetime({ offset: true });
export const CursorSchema = z.string().min(1);
export const PersonIdentitySchema = z.strictObject({ iss: z.url({ protocol: /^https$/ }), sub: z.string().min(1) });
export const HostSchema = z.string().min(1).refine((value) => {
  try {
    const url = new URL(`https://${value}`);
    return url.host.toLowerCase() === value.toLowerCase() && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash;
  } catch { return false; }
}, "Expected a host name or IP address.");
export const PortSchema = z.number().int().min(1).max(65535);
export type PersonIdentity = z.infer<typeof PersonIdentitySchema>;
