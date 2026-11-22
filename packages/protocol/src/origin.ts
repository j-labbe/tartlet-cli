import { z } from "zod";
import { HttpsUrlSchema } from "./primitives.js";

export function normalizeOrigin(value: string): string {
  if (!/^https:\/\/[^/?#]+\/?$/i.test(value) || /[\\\s]/.test(value)) throw new Error("Expected an HTTPS origin.");
  const url = new URL(HttpsUrlSchema.parse(value));
  if (url.port === "0" || url.hostname.endsWith(".")) throw new Error("Origins cannot use port zero or a trailing dot.");
  return url.origin;
}

function isCanonicalOrigin(value: string): boolean {
  try { return normalizeOrigin(value) === value; } catch { return false; }
}

export const CanonicalOriginSchema = z.string().refine(isCanonicalOrigin, "Expected a canonical HTTPS origin.");
export type CanonicalOrigin = z.infer<typeof CanonicalOriginSchema>;
