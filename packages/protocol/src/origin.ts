import { z } from "zod";

export function normalizeOrigin(value: string): string {
  if (!/^https:\/\/[^/?#]+\/?$/i.test(value) || /[\\\s]/.test(value)) throw new Error("Expected an HTTPS origin.");
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("An HTTPS origin without credentials is required.");
  if (url.pathname !== "/" || url.search || url.hash) throw new Error("An origin cannot contain a path, query or fragment.");
  return url.origin;
}

function isCanonicalOrigin(value: string): boolean {
  try { return normalizeOrigin(value) === value; } catch { return false; }
}

export const CanonicalOriginSchema = z.string().refine(isCanonicalOrigin, "Expected a canonical HTTPS origin.");
export type CanonicalOrigin = z.infer<typeof CanonicalOriginSchema>;
