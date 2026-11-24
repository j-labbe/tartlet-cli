import { z } from "zod";
import { ErrorResponseSchema } from "@tartlet/protocol";

const secrets = new Set<string>();
export function keepSecret(value: string): string { secrets.add(value); return value; }
export function plain(value: string): string { return value.replace(/[\p{Cc}\p{Cf}]/gu, " ").slice(0, 2048); }
export function safeMessage(error: unknown): string {
  let message = error instanceof Error ? error.message : "The command failed.";
  for (const secret of [...secrets].sort((left, right) => right.length - left.length)) message = message.replaceAll(secret, "[redacted]");
  return plain(message);
}
export class HttpError extends Error {
  constructor(readonly status: number, readonly reason: string, message: string) { super(`HTTP ${status}: ${reason}. ${message}`); }
}
const OAuthErrorSchema = z.object({ error: z.string().max(128), error_description: z.string().max(2048).optional() });
export function responseError(status: number, body: unknown): HttpError {
  const protocol = ErrorResponseSchema.safeParse(body);
  if (protocol.success) return new HttpError(status, protocol.data.error.code, protocol.data.error.message);
  const oauth = OAuthErrorSchema.safeParse(body);
  if (oauth.success) return new HttpError(status, oauth.data.error, oauth.data.error_description ?? "If your sign-in has ended, run tartlet login again.");
  return new HttpError(status, "request_failed", "The server could not complete the request.");
}
const CodeSchema = z.object({ code: z.string() });
const certificateErrors = new Set(["SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "DEPTH_ZERO_SELF_SIGNED_CERT", "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_HAS_EXPIRED"]);
const unreachableErrors = new Set(["ENOTFOUND", "EAI_AGAIN", "EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT"]);
const refusedErrors = new Set(["ECONNREFUSED", "ECONNRESET"]);
function cloudIssuer(origin: string | undefined) { return origin !== undefined && new URL(origin).hostname === "app.tartlet.io"; }
function unreachableMessage(origin: string | undefined) {
  if (cloudIssuer(origin)) return "Cannot reach Tartlet cloud. Check your internet connection and try again.";
  return "Cannot reach the server's network. Turn on Tailscale if the server is on a tailnet, then check the server address.";
}
export function networkError(error: unknown, origin?: string): Error {
  const parsed = CodeSchema.safeParse(error), code = parsed.success ? parsed.data.code : "";
  if (certificateErrors.has(code) && cloudIssuer(origin)) return new Error("The Tartlet cloud HTTPS certificate is not trusted. Check your internet connection or contact your administrator.");
  if (certificateErrors.has(code)) return new Error("The server's HTTPS certificate is not trusted. If your administrator gave you a root certificate, run `tartlet login --server <url> --ca <root.pem>`.");
  if (unreachableErrors.has(code)) return Object.assign(new Error(unreachableMessage(origin)), { code });
  if (refusedErrors.has(code)) return new Error("The server is down or refused the connection. Check that Tartlet is running at the address you signed in to.");
  return error instanceof Error ? error : new Error("The connection failed.");
}
