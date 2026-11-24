import { z } from "zod";
import { ErrorResponseSchema } from "@tartlet/protocol";

const secrets = new Set<string>();
export function keepSecret(value: string): string { secrets.add(value); return value; }
export function plain(value: string): string { return value.replace(/[\p{Cc}\p{Cf}]/gu, " ").slice(0, 2048); }
export function safeMessage(error: unknown): string {
  let message = error instanceof Error ? error.message : "The command failed.";
  for (const secret of secrets) message = message.replaceAll(secret, "[redacted]");
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
  if (oauth.success) return new HttpError(status, oauth.data.error, oauth.data.error_description ?? "Sign in again if your access has ended.");
  return new HttpError(status, "request_failed", "The server could not complete the request.");
}
const CodeSchema = z.object({ code: z.string() });
export function networkError(error: unknown): Error {
  const parsed = CodeSchema.safeParse(error), code = parsed.success ? parsed.data.code : "";
  switch (code) {
    case "ENOTFOUND": case "EAI_AGAIN": case "EHOSTUNREACH": case "ENETUNREACH": case "ETIMEDOUT":
      return Object.assign(new Error("Cannot resolve the name or reach the server's network. Turn on Tailscale if this server is on a tailnet, then check its address."), { code });
    case "ECONNREFUSED": case "ECONNRESET":
      return new Error("The server is down or refused the connection. Check that Tartlet is running at the saved address.");
    default: return error instanceof Error ? error : new Error("The connection failed.");
  }
}
