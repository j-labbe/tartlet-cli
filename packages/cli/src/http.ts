import { request } from "node:https";
import { X509Certificate, createHash } from "node:crypto";
import type { ConnectionOptions } from "node:tls";
import { z } from "zod";
import type { Trust } from "./storage.js";
import { networkError, responseError } from "./errors.js";

export type Endpoint = { origin: string; trust: Trust };
export function localTrust(pem: string): Trust {
  const certificate = new X509Certificate(pem);
  if (!certificate.ca || !certificate.verify(certificate.publicKey)) throw new Error("--ca needs the self-signed root certificate, not the server's own certificate.");
  const root_sha256 = createHash("sha256").update(certificate.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return { kind: "local_ca", root_sha256, root_pem: certificate.toString() };
}
export function tlsOptions(trust: Trust): ConnectionOptions {
  if (trust.kind === "webpki") return { rejectUnauthorized: true };
  const checked = localTrust(trust.root_pem);
  if (checked.kind !== "local_ca" || checked.root_sha256 !== trust.root_sha256) throw new Error("The saved root certificate does not match its pin. Sign in again with the correct --ca file.");
  return { rejectUnauthorized: true, ca: checked.root_pem };
}
export function sameOriginUrl(origin: string, value: string): URL {
  const url = new URL(value);
  if (url.origin !== origin || url.username || url.password || url.hash || url.protocol !== "https:") throw new Error("The server sent a sign-in address outside its saved HTTPS origin.");
  return url;
}
export interface JsonRequest { endpoint: Endpoint; url: string; method?: string; body?: string; headers?: Record<string, string> }
export async function requestJson(input: JsonRequest): Promise<{ status: number; body: unknown }> {
  const url = sameOriginUrl(input.endpoint.origin, input.url);
  const options = tlsOptions(input.endpoint.trust);
  return new Promise((resolve, reject) => {
    const req = request(url, { ...options, method: input.method ?? "GET", headers: { Accept: "application/json", ...input.headers }, timeout: 30000 }, (res) => {
      const chunks: Buffer[] = []; let length = 0;
      res.on("data", (chunk: Buffer) => {
        length += chunk.length;
        if (length > 4 * 1024 * 1024) { res.destroy(new Error("The server sent a reply that is too large.")); return; }
        chunks.push(chunk);
      });
      res.on("error", reject);
      res.on("end", () => {
        let body: unknown;
        try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch { reject(new Error(`HTTP ${res.statusCode ?? 0}: the server did not send JSON. Check that the address points to Tartlet.`)); return; }
        resolve({ status: res.statusCode ?? 0, body });
      });
    });
    req.on("timeout", () => req.destroy(Object.assign(new Error("The connection timed out."), { code: "ETIMEDOUT" })));
    req.on("error", (error) => reject(networkError(error, input.endpoint.origin)));
    req.end(input.body);
  });
}
export async function json<T>(input: JsonRequest, schema: z.ZodType<T>): Promise<T> {
  const response = await requestJson(input);
  if (response.status < 200 || response.status >= 300) throw responseError(response.status, response.body);
  const parsed = schema.safeParse(response.body);
  if (!parsed.success) throw new Error("The CLI cannot read the server's reply. Check that the CLI version matches the server.");
  return parsed.data;
}
export function form(endpoint: Endpoint, url: string, fields: Record<string, string>): JsonRequest {
  return { endpoint, url, method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString() };
}
