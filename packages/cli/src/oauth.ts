import { createServer } from "node:http";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { readUnverifiedJwsHeader, verifyCloudAccessToken } from "@tartlet/protocol";
import { json, form, requestJson, sameOriginUrl, type Endpoint, type JsonRequest } from "./http.js";
import { HttpError, keepSecret, responseError } from "./errors.js";
import { TokensSchema, type Tokens } from "./storage.js";

export const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const MetadataSchema = z.object({
  issuer: z.string(), authorization_endpoint: z.string(), token_endpoint: z.string(),
  registration_endpoint: z.string().optional(), device_authorization_endpoint: z.string().optional(),
  jwks_uri: z.string().optional(), code_challenge_methods_supported: z.array(z.string()),
});
export type Metadata = z.infer<typeof MetadataSchema>;
export interface SignInIO { say: (message: string) => void; open: (url: string) => Promise<void> }
export async function discover(endpoint: Endpoint, cloud = false): Promise<Metadata> {
  const path = cloud ? "/.well-known/openid-configuration" : "/.well-known/oauth-authorization-server";
  const metadata = await json({ endpoint, url: `${endpoint.origin}${path}` }, MetadataSchema);
  if (new URL(metadata.issuer).origin !== endpoint.origin) throw new Error("The OAuth issuer does not match the saved server origin.");
  if (!metadata.code_challenge_methods_supported.includes("S256")) throw new Error("The server does not support PKCE S256.");
  for (const url of [metadata.authorization_endpoint, metadata.token_endpoint, metadata.registration_endpoint, metadata.device_authorization_endpoint, metadata.jwks_uri]) {
    if (url !== undefined) sameOriginUrl(endpoint.origin, url);
  }
  return metadata;
}
export async function registerClient(endpoint: Endpoint, metadata: Metadata, redirect: string | undefined): Promise<string> {
  if (!metadata.registration_endpoint) throw new Error("The server does not support public OAuth client registration.");
  const registered = await json({ endpoint, url: metadata.registration_endpoint, method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
    client_name: "Tartlet CLI", redirect_uris: redirect ? [redirect] : [], token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token", DEVICE_GRANT], response_types: ["code"],
  }) }, z.object({ client_id: z.string().min(1).max(256), token_endpoint_auth_method: z.literal("none").optional() }));
  return registered.client_id;
}
function equalState(actual: string | null, expected: string) {
  if (actual === null) return false;
  const left = Buffer.from(actual), right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}
function callbackUrl(value: string | undefined) {
  try { return new URL(value ?? "/", "http://127.0.0.1"); } catch { return undefined; }
}
export async function loopback(state: string, timeout = 600000) {
  let accept: (code: string) => void = () => {}, deny: (error: Error) => void = () => {};
  const code = new Promise<string>((resolve, reject) => { accept = resolve; deny = reject; });
  // A browser can finish before the caller begins awaiting the code.
  void code.catch(() => {});
  const server = createServer((req, res) => {
    const url = callbackUrl(req.url);
    if (!url || req.method !== "GET" || url.pathname !== "/callback" || req.headers.host !== address || !equalState(url.searchParams.get("state"), state)) {
      res.writeHead(400).end("Invalid sign-in callback."); return;
    }
    const value = url.searchParams.get("code");
    if (url.searchParams.has("error") || !value || url.searchParams.getAll("code").length !== 1 || url.searchParams.getAll("state").length !== 1) {
      res.writeHead(400).end("Sign-in was not approved."); deny(new Error("Sign-in was denied or returned an invalid callback.")); return;
    }
    keepSecret(value); res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'" }).end("Signed in. You can close this window.");
    accept(value);
  });
  server.requestTimeout = 10000;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const bound = server.address();
  if (!bound || typeof bound === "string") { server.close(); throw new Error("Cannot open a loopback sign-in callback."); }
  const address = `127.0.0.1:${bound.port}`, timer = setTimeout(() => deny(new Error("Sign-in timed out. Run tartlet login again.")), timeout);
  return { redirect: `http://${address}/callback`, code, close: () => { clearTimeout(timer); server.closeAllConnections(); server.close(); } };
}
interface SignIn { endpoint: Endpoint; metadata: Metadata; device: boolean; cloud: boolean; io: SignInIO }
const resource = (input: SignIn): Record<string, string> => input.cloud ? {} : { resource: `${input.endpoint.origin}/mcp`, scope: "workspaces" };
export async function signIn(input: SignIn): Promise<{ client_id: string; tokens: Tokens }> {
  if (input.device) {
    const client_id = input.cloud ? "tartlet-cli" : await registerClient(input.endpoint, input.metadata, undefined);
    return { client_id, tokens: await deviceSignIn(input, client_id) };
  }
  const state = randomBytes(32).toString("base64url"), callback = await loopback(state);
  try {
    const client_id = input.cloud ? "tartlet-cli" : await registerClient(input.endpoint, input.metadata, callback.redirect);
    const verifier = keepSecret(randomBytes(32).toString("base64url"));
    const url = sameOriginUrl(input.endpoint.origin, input.metadata.authorization_endpoint);
    url.search = new URLSearchParams({ ...resource(input), client_id, response_type: "code", redirect_uri: callback.redirect, state, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" }).toString();
    input.io.say(`Open this URL to sign in:\n${url.href}`);
    await input.io.open(url.href).catch(() => input.io.say("Open the URL above in your browser to continue."));
    const code = await callback.code;
    const tokens = await json(form(input.endpoint, input.metadata.token_endpoint, { ...resource(input), grant_type: "authorization_code", client_id, code, redirect_uri: callback.redirect, code_verifier: verifier }), TokensSchema);
    return { client_id, tokens };
  } finally { callback.close(); }
}
const DeviceSchema = z.object({
  device_code: z.string().min(1).max(2048).transform(keepSecret), user_code: z.string().min(1).max(64),
  verification_uri: z.string(), verification_uri_complete: z.string().optional(),
  expires_in: z.number().int().positive().max(3600), interval: z.number().int().min(1).max(60).default(5),
});
async function devicePoll(input: JsonRequest, request: typeof requestJson): Promise<{ kind: "timeout" } | { kind: "response"; result: Awaited<ReturnType<typeof requestJson>> }> {
  try { return { kind: "response", result: await request(input) }; }
  catch (error) {
    if (z.object({ code: z.literal("ETIMEDOUT") }).safeParse(error).success) return { kind: "timeout" };
    throw error;
  }
}
export async function deviceSignIn(input: SignIn, client_id: string, wait = delay, request = requestJson): Promise<Tokens> {
  const endpoint = input.metadata.device_authorization_endpoint;
  if (!endpoint) throw new Error("This server does not support device sign-in. Run tartlet login without --device.");
  const device = await json(form(input.endpoint, endpoint, { ...resource(input), client_id }), DeviceSchema);
  const verification = sameOriginUrl(input.endpoint.origin, device.verification_uri);
  if (device.verification_uri_complete) sameOriginUrl(input.endpoint.origin, device.verification_uri_complete);
  input.io.say(`Open ${verification.href} and enter code ${device.user_code}.`);
  let interval = device.interval * 1000;
  const deadline = Date.now() + device.expires_in * 1000;
  while (Date.now() + interval < deadline) {
    await wait(interval);
    const poll = await devicePoll(form(input.endpoint, input.metadata.token_endpoint, { ...resource(input), client_id, grant_type: DEVICE_GRANT, device_code: device.device_code }), request);
    if (poll.kind === "timeout") { interval *= 2; continue; }
    const result = poll.result;
    if (result.status === 200) return TokensSchema.parse(result.body);
    const error = responseError(result.status, result.body);
    if (error.reason === "slow_down") interval += 5000;
    else if (error.reason !== "authorization_pending") throw error;
  }
  throw new HttpError(400, "expired_token", "Device sign-in expired. Run tartlet login again.");
}
const JwkSchema = z.object({ kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: z.string(), kid: z.string().optional() });
export async function verifyCloudToken(endpoint: Endpoint, metadata: Metadata, token: string) {
  if (!metadata.jwks_uri) throw new Error("The cloud did not publish its signing keys.");
  const { kid } = readUnverifiedJwsHeader(token);
  const jwks = await json({ endpoint, url: metadata.jwks_uri }, z.object({ keys: z.array(JwkSchema).max(32) }));
  const matching = jwks.keys.filter((key) => key.kid === kid);
  const key = matching[0];
  if (!key || matching.length !== 1) throw new Error("The cloud access token has an unknown signing key.");
  const public_key = await globalThis.crypto.subtle.importKey("jwk", key, "Ed25519", false, ["verify"]);
  await verifyCloudAccessToken({ jws: token, public_key, expected: { iss: endpoint.origin, aud: endpoint.origin } });
}
