import { z } from "zod";
import { CLOCK_SKEW_SECONDS, EnrollmentApprovalPayloadSchema, EnrollmentPollPayloadSchema, HelloPayloadSchema, IdentityTokenClaimsSchema, ServerProofPayloadSchema } from "./artifacts.js";
import type { EnrollmentApprovalPayload, EnrollmentPollPayload, HelloPayload, IdentityTokenClaims, ServerProofPayload } from "./artifacts.js";
import { readUnverifiedJwsHeader } from "./jws.js";
import { decodeBase64Url } from "./encoding.js";
import { UnixTimeSchema } from "./primitives.js";

const ClockClaimsSchema = z.looseObject({ iat: UnixTimeSchema, exp: UnixTimeSchema, nbf: UnixTimeSchema.optional() });
const RecordSchema = z.record(z.string(), z.unknown());

function decodeJson(value: string): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(value)));
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
  if (!value.success || Object.keys(record.data).length === 0) return false;
  return Object.entries(record.data).every(([key, field]) => Object.hasOwn(value.data, key) && matchesExpected(value.data[key], field));
}

type ExpectedFields<T> = { [K in keyof T]?: T[K] extends object ? ExpectedFields<T[K]> : T[K] };

interface VerifyJwsOptions<T> {
  jws: string;
  public_key: CryptoKey;
  schema: z.ZodType<T>;
  expected: ExpectedFields<T>;
  now?: number;
}

async function verifyJws<T>(options: VerifyJwsOptions<T>): Promise<T> {
  if (options.public_key.type !== "public" || options.public_key.algorithm.name !== "Ed25519") throw new Error("A trusted Ed25519 public key is required.");
  readUnverifiedJwsHeader(options.jws);
  const [header = "", body = "", signature = ""] = options.jws.split(".");
  const valid = await globalThis.crypto.subtle.verify("Ed25519", options.public_key, decodeBase64Url(signature), new TextEncoder().encode(`${header}.${body}`));
  if (!valid) throw new Error("Invalid JWS signature.");
  const raw = decodeJson(body);
  checkTime(raw, options.now ?? Math.floor(Date.now() / 1000));
  const payload = options.schema.parse(raw);
  if (!matchesExpected(payload, options.expected)) throw new Error("JWS does not match the expected fields.");
  return payload;
}

const expectedHello = z.strictObject({ server_id: HelloPayloadSchema.shape.server_id, nonce: HelloPayloadSchema.shape.nonce });
const expectedPoll = z.strictObject({ device_code: EnrollmentPollPayloadSchema.shape.device_code });
const approvalContext = {
  server_public_key: EnrollmentApprovalPayloadSchema.shape.server_public_key, nonce: EnrollmentApprovalPayloadSchema.shape.nonce,
  approver_iss: EnrollmentApprovalPayloadSchema.shape.approver.shape.iss,
};
const expectedApproval = z.discriminatedUnion("mode", [
  z.strictObject({ mode: z.literal("initial"), ...approvalContext }),
  z.strictObject({ mode: z.literal("reenroll"), ...approvalContext, server_id: EnrollmentApprovalPayloadSchema.shape.server_id, org_id: EnrollmentApprovalPayloadSchema.shape.org_id }),
]);
const expectedProof = z.strictObject({ server_id: ServerProofPayloadSchema.shape.server_id, origin: ServerProofPayloadSchema.shape.origin, nonce: ServerProofPayloadSchema.shape.nonce });
const expectedIdentity = z.strictObject({ iss: IdentityTokenClaimsSchema.shape.iss, aud: IdentityTokenClaimsSchema.shape.aud, nonce: IdentityTokenClaimsSchema.shape.nonce, org: IdentityTokenClaimsSchema.shape.org });

interface Verification<E> { jws: string; public_key: CryptoKey; expected: E; now?: number }
export type ExpectedHello = Pick<HelloPayload, "server_id" | "nonce">;
export type ExpectedEnrollmentPoll = Pick<EnrollmentPollPayload, "device_code">;
export type ExpectedEnrollmentApproval = z.infer<typeof expectedApproval>;
export type ExpectedServerProof = Pick<ServerProofPayload, "server_id" | "origin" | "nonce">;
export type ExpectedIdentityToken = Pick<IdentityTokenClaims, "iss" | "aud" | "nonce" | "org">;
export function verifyHello(options: Verification<ExpectedHello>): Promise<HelloPayload> {
  return verifyJws({ ...options, schema: HelloPayloadSchema, expected: expectedHello.parse(options.expected) });
}
export function verifyEnrollmentPoll(options: Verification<ExpectedEnrollmentPoll>): Promise<EnrollmentPollPayload> {
  return verifyJws({ ...options, schema: EnrollmentPollPayloadSchema, expected: expectedPoll.parse(options.expected) });
}
export function verifyEnrollmentApproval(options: Verification<ExpectedEnrollmentApproval>): Promise<EnrollmentApprovalPayload> {
  const context = expectedApproval.parse(options.expected);
  const expected = { server_public_key: context.server_public_key, nonce: context.nonce, approver: { iss: context.approver_iss } };
  switch (context.mode) {
    case "initial": return verifyJws({ ...options, schema: EnrollmentApprovalPayloadSchema, expected });
    case "reenroll": return verifyJws({ ...options, schema: EnrollmentApprovalPayloadSchema, expected: { ...expected, server_id: context.server_id, org_id: context.org_id } });
    default: { const exhaustive: never = context; return exhaustive; }
  }
}
/** Verify before sending credentials, using the saved profile key and origin; cloud metadata cannot replace pins. */
export function verifyServerProof(options: Verification<ExpectedServerProof>): Promise<ServerProofPayload> {
  return verifyJws({ ...options, schema: ServerProofPayloadSchema, expected: expectedProof.parse(options.expected) });
}
export function verifyIdentityToken(options: Verification<ExpectedIdentityToken>): Promise<IdentityTokenClaims> {
  return verifyJws({ ...options, schema: IdentityTokenClaimsSchema, expected: expectedIdentity.parse(options.expected) });
}
