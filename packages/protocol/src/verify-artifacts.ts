import { z } from "zod";
import { EnrollmentApprovalPayloadSchema, EnrollmentPollPayloadSchema, HelloPayloadSchema, IdentityTokenClaimsSchema, ServerProofPayloadSchema } from "./artifacts.js";
import type { EnrollmentApprovalPayload, EnrollmentPollPayload, HelloPayload, IdentityTokenClaims, ServerProofPayload } from "./artifacts.js";
import { verifyJws } from "./jws.js";

const expectedHello = z.strictObject({ server_id: HelloPayloadSchema.shape.server_id, nonce: HelloPayloadSchema.shape.nonce });
const expectedPoll = z.strictObject({ device_code: EnrollmentPollPayloadSchema.shape.device_code });
const expectedApproval = z.strictObject({
  server_id: EnrollmentApprovalPayloadSchema.shape.server_id, org_id: EnrollmentApprovalPayloadSchema.shape.org_id,
  server_public_key: EnrollmentApprovalPayloadSchema.shape.server_public_key, approver: EnrollmentApprovalPayloadSchema.shape.approver,
  nonce: EnrollmentApprovalPayloadSchema.shape.nonce,
});
const expectedProof = z.strictObject({ server_id: ServerProofPayloadSchema.shape.server_id, origin: ServerProofPayloadSchema.shape.origin, nonce: ServerProofPayloadSchema.shape.nonce });
const expectedIdentity = z.strictObject({ iss: IdentityTokenClaimsSchema.shape.iss, aud: IdentityTokenClaimsSchema.shape.aud, nonce: IdentityTokenClaimsSchema.shape.nonce, org: IdentityTokenClaimsSchema.shape.org });

interface Verification<E> { jws: string; public_key: CryptoKey; expected: E; now?: number }
export type ExpectedHello = Pick<HelloPayload, "server_id" | "nonce">;
export type ExpectedEnrollmentPoll = Pick<EnrollmentPollPayload, "device_code">;
export type ExpectedEnrollmentApproval = Pick<EnrollmentApprovalPayload, "server_id" | "org_id" | "server_public_key" | "approver" | "nonce">;
export type ExpectedServerProof = Pick<ServerProofPayload, "server_id" | "origin" | "nonce">;
export type ExpectedIdentityToken = Pick<IdentityTokenClaims, "iss" | "aud" | "nonce" | "org">;
export function verifyHello(options: Verification<ExpectedHello>): Promise<HelloPayload> {
  return verifyJws({ ...options, schema: HelloPayloadSchema, expected: expectedHello.parse(options.expected) });
}
export function verifyEnrollmentPoll(options: Verification<ExpectedEnrollmentPoll>): Promise<EnrollmentPollPayload> {
  return verifyJws({ ...options, schema: EnrollmentPollPayloadSchema, expected: expectedPoll.parse(options.expected) });
}
export function verifyEnrollmentApproval(options: Verification<ExpectedEnrollmentApproval>): Promise<EnrollmentApprovalPayload> {
  return verifyJws({ ...options, schema: EnrollmentApprovalPayloadSchema, expected: expectedApproval.parse(options.expected) });
}
/** Verify before sending credentials, using the saved profile key and origin; cloud metadata cannot replace pins. */
export function verifyServerProof(options: Verification<ExpectedServerProof>): Promise<ServerProofPayload> {
  return verifyJws({ ...options, schema: ServerProofPayloadSchema, expected: expectedProof.parse(options.expected) });
}
export function verifyIdentityToken(options: Verification<ExpectedIdentityToken>): Promise<IdentityTokenClaims> {
  return verifyJws({ ...options, schema: IdentityTokenClaimsSchema, expected: expectedIdentity.parse(options.expected) });
}
