import { z } from "zod";
import { CloudAccountIdSchema, OrganizationIdSchema, ServerIdSchema } from "./ids.js";
import { CanonicalOriginSchema } from "./origin.js";
import { DeviceCodeSchema, NonceSchema, PersonIdentitySchema, ServerPublicKeySchema, UnixTimeSchema } from "./primitives.js";

export const CLOCK_SKEW_SECONDS = 60;
const times = { iat: UnixTimeSchema, exp: UnixTimeSchema };
const oneMinute = (value: { iat: number; exp: number }) => value.exp === value.iat + 60;
const tenMinutes = (value: { iat: number; exp: number }) => value.exp > value.iat && value.exp <= value.iat + 600;
export const HelloPayloadSchema = z.strictObject({ typ: z.literal("tartlet-hello"), server_id: ServerIdSchema, nonce: NonceSchema, ...times }).refine(oneMinute, "Hello proofs last 60 seconds.");
export const EnrollmentPollPayloadSchema = z.strictObject({ typ: z.literal("tartlet-enroll-poll"), device_code: DeviceCodeSchema, ...times }).refine(oneMinute, "Enrollment poll proofs last 60 seconds.");
export const EnrollmentApprovalPayloadSchema = z.strictObject({
  typ: z.literal("tartlet-enrollment"), server_id: ServerIdSchema, org_id: OrganizationIdSchema,
  server_public_key: ServerPublicKeySchema, approver: PersonIdentitySchema.extend({ sub: CloudAccountIdSchema }), nonce: NonceSchema, ...times,
}).refine(tenMinutes, "Enrollment approvals last at most 600 seconds.");
export const ServerProofPayloadSchema = z.strictObject({
  typ: z.literal("tartlet-server-proof"), server_id: ServerIdSchema, origin: CanonicalOriginSchema, nonce: NonceSchema, ...times,
}).refine(oneMinute, "Server identity proofs last 60 seconds.");
export const IdentityTokenClaimsSchema = z.strictObject({
  typ: z.literal("tartlet-identity"), iss: PersonIdentitySchema.shape.iss, aud: ServerIdSchema, sub: CloudAccountIdSchema, nonce: NonceSchema,
  ...times, nbf: UnixTimeSchema, org: OrganizationIdSchema, email: z.email({ pattern: z.regexes.unicodeEmail }).max(254).refine((value) => !/\p{Cc}/u.test(value)), email_verified: z.boolean(),
}).refine(tenMinutes, "Identity tokens last at most 600 seconds.")
  .refine((value) => value.nbf <= value.exp, "Identity tokens cannot become valid after expiry.");
export const UnenrollPayloadSchema = z.strictObject({
  typ: z.literal("tartlet-unenroll"), server_id: ServerIdSchema, nonce: NonceSchema, ...times,
}).refine(oneMinute, "Un-enroll proofs last 60 seconds.");
export const CloudAccessTokenClaimsSchema = z.strictObject({
  typ: z.literal("tartlet-cloud-access"), iss: PersonIdentitySchema.shape.iss, aud: PersonIdentitySchema.shape.iss,
  sub: CloudAccountIdSchema, ...times, nbf: UnixTimeSchema,
}).refine(tenMinutes, "Cloud access tokens last at most 600 seconds.")
  .refine((value) => value.nbf <= value.exp, "Cloud access tokens cannot become valid after expiry.")
  .refine((value) => value.aud === value.iss, "Cloud access tokens target their cloud issuer URL.");
export const SignedPayloadSchema = z.discriminatedUnion("typ", [HelloPayloadSchema, EnrollmentPollPayloadSchema, EnrollmentApprovalPayloadSchema, ServerProofPayloadSchema, IdentityTokenClaimsSchema, UnenrollPayloadSchema, CloudAccessTokenClaimsSchema]);
export type HelloPayload = z.infer<typeof HelloPayloadSchema>;
export type EnrollmentPollPayload = z.infer<typeof EnrollmentPollPayloadSchema>;
export type EnrollmentApprovalPayload = z.infer<typeof EnrollmentApprovalPayloadSchema>;
export type ServerProofPayload = z.infer<typeof ServerProofPayloadSchema>;
export type IdentityTokenClaims = z.infer<typeof IdentityTokenClaimsSchema>;
export type UnenrollPayload = z.infer<typeof UnenrollPayloadSchema>;
export type CloudAccessTokenClaims = z.infer<typeof CloudAccessTokenClaimsSchema>;
export type SignedPayload = z.infer<typeof SignedPayloadSchema>;
