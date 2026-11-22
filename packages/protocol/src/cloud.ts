import { z } from "zod";
import { CutoffIdSchema, OrganizationIdSchema, ServerIdSchema } from "./ids.js";
import { ProtocolFailureSchema } from "./errors.js";
import { CursorSchema, DeviceCodeSchema, HostSchema, HttpsUrlSchema, NonceSchema, PersonIdentitySchema, PortSchema, ServerPublicKeySchema, UnixTimeSchema } from "./primitives.js";

export const JwsCompactSchema = z.string().max(16384).regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
export const EnrollmentAddressSchema = z.strictObject({
  kind: z.enum(["tailnet", "lan"]), host: HostSchema,
  port: PortSchema.refine((value) => value !== 443, "Omit the default HTTPS port 443.").optional(),
});
export const HttpsTrustSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("webpki") }),
  z.strictObject({ kind: z.literal("local_ca"), root_sha256: z.string().regex(/^[0-9a-f]{64}$/).describe("SHA-256 of the root certificate's DER-encoded SubjectPublicKeyInfo (SPKI), as 64 lowercase hex characters.") }),
]);
export const EnrollmentStartRequestSchema = z.strictObject({
  server_public_key: ServerPublicKeySchema, server_name: z.string().min(1).max(64).refine((value) => !/[\p{Cc}\p{Cf}]/u.test(value), "Server names cannot contain control or formatting characters."),
  addresses: z.array(EnrollmentAddressSchema).min(1).max(4), nonce: NonceSchema,
  reenroll: z.strictObject({ server_id: ServerIdSchema, org_id: OrganizationIdSchema }).optional(),
  https_trust: HttpsTrustSchema.optional(),
});
export const EnrollmentStartResponseSchema = z.strictObject({
  device_code: DeviceCodeSchema, user_code: z.string().regex(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/),
  verification_uri: HttpsUrlSchema, expires_in: z.number().int().min(1).max(600), interval: z.number().int().positive().max(600),
});
export const EnrollmentPollRequestSchema = z.strictObject({ device_code: DeviceCodeSchema, proof: JwsCompactSchema });
const pollSuccess = z.strictObject({ approval: JwsCompactSchema });
const pollPending = z.strictObject({ error: ProtocolFailureSchema.extend({ code: z.enum(["authorization_pending", "slow_down"]), action: z.literal("retry the same call") }) });
const pollTerminal = z.strictObject({ error: ProtocolFailureSchema.extend({ code: z.enum(["expired_token", "access_denied"]), action: z.literal("a person must act") }) });
export const EnrollmentPollResponseSchema = z.union([pollSuccess, pollPending, pollTerminal]);
export type ParsedEnrollmentPollResponse =
  | ({ kind: "success" } & z.infer<typeof pollSuccess>)
  | ({ kind: "pending" } & z.infer<typeof pollPending>)
  | ({ kind: "terminal" } & z.infer<typeof pollTerminal>);
export function parseEnrollmentPollResponse(input: unknown): ParsedEnrollmentPollResponse {
  const response = EnrollmentPollResponseSchema.parse(input);
  if ("approval" in response) return { kind: "success", ...response };
  const error = response.error;
  switch (error.action) {
    case "retry the same call": return { kind: "pending", error };
    case "a person must act": return { kind: "terminal", error };
    default: { const exhaustive: never = error; return exhaustive; }
  }
}
export const UnenrollChallengeRequestSchema = z.strictObject({});
export const UnenrollChallengeResponseSchema = z.strictObject({ nonce: NonceSchema, expires_in: z.number().int().min(1).max(120) });
export const UnenrollRequestSchema = z.strictObject({ proof: JwsCompactSchema });
export const UnenrollResponseSchema = z.strictObject({ unenrolled: z.literal(true) });
export const ServerListResponseSchema = z.strictObject({
  servers: z.array(z.strictObject({
    server_id: ServerIdSchema, org_id: OrganizationIdSchema, name: EnrollmentStartRequestSchema.shape.server_name,
    addresses: EnrollmentStartRequestSchema.shape.addresses.refine((addresses) => new Set(addresses.map(({ kind, host, port }) => JSON.stringify([kind, host, port]))).size === addresses.length, "Server addresses must be unique."), online: z.boolean(),
  })).max(500).refine((servers) => new Set(servers.map((server) => server.server_id)).size === servers.length, "Server IDs must be unique."),
});
export const ChallengeMessageSchema = z.strictObject({ type: z.literal("challenge"), nonce: NonceSchema, issued_at: UnixTimeSchema });
export const HelloMessageSchema = z.strictObject({ type: z.literal("hello"), server_id: ServerIdSchema, protocol_version: z.number().int().positive(), proof: JwsCompactSchema });
export const WelcomeMessageSchema = z.strictObject({ type: z.literal("welcome"), head_cursor: CursorSchema });
export const KeyRefreshMessageSchema = z.strictObject({ type: z.literal("key_refresh") });
export const CutoffMessageSchema = z.strictObject({
  type: z.literal("cutoff"), cutoff_id: CutoffIdSchema, cursor: CursorSchema, person: PersonIdentitySchema, at: UnixTimeSchema,
});
/** Acknowledge cut-offs only after saving them. Delivery is at least once, so ignore any cutoff_id you already saved. */
export const AckMessageSchema = z.strictObject({ type: z.literal("ack"), cutoff_ids: z.array(CutoffIdSchema).min(1).max(100) });
/** Finish catch-up after reconnecting before serving requests. Save the cursor only after you handle the full batch. */
export const CatchUpRequestMessageSchema = z.strictObject({ type: z.literal("catch_up_request"), after_cursor: CursorSchema.nullable() });
export const CatchUpMessageSchema = z.strictObject({
  type: z.literal("catch_up"), cutoffs: z.array(CutoffMessageSchema).max(100), next_cursor: CursorSchema, complete: z.boolean(),
  upstream_synced_at: UnixTimeSchema.describe("Time of the cloud's last complete upstream reconciliation for the organization, with no undelivered cut-offs. The server records this value as its last successful sync, never its own clock."),
});
export const CloudMessageSchema = z.discriminatedUnion("type", [ChallengeMessageSchema, HelloMessageSchema, WelcomeMessageSchema, KeyRefreshMessageSchema, CutoffMessageSchema, AckMessageSchema, CatchUpRequestMessageSchema, CatchUpMessageSchema]);
export const CloudToServerMessageSchema = z.discriminatedUnion("type", [ChallengeMessageSchema, WelcomeMessageSchema, KeyRefreshMessageSchema, CutoffMessageSchema, CatchUpMessageSchema]);
export const ServerToCloudMessageSchema = z.discriminatedUnion("type", [HelloMessageSchema, AckMessageSchema, CatchUpRequestMessageSchema]);
export type EnrollmentAddress = z.infer<typeof EnrollmentAddressSchema>;
export type HttpsTrust = z.infer<typeof HttpsTrustSchema>;
export type EnrollmentStartRequest = z.infer<typeof EnrollmentStartRequestSchema>;
export type EnrollmentStartResponse = z.infer<typeof EnrollmentStartResponseSchema>;
export type EnrollmentPollRequest = z.infer<typeof EnrollmentPollRequestSchema>;
export type EnrollmentPollResponse = z.infer<typeof EnrollmentPollResponseSchema>;
export type UnenrollChallengeRequest = z.infer<typeof UnenrollChallengeRequestSchema>;
export type UnenrollChallengeResponse = z.infer<typeof UnenrollChallengeResponseSchema>;
export type UnenrollRequest = z.infer<typeof UnenrollRequestSchema>;
export type UnenrollResponse = z.infer<typeof UnenrollResponseSchema>;
export type ServerListResponse = z.infer<typeof ServerListResponseSchema>;
export type ChallengeMessage = z.infer<typeof ChallengeMessageSchema>;
export type HelloMessage = z.infer<typeof HelloMessageSchema>;
export type WelcomeMessage = z.infer<typeof WelcomeMessageSchema>;
export type KeyRefreshMessage = z.infer<typeof KeyRefreshMessageSchema>;
export type CutoffMessage = z.infer<typeof CutoffMessageSchema>;
export type AckMessage = z.infer<typeof AckMessageSchema>;
export type CatchUpRequestMessage = z.infer<typeof CatchUpRequestMessageSchema>;
export type CatchUpMessage = z.infer<typeof CatchUpMessageSchema>;
export type CloudMessage = z.infer<typeof CloudMessageSchema>;
export type CloudToServerMessage = z.infer<typeof CloudToServerMessageSchema>;
export type ServerToCloudMessage = z.infer<typeof ServerToCloudMessageSchema>;
