import { z } from "zod";
import { CutoffIdSchema, ServerIdSchema } from "./ids.js";
import { CursorSchema, DeviceCodeSchema, HostSchema, HttpsUrlSchema, NonceSchema, PersonIdentitySchema, ServerPublicKeySchema, UnixTimeSchema } from "./primitives.js";

export const JwsCompactSchema = z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
export const EnrollmentAddressSchema = z.strictObject({ kind: z.enum(["tailnet", "lan"]), host: HostSchema });
export const EnrollmentStartRequestSchema = z.strictObject({
  server_public_key: ServerPublicKeySchema, server_name: z.string().min(1).max(64),
  addresses: z.array(EnrollmentAddressSchema).min(1).max(4), nonce: NonceSchema,
});
export const EnrollmentStartResponseSchema = z.strictObject({
  device_code: DeviceCodeSchema, user_code: z.string().regex(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/),
  verification_uri: HttpsUrlSchema, expires_in: z.number().int().min(1).max(600), interval: z.number().int().positive(),
});
export const EnrollmentPollRequestSchema = z.strictObject({ device_code: DeviceCodeSchema, proof: JwsCompactSchema });
export const ChallengeMessageSchema = z.strictObject({ type: z.literal("challenge"), nonce: NonceSchema, issued_at: UnixTimeSchema });
export const HelloMessageSchema = z.strictObject({ type: z.literal("hello"), server_id: ServerIdSchema, protocol_version: z.number().int().positive(), proof: JwsCompactSchema });
export const WelcomeMessageSchema = z.strictObject({ type: z.literal("welcome"), head_cursor: CursorSchema });
export const KeyRefreshMessageSchema = z.strictObject({ type: z.literal("key_refresh") });
export const CutoffMessageSchema = z.strictObject({
  type: z.literal("cutoff"), cutoff_id: CutoffIdSchema, cursor: CursorSchema, person: PersonIdentitySchema, at: UnixTimeSchema,
});
/** Acknowledge only after persisting cut-offs; delivery is at least once and deduplication uses cutoff_id. */
export const AckMessageSchema = z.strictObject({ type: z.literal("ack"), cutoff_ids: z.array(CutoffIdSchema).min(1).max(100) });
/** Reconnect catch-up must finish before serving requests; persist the last fully processed cursor. */
export const CatchUpRequestMessageSchema = z.strictObject({ type: z.literal("catch_up_request"), after_cursor: CursorSchema.nullable() });
export const CatchUpMessageSchema = z.strictObject({ type: z.literal("catch_up"), cutoffs: z.array(CutoffMessageSchema).max(100), next_cursor: CursorSchema, complete: z.boolean() });
export const CloudMessageSchema = z.discriminatedUnion("type", [ChallengeMessageSchema, HelloMessageSchema, WelcomeMessageSchema, KeyRefreshMessageSchema, CutoffMessageSchema, AckMessageSchema, CatchUpRequestMessageSchema, CatchUpMessageSchema]);
export const CloudToServerMessageSchema = z.discriminatedUnion("type", [ChallengeMessageSchema, WelcomeMessageSchema, KeyRefreshMessageSchema, CutoffMessageSchema, CatchUpMessageSchema]);
export const ServerToCloudMessageSchema = z.discriminatedUnion("type", [HelloMessageSchema, AckMessageSchema, CatchUpRequestMessageSchema]);
export type EnrollmentAddress = z.infer<typeof EnrollmentAddressSchema>;
export type EnrollmentStartRequest = z.infer<typeof EnrollmentStartRequestSchema>;
export type EnrollmentStartResponse = z.infer<typeof EnrollmentStartResponseSchema>;
export type EnrollmentPollRequest = z.infer<typeof EnrollmentPollRequestSchema>;
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
