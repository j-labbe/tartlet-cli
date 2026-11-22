import { z } from "zod";

export const ErrorActionSchema = z.enum(["retry the same call", "change your input", "a person must act"]);
export const ProtocolFailureSchema = z.strictObject({ code: z.string().min(1).max(64), action: ErrorActionSchema, message: z.string().min(1).max(1024) });
export const ErrorResponseSchema = z.strictObject({ error: ProtocolFailureSchema });
export type ErrorAction = z.infer<typeof ErrorActionSchema>;
export type ProtocolFailure = z.infer<typeof ProtocolFailureSchema>;
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
