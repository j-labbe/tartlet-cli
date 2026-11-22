import { z } from "zod";

export const ErrorActionSchema = z.enum(["retry the same call", "change your input", "a person must act"]);
export const ProtocolFailureSchema = z.strictObject({ code: z.string(), action: ErrorActionSchema, message: z.string() });
export const ErrorResponseSchema = z.strictObject({ error: ProtocolFailureSchema });
export type ErrorAction = z.infer<typeof ErrorActionSchema>;
export type ProtocolFailure = z.infer<typeof ProtocolFailureSchema>;
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
