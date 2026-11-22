import { z } from "zod";
import { ClientRequestIdSchema, JobIdSchema, VmNameSchema } from "./ids.js";
import { ProtocolFailureSchema } from "./errors.js";
import { TimestampSchema } from "./primitives.js";

export const DEFAULT_COMMAND_TIMEOUT_SECONDS = 1800;
export const MAX_COMMAND_TIMEOUT_SECONDS = 7200;
export const DEFAULT_OUTPUT_PAGE_BYTES = 16384;
export const MAX_OUTPUT_PAGE_BYTES = 65536;
export const MAX_RETAINED_STREAM_BYTES = 4 * 1024 * 1024;
const ByteOffsetSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const paging = {
  stdout_offset: ByteOffsetSchema.default(0),
  stderr_offset: ByteOffsetSchema.default(0),
  max_bytes: z.number().int().min(1).max(MAX_OUTPUT_PAGE_BYTES).default(DEFAULT_OUTPUT_PAGE_BYTES),
};

export const OutputPageSchema = z.strictObject({
  text: z.string().refine((value) => !/[\uD800-\uDFFF]/u.test(value), "Output text cannot contain unpaired surrogates."), offset: ByteOffsetSchema, next_offset: ByteOffsetSchema, total_bytes: ByteOffsetSchema, dropped_before: ByteOffsetSchema,
}).refine((page) => page.dropped_before <= page.offset && page.offset <= page.next_offset && page.next_offset <= page.total_bytes, "Output byte offsets are out of order.")
  .refine((page) => page.total_bytes - page.dropped_before <= MAX_RETAINED_STREAM_BYTES, "Output exceeds retention.")
  .refine((page) => page.next_offset - page.offset <= MAX_OUTPUT_PAGE_BYTES, "Output page exceeds the maximum byte count.")
  .refine((page) => page.text.length <= page.next_offset - page.offset, "Output text cannot exceed the raw bytes consumed.")
  .describe("Offsets and counts are raw-stream bytes. Decode UTF-8 with replacement, ending before any split character. Read from max(requested_offset, dropped_before); retain at most the last 4 MiB. dropped_before is the sole truncation indicator.");

const job = { job_id: JobIdSchema, vm: VmNameSchema, started_at: TimestampSchema };
const finished = { ...job, finished_at: TimestampSchema };
export const CommandStatusSchema = z.discriminatedUnion("status", [
  z.strictObject({ status: z.literal("running"), ...job }),
  z.strictObject({ status: z.literal("exited"), ...finished, exit_code: z.number().int().min(0).max(255) }),
  z.strictObject({ status: z.literal("canceled"), ...finished }),
  z.strictObject({ status: z.literal("timed_out"), ...finished }),
  z.strictObject({ status: z.literal("lost"), ...finished }),
  z.strictObject({ status: z.literal("failed_to_start"), ...finished, error: ProtocolFailureSchema }),
]).refine((value) => value.status === "running" || Date.parse(value.finished_at) >= Date.parse(value.started_at), "A command cannot finish before it starts.");

export const RunCommandRequestSchema = z.strictObject({
  client_request_id: ClientRequestIdSchema, vm: VmNameSchema,
  command: z.string().min(1).describe("Command text is sent to the guest through stdin; never interpolate it into a shell command."),
  timeout_seconds: z.number().int().min(1).max(MAX_COMMAND_TIMEOUT_SECONDS).default(DEFAULT_COMMAND_TIMEOUT_SECONDS),
});
export const GetCommandRequestSchema = z.strictObject({ job_id: JobIdSchema, vm: VmNameSchema, ...paging });
export const CancelCommandRequestSchema = z.strictObject({ job_id: JobIdSchema, vm: VmNameSchema });
export const RunCommandResponseSchema = CommandStatusSchema;
export const GetCommandResponseSchema = z.strictObject({ job: CommandStatusSchema, stdout: OutputPageSchema, stderr: OutputPageSchema });
export const CancelCommandResponseSchema = CommandStatusSchema;
export type OutputPage = z.infer<typeof OutputPageSchema>;
export type CommandStatus = z.infer<typeof CommandStatusSchema>;
export type RunCommandRequest = z.infer<typeof RunCommandRequestSchema>;
export type RunCommandResponse = z.infer<typeof RunCommandResponseSchema>;
export type GetCommandRequest = z.infer<typeof GetCommandRequestSchema>;
export type GetCommandResponse = z.infer<typeof GetCommandResponseSchema>;
export type CancelCommandRequest = z.infer<typeof CancelCommandRequestSchema>;
export type CancelCommandResponse = z.infer<typeof CancelCommandResponseSchema>;
