import { z } from "zod";
import type { ErrorResponse } from "./errors.js";

export const PROTOCOL_VERSION = 1;
export const CliVersionSchema = z.string().regex(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/);
export const VersionResponseSchema = z.strictObject({ protocol_version: z.number().int().positive(), cli_version: CliVersionSchema });
export type VersionResponse = z.infer<typeof VersionResponseSchema>;

export function isCompatible(protocolVersion: number): boolean { return protocolVersion === PROTOCOL_VERSION; }

export function checkCompatibility(server: VersionResponse): ErrorResponse | undefined {
  const version = VersionResponseSchema.parse(server);
  if (isCompatible(version.protocol_version)) return undefined;
  return { error: { code: "incompatible_protocol", action: "change your input", message: `Run npx @tartlet/cli@${version.cli_version}.` } };
}
