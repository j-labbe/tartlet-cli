import { z } from "zod";
import { ProtocolFailureSchema } from "./errors.js";
import { TaskLabelSchema, VmNameSchema, WorkerNameSchema } from "./ids.js";
import { NonceSchema, HostSchema, HostKeyAliasSchema, SshUserSchema, PortSchema, TimestampSchema } from "./primitives.js";
import { JwsCompactSchema } from "./cloud.js";
import { PublicKeySchema, parsePublicKey } from "./ssh-keys.js";

export const VmTargetSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("name"), name: VmNameSchema }),
  z.strictObject({ kind: z.literal("label"), label: TaskLabelSchema }),
]);
export const SetupSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("tartlet") }),
  z.strictObject({ kind: z.literal("none"), reason: z.string() }),
]);

export const KnownHostsLineSchema = z.string().refine((value) => {
  if (/\p{Cc}/u.test(value)) return false;
  const [alias, ...parts] = value.split(" ");
  if (!HostKeyAliasSchema.safeParse(alias).success) return false;
  try { return parsePublicKey(parts.join(" ")).public_key === parts.join(" "); } catch { return false; }
}, "Expected a host alias and a pinned SSH public key, with no options or comments.");
const connection = {
  host: HostSchema, port: PortSchema, user: SshUserSchema,
  host_key_alias: HostKeyAliasSchema, known_hosts_line: KnownHostsLineSchema,
};
const DisplayOnlyTextSchema = z.string().describe("Display-only text. The CLI builds SSH arguments from typed fields only.");
const matchingAlias = (value: { host_key_alias: string; known_hosts_line: string }) => value.known_hosts_line.startsWith(`${value.host_key_alias} `);
export const SshConnectionSchema = z.strictObject({ ...connection, ssh_options: DisplayOnlyTextSchema, command: DisplayOnlyTextSchema }).refine(matchingAlias, "Pinned host key alias does not match.");
const progress = { completed_bytes: z.string().regex(/^\d+$/), total_bytes: z.string().regex(/^\d+$/), percent: z.number().min(0).max(100), seconds_left: z.number().min(0).optional(), message: z.string() };
export const VmHomeSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("none") }),
  z.strictObject({ kind: z.literal("host"), host: WorkerNameSchema, path: z.string(), mount_name: z.string().min(1).max(255) }),
  z.strictObject({ kind: z.literal("nas"), path: z.string(), mount_name: z.string().min(1).max(255) }),
  z.strictObject({
    kind: z.literal("volume"), health: z.enum(["healthy", "degraded", "unavailable", "unknown"]), mode: z.enum(["memory", "durable"]),
    copy_count: z.number().int().min(0), reason: z.string().optional(), safety: z.string(),
    copies: z.array(z.strictObject({ host: WorkerNameSchema, replica: z.string().min(1).max(128).optional(), role: z.enum(["primary", "copy", "filling", "stale"]) })),
    progress: z.discriminatedUnion("phase", [
      z.strictObject({ phase: z.literal("filling"), ...progress }),
      z.strictObject({ phase: z.literal("recovering"), ...progress, completed_bytes: progress.completed_bytes.optional(), total_bytes: progress.total_bytes.optional(), percent: progress.percent.optional() }),
    ]).optional(),
    possible_loss: z.strictObject({ after: TimestampSchema.optional(), at: TimestampSchema }).optional(),
  }),
]);
export const VmConnectionSchema = z.strictObject({ name: z.string(), guest_port: PortSchema, connection: z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("pending") }),
  z.strictObject({ kind: z.literal("unsupported") }),
  z.strictObject({ kind: z.literal("ssh"), command: DisplayOnlyTextSchema }),
  z.strictObject({ kind: z.literal("screen-sharing"), url: z.url({ protocol: /^vnc$/ }) }),
  z.strictObject({ kind: z.literal("port"), address: DisplayOnlyTextSchema }),
]) });
export const VmSchema = z.strictObject({
  name: VmNameSchema, label: TaskLabelSchema.optional(), status: z.enum(["starting", "running", "failed", "unknown"]),
  detail: z.string().optional(), host: WorkerNameSchema.optional(), image: z.string(), image_id: z.string().min(1).max(128).optional(), image_label: z.string().optional(),
  size: z.strictObject({ cpu: z.number().int().positive().optional(), memory_mib: z.number().int().positive().optional(), disk_gib: z.number().int().positive().optional() }),
  login: SshUserSchema.optional(), network: z.enum(["shared", "isolated", "bridged"]), persistent_home: z.boolean(), home: VmHomeSchema,
  guest_home_path: z.string().optional(), connect: z.array(VmConnectionSchema), created_at: TimestampSchema.optional(),
  ready: z.boolean(), setup: SetupSchema, ssh_keys_installed: z.boolean(), reason: z.string(), warnings: z.array(z.string()),
  ssh: SshConnectionSchema.optional(), error: ProtocolFailureSchema.optional(),
});
export const ListMyVmsRequestSchema = z.strictObject({});
export const ListMyVmsResponseSchema = z.strictObject({ vms: z.array(VmSchema) });
export const ServerProofRequestSchema = z.strictObject({ nonce: NonceSchema });
export const ServerProofResponseSchema = JwsCompactSchema;
export const AuthorizeSshKeyRequestSchema = z.strictObject({ vm: VmNameSchema, public_key: PublicKeySchema, lifetime_minutes: z.number().int().min(1).max(60).default(10) });
export const AuthorizeSshKeyResponseSchema = z.strictObject({ expires_at: TimestampSchema, ...connection }).refine(matchingAlias, "Pinned host key alias does not match.");
export const LinkRequestSchema = z.strictObject({ vm: VmTargetSchema, public_key: PublicKeySchema });
export const LinkResponseSchema = z.strictObject({ vm: VmNameSchema, public_key: PublicKeySchema, linked: z.literal(true) });
export const UnlinkRequestSchema = LinkRequestSchema;
export const UnlinkResponseSchema = z.strictObject({ vm: VmNameSchema, public_key: PublicKeySchema, linked: z.literal(false) });
export const TunnelOpenRequestSchema = z.strictObject({ vm: VmTargetSchema }).describe("Open a direct HTTPS WebSocket tunnel to port 22 on the current instance of a VM the caller owns. Send the bearer token only in the Authorization header, never in a cookie or query string.");
export type VmTarget = z.infer<typeof VmTargetSchema>;
export type Setup = z.infer<typeof SetupSchema>;
export type SshConnection = z.infer<typeof SshConnectionSchema>;
export type VmHome = z.infer<typeof VmHomeSchema>;
export type VmConnection = z.infer<typeof VmConnectionSchema>;
export type Vm = z.infer<typeof VmSchema>;
export type ListMyVmsRequest = z.infer<typeof ListMyVmsRequestSchema>;
export type ListMyVmsResponse = z.infer<typeof ListMyVmsResponseSchema>;
export type ServerProofRequest = z.infer<typeof ServerProofRequestSchema>;
export type ServerProofResponse = z.infer<typeof ServerProofResponseSchema>;
export type AuthorizeSshKeyRequest = z.infer<typeof AuthorizeSshKeyRequestSchema>;
export type AuthorizeSshKeyResponse = z.infer<typeof AuthorizeSshKeyResponseSchema>;
export type LinkRequest = z.infer<typeof LinkRequestSchema>;
export type LinkResponse = z.infer<typeof LinkResponseSchema>;
export type UnlinkRequest = z.infer<typeof UnlinkRequestSchema>;
export type UnlinkResponse = z.infer<typeof UnlinkResponseSchema>;
export type TunnelOpenRequest = z.infer<typeof TunnelOpenRequestSchema>;
