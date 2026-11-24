import { z } from "zod";
import { AuthorizeSshKeyRequestSchema, AuthorizeSshKeyResponseSchema, VmNameSchema, TaskLabelSchema, ErrorResponseSchema } from "@tartlet/protocol";
import { json } from "./http.js";
import { responseError } from "./errors.js";
import { connectedProfile } from "./profiles.js";
import { selectedKey } from "./keys.js";
import type { Profile } from "./storage.js";

const RpcSchema = z.object({ jsonrpc: z.literal("2.0"), id: z.number(), result: z.unknown().optional(), error: z.object({ code: z.number(), message: z.string() }).optional() });
async function rpc(profile: Profile, id: number, method: string, params: unknown): Promise<unknown> {
  const response = await json({ endpoint: profile, url: `${profile.origin}/mcp`, method: "POST", headers: {
    Authorization: `Bearer ${profile.tokens.access_token}`, Accept: "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": "2025-03-26",
  }, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) }, RpcSchema);
  if (response.id !== id) throw new Error("The server returned an unexpected response ID.");
  if (response.error) throw new Error("The server could not resolve the VM. Check your access and the CLI version.");
  return response.result;
}
const VmListSchema = z.object({ structuredContent: z.object({ vms: z.array(z.object({ name: VmNameSchema, label: TaskLabelSchema.optional() })) }) });
export async function resolveVm(profile: Profile, value: string, labelOnly = false) {
  const name = VmNameSchema.parse(value);
  await rpc(profile, 1, "initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "tartlet-cli", version: "0.2.0" } });
  const result = await rpc(profile, 2, "tools/call", { name: "list_my_vms", arguments: {} });
  const failure = z.object({ structuredContent: ErrorResponseSchema }).safeParse(result);
  if (failure.success) throw responseError(409, failure.data.structuredContent);
  const list = VmListSchema.safeParse(result);
  if (!list.success) throw new Error("The server returned an invalid VM list. Check that the CLI version matches the server.");
  const matches = list.data.structuredContent.vms.filter((vm) => labelOnly ? vm.label === value : vm.name === name || vm.label === value);
  const selected = matches[0];
  if (!selected) throw new Error("No VM with that name or label belongs to this account.");
  if (matches.length !== 1) throw new Error("The name matches more than one VM. Use --label to select by label.");
  return selected.name;
}
export async function authorize(directory: string, target: string, options: { profile?: string; label: boolean }) {
  const profile = await connectedProfile(directory, options.profile), key = await selectedKey(directory);
  const vm = await resolveVm(profile, target, options.label);
  const request = AuthorizeSshKeyRequestSchema.parse({ vm, public_key: key.public_key });
  const connection = await json({ endpoint: profile, url: `${profile.origin}/api/agent/authorize-ssh-key`, method: "POST", headers: {
    Authorization: `Bearer ${profile.tokens.access_token}`, "Content-Type": "application/json",
  }, body: JSON.stringify(request) }, AuthorizeSshKeyResponseSchema);
  return { profile, key, vm, connection };
}
export type Access = Awaited<ReturnType<typeof authorize>>;
