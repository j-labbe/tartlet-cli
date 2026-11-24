import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import ssh2, { type BaseAgent as SshAgent, type ParsedKey, type PublicKeyEntry, type SignCallback, type IdentityCallback, type SigningRequestOptions, type ConnectConfig } from "ssh2";
import { PublicKeySchema } from "@tartlet/protocol";
import { changeState, privateWrite, readUtf8, type KeyChoice } from "./storage.js";
import type { LoginIO } from "./profiles.js";
import { generatePair } from "./keypair.js";
const { BaseAgent, createAgent, utils } = ssh2;

function agent() {
  const socket = process.env.SSH_AUTH_SOCK ?? (process.platform === "win32" ? "\\\\.\\pipe\\openssh-ssh-agent" : undefined);
  if (!socket) throw new Error("No SSH agent is available. Start an agent, or run tartlet link --file <key.pub>.");
  return createAgent(socket);
}
export function identities(source = agent()): Promise<ParsedKey[]> {
  return new Promise((resolve, reject) => source.getIdentities((error, keys) => {
    if (error) reject(new Error("Cannot read keys from the SSH agent."));
    else resolve((keys ?? []).flatMap(agentPublicKey));
  }));
}
function agentPublicKey(value: string | Buffer | ParsedKey | PublicKeyEntry): ParsedKey[] {
  if (typeof value !== "string" && !Buffer.isBuffer(value) && "pubKey" in value) {
    return agentPublicKey("pubKey" in value.pubKey ? value.pubKey.pubKey : value.pubKey);
  }
  const key = utils.parseKey(value);
  if (key instanceof Error || !PublicKeySchema.safeParse(`${key.type} ${key.getPublicSSH().toString("base64")}`).success) return [];
  return [key];
}
export const publicLine = (key: ParsedKey) => PublicKeySchema.parse(`${key.type} ${key.getPublicSSH().toString("base64")}`);
export function fingerprint(publicKey: string): string {
  return `SHA256:${createHash("sha256").update(Buffer.from(publicKey.split(" ")[1] ?? "", "base64")).digest("base64").replace(/=+$/, "")}`;
}
class ChosenAgent extends BaseAgent {
  constructor(private readonly source: SshAgent, private readonly publicKey: string) { super(); }
  getIdentities(callback: IdentityCallback<ParsedKey>) {
    void identities(this.source).then((keys) => callback(null, keys.filter((key) => publicLine(key) === this.publicKey)), (error: Error) => callback(error));
  }
  sign(key: string | Buffer | ParsedKey, data: Buffer, options: SigningRequestOptions | SignCallback, callback?: SignCallback) {
    if (typeof options === "function") this.source.sign(key, data, options);
    else this.source.sign(key, data, options, callback);
  }
}
export async function generateChoice(directory: string): Promise<KeyChoice> {
  const pair = generatePair(), private_path = path.join(directory, `id_ed25519_${randomUUID()}`), public_path = `${private_path}.pub`;
  await privateWrite(private_path, `${pair.private.trim()}\n`);
  await privateWrite(public_path, `${pair.public.trim()}\n`);
  return { kind: "file", private_path, public_path, public_key: PublicKeySchema.parse(pair.public.trim()) };
}
export interface LinkOptions { file?: string; identity?: string; generate: boolean; agentKey?: string; io: LoginIO }
async function fileChoice(file: string, identity?: string): Promise<KeyChoice> {
  const public_path = path.resolve(file), private_path = identity ? path.resolve(identity) : public_path.replace(/\.pub$/, "");
  if (private_path === public_path) throw new Error("Use a .pub file, or pass --identity <private-key> separately.");
  return { kind: "file", public_path, private_path, public_key: PublicKeySchema.parse((await readUtf8(public_path)).trim()) };
}
async function agentChoice(key: string, io: LoginIO): Promise<KeyChoice> {
  const keys = (await identities()).map(publicLine);
  if (!keys.length) throw new Error("The SSH agent has no supported keys.");
  const chosen = key === "choose" ? keys[await io.choose("Choose an SSH agent key", keys.map(fingerprint))] : keys.find((entry) => fingerprint(entry) === key);
  if (!chosen) throw new Error("The chosen key is not available in the SSH agent. Use its SHA256 fingerprint.");
  return { kind: "agent", public_key: chosen };
}
export async function link(directory: string, options: LinkOptions) {
  let choice: KeyChoice;
  if (options.generate) choice = await changeState(directory, async (state) => {
    if (state.key) throw new Error("A key is already selected. Run tartlet unlink before generating another key.");
    const next = await generateChoice(directory); state.key = next; return next;
  });
  else {
    choice = options.file ? await fileChoice(options.file, options.identity) : await agentChoice(options.agentKey ?? "choose", options.io);
    await changeState(directory, async (state) => { state.key = choice; });
  }
  options.io.say(`Selected ${fingerprint(choice.public_key)}. This key will be authorized on each connection.`);
}
export async function selectedKey(directory: string): Promise<KeyChoice> {
  return changeState(directory, async (state) => {
    if (!state.key) state.key = await generateChoice(directory);
    return state.key;
  });
}
export async function authentication(choice: KeyChoice): Promise<Pick<ConnectConfig, "agent" | "privateKey" | "passphrase">> {
  if (choice.kind === "agent") return { agent: new ChosenAgent(agent(), choice.public_key) };
  const privateKey = await readUtf8(choice.private_path), parsed = utils.parseKey(privateKey);
  if (parsed instanceof Error) throw new Error("Cannot open the private key. For an encrypted key, load it into your SSH agent and use tartlet link --agent.");
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!key || publicLine(key) !== choice.public_key) throw new Error("The selected public and private SSH keys do not match. Run tartlet link again.");
  return { privateKey };
}
