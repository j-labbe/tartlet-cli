import { chmod, lstat, mkdir, readFile, readdir, rename, rm, rmdir, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { homedir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";
import { z } from "zod";
import { CanonicalOriginSchema, HttpsTrustSchema, PublicKeySchema, ServerIdSchema } from "@tartlet/protocol";
import { keepSecret } from "./errors.js";

export const TrustSchema = z.discriminatedUnion("kind", [
  HttpsTrustSchema.options[0],
  HttpsTrustSchema.options[1].extend({ root_pem: z.string().max(32768) }),
]);
export const TokensSchema = z.object({
  access_token: z.string().min(1).max(16384).transform(keepSecret),
  refresh_token: z.string().min(1).max(16384).transform(keepSecret).optional(),
  token_type: z.string().refine((value) => value.toLowerCase() === "bearer"),
  expires_in: z.number().int().positive().max(31536000),
});
export const ProfileSchema = z.strictObject({
  name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/),
  origin: CanonicalOriginSchema, trust: TrustSchema,
  server_id: ServerIdSchema.optional(), client_id: z.string().min(1).max(256),
  tokens: TokensSchema, expires_at: z.number().int().positive(),
});
export const KeyChoiceSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("file"), public_key: PublicKeySchema, public_path: z.string(), private_path: z.string() }),
  z.strictObject({ kind: z.literal("agent"), public_key: PublicKeySchema }),
]);
const StateSchema = z.strictObject({
  version: z.literal(1), profiles: z.array(ProfileSchema), active: ProfileSchema.shape.name.optional(),
  key: KeyChoiceSchema.optional(),
}).refine((state) => new Set(state.profiles.map((profile) => profile.name)).size === state.profiles.length);
export type Trust = z.infer<typeof TrustSchema>;
export type Tokens = z.infer<typeof TokensSchema>;
export type Profile = z.infer<typeof ProfileSchema>;
export type KeyChoice = z.infer<typeof KeyChoiceSchema>;
export type State = z.infer<typeof StateSchema>;
const exec = promisify(execFile);

export function configDirectory(platform = process.platform, env = process.env, home = homedir()): string {
  if (env.TARTLET_CONFIG_DIR) return path.resolve(env.TARTLET_CONFIG_DIR);
  if (platform === "win32") return path.win32.join(env.LOCALAPPDATA ?? path.win32.join(home, "AppData", "Local"), "tartlet");
  if (platform === "darwin") return path.join(home, "Library", "Application Support", "tartlet");
  return path.join(env.XDG_CONFIG_HOME ?? path.join(home, ".config"), "tartlet");
}
export function windowsAclArguments(): string[] {
  const script = `$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
(Get-Item -LiteralPath $env:TARTLET_ACL_DIRECTORY).SetAccessControl($acl)`;
  return ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")];
}
export async function windowsPrivate(directory: string, execute: (file: string, args: string[], options: { windowsHide: boolean; env: NodeJS.ProcessEnv }) => Promise<unknown> = exec) {
  await execute("powershell.exe", windowsAclArguments(), { windowsHide: true, env: { ...process.env, TARTLET_ACL_DIRECTORY: directory } });
}
export async function privateDirectory(directory: string, platform = process.platform, protectWindows = windowsPrivate) {
  const created = await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("The configuration folder must be a real folder, not a link.");
  if (platform === "win32") {
    if (created !== undefined) {
      try { await protectWindows(directory); }
      catch (error) { await rmdir(directory); throw error; }
    }
  }
  else {
    if (process.getuid && info.uid !== process.getuid()) throw new Error("The configuration folder belongs to another account.");
    await chmod(directory, 0o700);
  }
}
export async function privateWrite(file: string, contents: string) {
  await privateDirectory(path.dirname(file));
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, contents, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(temporary, file);
  } finally { await rm(temporary, { force: true }); }
}
export async function readState(directory: string): Promise<State> {
  await privateDirectory(directory);
  const file = path.join(directory, "profiles.json");
  try {
    const { open } = await import("node:fs/promises");
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try { return StateSchema.parse(JSON.parse(await handle.readFile("utf8"))); }
    finally { await handle.close(); }
  } catch (error) {
    if (z.object({ code: z.literal("ENOENT") }).safeParse(error).success) return { version: 1, profiles: [] };
    throw new Error("Cannot read the saved profiles in the configuration folder.");
  }
}
export async function withLock<T>(directory: string, name: string, run: () => Promise<T>): Promise<T> {
  await privateDirectory(directory);
  const lock = path.join(directory, `${name}.lock`), deadline = Date.now() + 30000;
  const owner = path.join(lock, `${randomUUID()}.owner`);
  while (!await acquireLock(lock, owner)) {
    if (Date.now() > deadline) throw new Error("Another tartlet command is using the saved profiles. Try again in a minute.");
    await setTimeout(100);
  }
  try { return await run(); } finally { await releaseLock(lock, owner); }
}
const FileErrorSchema = z.object({ code: z.string() });
const OwnerSchema = z.object({ pid: z.number().int().positive() });
const fileError = (error: unknown, codes: string[]) => { const result = FileErrorSchema.safeParse(error); return result.success && codes.includes(result.data.code); };
async function removeEmptyLock(lock: string) {
  try { await rmdir(lock); } catch (error) { if (!fileError(error, ["ENOENT", "ENOTEMPTY", "EEXIST"])) throw error; }
}
async function releaseLock(lock: string, owner: string) {
  await rm(owner, { force: true }); await removeEmptyLock(lock);
}
async function liveOwner(file: string) {
  try {
    const parsed = OwnerSchema.safeParse(JSON.parse(await readFile(file, "utf8")));
    if (!parsed.success) return false;
    process.kill(parsed.data.pid, 0); return true;
  } catch (error) { return !(error instanceof SyntaxError || fileError(error, ["ENOENT", "ESRCH"])); }
}
async function recoverLock(lock: string) {
  const entries = await readdir(lock);
  if (entries.length === 0) {
    if (Date.now() - (await lstat(lock)).mtimeMs > 60000) await removeEmptyLock(lock);
    return;
  }
  for (const entry of entries) {
    if (!/^[0-9a-f-]{36}\.owner$/.test(entry)) continue;
    const owner = path.join(lock, entry), info = await lstat(owner);
    if (info.isFile() && Date.now() - info.mtimeMs > 60000 && !await liveOwner(owner)) await rm(owner, { force: true });
  }
  await removeEmptyLock(lock);
}
async function acquireLock(lock: string, owner: string): Promise<boolean> {
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) {
    if (!fileError(error, ["EEXIST"])) throw error;
    try { await recoverLock(lock); } catch (error) { if (!fileError(error, ["ENOENT"])) throw error; }
    return false;
  }
  try {
    await writeFile(owner, JSON.stringify({ pid: process.pid }), { mode: 0o600, flag: "wx" });
    const entries = await readdir(lock);
    if (entries.length === 1 && entries[0] === path.basename(owner)) return true;
  } catch (error) { if (!fileError(error, ["ENOENT"])) throw error; }
  await releaseLock(lock, owner); return false;
}
export async function changeState<T>(directory: string, change: (state: State) => Promise<T>) {
  return withLock(directory, "profiles", async () => {
    const state = await readState(directory), result = await change(state);
    await privateWrite(path.join(directory, "profiles.json"), `${JSON.stringify(StateSchema.parse(state), null, 2)}\n`);
    return result;
  });
}
export function selectProfile(state: State, name = state.active): Profile {
  const profile = state.profiles.find((entry) => entry.name === name);
  if (!profile) throw new Error("No saved profile found. Run tartlet login first, or check the --profile name.");
  return profile;
}
export async function readUtf8(file: string) { return readFile(file, "utf8"); }
