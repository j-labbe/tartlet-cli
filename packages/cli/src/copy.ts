import path from "node:path";
import { stat, rename, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { type SFTPWrapper } from "ssh2";
import { withSsh } from "./ssh.js";
import type { Access } from "./access.js";

type Location = { kind: "local"; path: string } | { kind: "remote"; vm: string; path: string };
export function copyLocation(value: string, platform = process.platform): Location {
  if (platform === "win32" && /^[A-Za-z]:/.test(value)) return { kind: "local", path: value };
  const match = /^([a-z0-9][a-z0-9-]{0,62}):(.+)$/.exec(value), vm = match?.[1], file = match?.[2];
  return vm && file ? { kind: "remote", vm, path: file } : { kind: "local", path: value };
}
export function copyPlan(from: string, to: string) {
  const source = copyLocation(from), destination = copyLocation(to);
  if (source.kind === "remote" && destination.kind === "local") return { direction: "download", vm: source.vm, remote: source.path, local: destination.path };
  if (source.kind === "local" && destination.kind === "remote") return { direction: "upload", vm: destination.vm, remote: destination.path, local: source.path };
  throw new Error("Give one local file and one <vm>:<path>, for example tartlet cp ./file vm-example:/tmp/file.");
}
async function remoteDestination(sftp: SFTPWrapper, file: string, local: string) {
  return new Promise<string>((resolve, reject) => sftp.stat(file, (error, stats) => {
    if (!error) { resolve(stats.isDirectory() ? path.posix.join(file, path.basename(local)) : file); return; }
    if ("code" in error && error.code === 2) resolve(file); else reject(error);
  }));
}
async function localDestination(file: string, remote: string) {
  try { return (await stat(file)).isDirectory() ? path.join(file, path.posix.basename(remote)) : file; }
  catch (error) { if (error instanceof Error && "code" in error && error.code === "ENOENT") return file; throw error; }
}
async function transfer(sftp: SFTPWrapper, plan: ReturnType<typeof copyPlan>) {
  if (plan.direction === "upload") {
    const remote = await remoteDestination(sftp, plan.remote, plan.local);
    await new Promise<void>((resolve, reject) => sftp.fastPut(plan.local, remote, (error) => error ? reject(error) : resolve()));
    return;
  }
  const local = await localDestination(plan.local, plan.remote), temporary = `${local}.${randomUUID()}.tmp`;
  try {
    await new Promise<void>((resolve, reject) => sftp.fastGet(plan.remote, temporary, (error) => error ? reject(error) : resolve()));
    await rename(temporary, local);
  } finally { await rm(temporary, { force: true }); }
}
export async function copy(access: Access, plan: ReturnType<typeof copyPlan>) {
  await withSsh(access, (client) => new Promise<void>((resolve, reject) => client.sftp((error, sftp) => {
    if (error) { reject(error); return; }
    void transfer(sftp, plan).then(() => { sftp.end(); resolve(); }, (failure: unknown) => { sftp.end(); reject(failure); });
  })));
}
