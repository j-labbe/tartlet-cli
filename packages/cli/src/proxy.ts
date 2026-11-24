import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { privateWrite } from "./storage.js";
import { openTunnel } from "./tunnel.js";
import type { Access } from "./access.js";
import type { TerminalIO } from "./ssh.js";

export function sshConfigValue(value: string): string {
  if (/[\r\n\0]/.test(value)) throw new Error("SSH config file paths cannot contain line breaks.");
  return `"${value.replaceAll("\\", "/").replaceAll('"', '\\"').replaceAll("%", "%%")}"`;
}
export function commandArgument(value: string, platform = process.platform): string {
  if (/[\r\n\0]/.test(value)) throw new Error("Paths in the proxy command cannot contain line breaks.");
  if (platform === "win32") {
    return `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}
export function nativeConfig(access: Access, knownHosts: string, directory: string, executable = process.execPath, entry = fileURLToPath(new URL("main.js", import.meta.url)), platform = process.platform): string {
  const args = [executable, entry, "proxy", access.vm, "--profile", access.profile.name, "--config-dir", directory];
  const command = args.map((part) => commandArgument(part, platform)).join(" ");
  const identity = access.key.kind === "file" ? access.key.private_path : path.join(path.dirname(knownHosts), "identity.pub");
  return [
    `Host ${access.vm}`, `  HostName ${access.vm}`, `  User ${access.connection.user}`, `  HostKeyAlias ${access.connection.host_key_alias}`,
    `  UserKnownHostsFile ${sshConfigValue(knownHosts)}`, "  GlobalKnownHostsFile none", "  StrictHostKeyChecking yes", "  CheckHostIP no", "  UpdateHostKeys no",
    `  IdentityFile ${sshConfigValue(identity)}`, "  IdentitiesOnly yes", "  ServerAliveInterval 15", "  ServerAliveCountMax 3",
    `  ProxyCommand ${command.replaceAll("%", "%%")}`, "",
  ].join("\n");
}
export async function writeNativeConfig(access: Access, directory: string) {
  const id = createHash("sha256").update(`${access.profile.name}\0${access.vm}`).digest("hex").slice(0, 32);
  const folder = path.join(directory, "connections", id), knownHosts = path.join(folder, "known_hosts"), config = path.join(folder, "ssh_config");
  await privateWrite(knownHosts, `${access.connection.known_hosts_line}\n`);
  if (access.key.kind === "agent") await privateWrite(path.join(folder, "identity.pub"), `${access.key.public_key}\n`);
  await privateWrite(config, nativeConfig(access, knownHosts, directory));
  return config;
}
export async function proxy(access: Access, io: TerminalIO) {
  const tunnel = await openTunnel(access);
  await new Promise<void>((resolve, reject) => {
    let finished = false;
    const finish = (error?: Error) => {
      if (finished) return; finished = true;
      io.stdin.unpipe(tunnel); io.stdin.pause(); tunnel.unpipe(io.stdout);
      tunnel.off("end", ended); tunnel.off("close", ended); io.stdin.off("end", ended);
      tunnel.destroy(); io.stdout.end();
      if (error) reject(error); else resolve();
    };
    const ended = () => finish();
    tunnel.once("error", finish); tunnel.once("end", ended); tunnel.once("close", ended); io.stdin.once("end", ended);
    io.stdin.pipe(tunnel); tunnel.pipe(io.stdout, { end: false });
    if (io.stdin.readableEnded || tunnel.readableEnded) finish();
  });
}
