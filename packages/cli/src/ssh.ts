import { timingSafeEqual } from "node:crypto";
import ssh2, { type Client as SshClient, type ClientChannel, type ServerHostKeyAlgorithm } from "ssh2";
import { parsePublicKey } from "@tartlet/protocol";
import { authentication } from "./keys.js";
import { openTunnel } from "./tunnel.js";
import type { Access } from "./access.js";
const { Client } = ssh2;

export function pinnedHostKey(line: string) {
  const publicKey = parsePublicKey(line.split(" ").slice(1).join(" "));
  const expected = Buffer.from(publicKey.public_key.split(" ")[1] ?? "", "base64");
  return (actual: Buffer) => actual.length === expected.length && timingSafeEqual(actual, expected);
}
function hostAlgorithms(line: string): ServerHostKeyAlgorithm[] {
  const key = parsePublicKey(line.split(" ").slice(1).join(" "));
  return key.type === "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [key.type];
}
export async function withSsh<T>(access: Access, run: (client: SshClient) => Promise<T>): Promise<T> {
  const auth = await authentication(access.key), tunnel = await openTunnel(access), client = new Client();
  let failed: (error: Error) => void = () => {}, closing = false;
  const lost = new Promise<never>((_resolve, reject) => { failed = reject; });
  void lost.catch(() => {});
  client.on("error", failed);
  client.on("close", () => { if (!closing) failed(new Error("The connection closed before the command finished.")); });
  tunnel.on("error", failed);
  try {
    await Promise.race([lost, new Promise<void>((resolve) => {
      client.once("ready", resolve);
      client.connect({ ...auth, sock: tunnel, username: access.connection.user, hostVerifier: pinnedHostKey(access.connection.known_hosts_line),
        algorithms: { serverHostKey: hostAlgorithms(access.connection.known_hosts_line) }, readyTimeout: 30000, keepaliveInterval: 15000, keepaliveCountMax: 3 });
    })]);
    return await Promise.race([lost, run(client)]);
  } finally { closing = true; client.end(); client.destroy(); tunnel.destroy(); }
}
export interface TerminalIO { stdin: NodeJS.ReadStream; stdout: NodeJS.WriteStream; stderr: NodeJS.WriteStream }
function pipeChannel(channel: ClientChannel, io: TerminalIO, interactive: boolean): Promise<number> {
  const wasRaw = io.stdin.isRaw;
  const resize = () => channel.setWindow(io.stdout.rows || 24, io.stdout.columns || 80, 0, 0);
  if (interactive) { io.stdin.setRawMode(true); io.stdout.on("resize", resize); }
  io.stdin.pipe(channel); channel.pipe(io.stdout, { end: false }); channel.stderr.pipe(io.stderr, { end: false });
  return new Promise<number>((resolve, reject) => {
    const clean = () => {
      io.stdin.unpipe(channel); io.stdin.pause(); channel.unpipe(io.stdout); channel.stderr.unpipe(io.stderr);
      io.stdout.off("resize", resize); if (interactive) io.stdin.setRawMode(wasRaw);
    };
    channel.once("error", (error: Error) => { clean(); reject(error); });
    channel.once("close", (code: number | undefined) => { clean(); resolve(code ?? 255); });
  });
}
export async function ssh(access: Access, command: string[], io: TerminalIO): Promise<number> {
  return withSsh(access, (client) => new Promise<number>((resolve, reject) => {
    const ready = (error: Error | undefined, channel: ClientChannel) => {
      if (error) { reject(error); return; }
      void pipeChannel(channel, io, command.length === 0 && Boolean(io.stdin.isTTY)).then(resolve, reject);
    };
    if (command.length) client.exec(command.join(" "), ready);
    else client.shell(io.stdin.isTTY ? { term: process.env.TERM ?? "xterm-256color", rows: io.stdout.rows || 24, cols: io.stdout.columns || 80 } : false, ready);
  }));
}
