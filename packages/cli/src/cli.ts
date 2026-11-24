import { parseArgs } from "node:util";
import { createInterface } from "node:readline/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { login, type LoginIO } from "./profiles.js";
import { link } from "./keys.js";
import { authorize } from "./access.js";
import { configDirectory, changeState, privateDirectory } from "./storage.js";
import { ssh, type TerminalIO } from "./ssh.js";
import { copy, copyPlan } from "./copy.js";
import { proxy, writeNativeConfig } from "./proxy.js";
import type { Endpoint } from "./http.js";

export const HELP = `Usage: tartlet <command> [options]

  login [--server <https-origin>] [--device] [--ca <root.pem>]
  ssh <vm|label> [-- <command>]
  cp <local-file> <vm|label>:<path>   (or the reverse)
  proxy <vm|label> [--config]
  link [<key.pub>] [--identity <private-key>]
  link --agent <SHA256:fingerprint> | --generate
  unlink

Options:
  --profile <name>  Choose a saved server profile
  --label           Select the target by label when its name is ambiguous
  --help            Show this help
  --version         Show the version

login uses browser sign-in, or a device code with --device.
--ca pins a self-signed HTTPS root CA obtained from your administrator.
link chooses a local key; each connection authorizes it briefly on the VM.
Without a selected key, the CLI creates one in its private configuration folder.
proxy --config prints a private OpenSSH config path. Use ssh -F <path> <vm>.
Use that same config with VS Code or native SSH port forwarding.
cp copies one file over SFTP. Quote remote shell commands after --.
`;
const exec = promisify(execFile);
export async function openBrowser(url: string) {
  if (process.platform === "darwin") await exec("open", [url]);
  else if (process.platform === "win32") await exec("rundll32.exe", ["url.dll,FileProtocolHandler", url], { windowsHide: true });
  else await exec("xdg-open", [url]);
}
export function defaultIO(): LoginIO & TerminalIO {
  return { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr, open: openBrowser,
    say: (message) => { process.stderr.write(`${message}\n`); },
    choose: async (message, options) => {
      if (options.length === 1) return 0;
      if (!process.stdin.isTTY) throw new Error(`${message} needs a terminal. Use --server or an explicit key flag.`);
      const terminal = createInterface({ input: process.stdin, output: process.stderr });
      try {
        const choice = Number(await terminal.question(`${message}:\n${options.map((item, index) => `  ${index + 1}. ${item}`).join("\n")}\nChoice: `)) - 1;
        if (!Number.isInteger(choice) || choice < 0 || choice >= options.length) throw new Error("Choose one of the listed options.");
        return choice;
      } finally { terminal.close(); }
    },
  };
}
const string: { type: "string" } = { type: "string" }, boolean: { type: "boolean" } = { type: "boolean" };
function parse(command: string, args: string[]) {
  const common = { profile: string, help: boolean, version: boolean };
  const extra = commandOptions(command);
  const options: Record<string, { type: "string" | "boolean" }> = { ...common, ...extra };
  return parseArgs({ args, allowPositionals: true, options });
}
function commandOptions(command: string): Record<string, { type: "string" | "boolean" }> {
  switch (command) {
    case "login": return { server: { type: "string" }, ca: { type: "string" }, device: { type: "boolean" } };
    case "link": return { file: { type: "string" }, identity: { type: "string" }, agent: { type: "string" }, generate: { type: "boolean" } };
    case "ssh": case "cp": return { label: { type: "boolean" } };
    case "proxy": return { label: { type: "boolean" }, config: { type: "boolean" } };
    case "unlink": return {};
    default: throw new Error(`Unknown command: ${command}. Run tartlet --help.`);
  }
}
async function linkCommand(directory: string, args: ReturnType<typeof parse>, io: LoginIO) {
  let file = stringOption(args, "file") ?? args.positionals[0];
  let generate = Boolean(args.values.generate), agentKey = stringOption(args, "agent");
  if (args.positionals.length > 1 || Number(Boolean(file)) + Number(generate) + Number(Boolean(agentKey)) > 1) throw new Error("Choose one key source: a .pub file, --agent, or --generate.");
  if (!file && !generate && !agentKey) ({ file, generate, agentKey } = await chooseKeySource(io));
  const identity = stringOption(args, "identity");
  await link(directory, { generate, io, ...(file ? { file } : {}), ...(agentKey ? { agentKey } : {}), ...(identity ? { identity } : {}) });
}
async function chooseKeySource(io: LoginIO): Promise<{ file: string | undefined; generate: boolean; agentKey: string | undefined }> {
  const choice = await io.choose("Choose a key source", ["SSH agent", "Public key file", "Create a new key"]);
  if (choice === 0) return { file: undefined, generate: false, agentKey: "choose" };
  if (choice === 2) return { file: undefined, generate: true, agentKey: undefined };
  const terminal = createInterface({ input: process.stdin, output: process.stderr });
  try { return { file: await terminal.question("Public key file: "), generate: false, agentKey: undefined }; }
  finally { terminal.close(); }
}
function stringOption(args: ReturnType<typeof parse>, key: string) {
  const value = args.values[key]; return typeof value === "string" ? value : undefined;
}
function immediateOutput(command: string | undefined) {
  if (!command || command === "--help" || command === "-h") return HELP;
  if (command === "--version") return "0.2.0\n";
  return undefined;
}
export interface Runtime { directory?: string; io?: LoginIO & TerminalIO; cloud?: Endpoint }
export async function run(argv: string[], runtime: Runtime = {}): Promise<number> {
  const io = runtime.io ?? defaultIO(), command = argv[0];
  const immediate = immediateOutput(command);
  if (immediate) { io.stdout.write(immediate); return 0; }
  if (!command) return 0;
  const { args, remoteCommand } = parseCommand(command, argv);
  if (args.values.help) { io.stdout.write(HELP); return 0; }
  if (args.values.version) { io.stdout.write("0.2.0\n"); return 0; }
  const directory = runtime.directory ?? configDirectory();
  await privateDirectory(directory);
  return execute({ command, args, io, directory, remoteCommand, ...(runtime.cloud ? { cloud: runtime.cloud } : {}) });
}
function parseCommand(command: string, argv: string[]) {
  const separator = command === "ssh" ? argv.indexOf("--") : -1;
  return { args: parse(command, argv.slice(1, separator === -1 ? undefined : separator)), remoteCommand: separator === -1 ? [] : argv.slice(separator + 1) };
}
interface Execution { command: string; args: ReturnType<typeof parse>; io: LoginIO & TerminalIO; directory: string; remoteCommand: string[]; cloud?: Endpoint }
async function execute(input: Execution): Promise<number> {
  const { command, args, directory, io } = input;
  const profile = stringOption(args, "profile");
  switch (command) {
    case "login": {
      if (args.positionals.length) throw new Error("Use tartlet login --server <https-origin>.");
      await loginCommand(input, profile); return 0;
    }
    case "link": await linkCommand(directory, args, io); return 0;
    case "unlink":
      if (args.positionals.length) throw new Error("Use tartlet unlink with no arguments.");
      await changeState(directory, async (state) => { delete state.key; }); io.say("Removed the local key selection. Existing temporary authorizations expire on their own."); return 0;
    default: return connectCommand(input, profile);
  }
}
async function loginCommand(input: Execution, profile: string | undefined) {
  const { directory, args, io } = input, server = stringOption(args, "server"), ca = stringOption(args, "ca");
  await login({ directory, device: Boolean(args.values.device), io, ...(profile ? { profile } : {}), ...(server ? { server } : {}), ...(ca ? { ca } : {}), ...(input.cloud ? { cloud: input.cloud } : {}) });
}
async function connectCommand({ command, args, directory, io, remoteCommand }: Execution, profile?: string): Promise<number> {
  const target = args.positionals[0];
  if (!target) throw new Error(`Use tartlet ${command} <vm|label>. Run tartlet --help for examples.`);
  const options = { label: Boolean(args.values.label), ...(profile ? { profile } : {}) };
  if (command === "cp") {
    const destination = args.positionals[1];
    if (!destination || args.positionals.length !== 2) throw new Error("Use tartlet cp <source> <destination>.");
    const plan = copyPlan(target, destination); await copy(await authorize(directory, plan.vm, options), plan); return 0;
  }
  if (args.positionals.length !== 1) throw new Error("Put a remote shell command after --.");
  const access = await authorize(directory, target, options);
  if (command === "ssh") return ssh(access, remoteCommand, io);
  if (args.values.config) io.stdout.write(`${await writeNativeConfig(access, directory)}\n`);
  else await proxy(access, io);
  return 0;
}
