import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile), root = fileURLToPath(new URL("../", import.meta.url));
const directory = await mkdtemp(path.join(tmpdir(), "tartlet pack "));
try {
  const { stdout } = await exec("npm", ["pack", "--workspace", "@tartlet/protocol", "--workspace", "@tartlet/cli", "--json", "--pack-destination", directory], { cwd: root });
  const packages = JSON.parse(stdout.slice(stdout.indexOf("[")));
  assert.equal(packages.length, 2);
  await writeFile(path.join(directory, "package.json"), '{"private":true}\n');
  await exec("npm", ["install", "--ignore-scripts", "--omit=optional", "--no-audit", "--no-fund", ...packages.map((entry) => path.join(directory, entry.filename))], { cwd: directory });
  const binary = path.join(directory, "node_modules", ".bin", "tartlet");
  const output = await exec(binary, ["--help"], { cwd: directory, env: { ...process.env, TARTLET_CONFIG_DIR: path.join(directory, "config") } });
  assert.match(output.stdout, /Usage: tartlet/); assert.equal(output.stderr, "");
  await assert.rejects(access(path.join(directory, "config")));
  process.stdout.write(`${JSON.stringify({ packages: packages.map((entry) => ({ name: entry.name, version: entry.version, files: entry.files.length })), help_exit: 0, native_optional_dependencies: false })}\n`);
} finally { await rm(directory, { recursive: true, force: true }); }
