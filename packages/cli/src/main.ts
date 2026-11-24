#!/usr/bin/env node
import { run } from "./cli.js";
import { safeMessage } from "./errors.js";

try { process.exitCode = await run(process.argv.slice(2)); }
catch (error) { process.stderr.write(`tartlet: ${safeMessage(error)}\n`); process.exitCode = 1; }
