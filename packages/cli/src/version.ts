import { readFileSync } from "node:fs";
import { z } from "zod";
import { CliVersionSchema } from "@tartlet/protocol";

const metadata = z.object({ version: CliVersionSchema }).parse(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")));
export const VERSION = metadata.version;
