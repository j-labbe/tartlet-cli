import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import yaml from "js-yaml";

const workflow = async (name) => yaml.load(await readFile(new URL(`../../../.github/workflows/${name}.yml`, import.meta.url), "utf8"));
test("CI verifies packages and the installed binary on Linux, macOS and Windows", async () => {
  const { jobs } = await workflow("ci");
  for (const platform of ["ubuntu-latest", "windows-latest", "macos-latest"]) {
    const job = Object.values(jobs).find((value) => value["runs-on"] === platform || value.strategy?.matrix?.os?.includes(platform));
    assert.ok(job, `${platform} needs package checks.`);
    const commands = job.steps.map((step) => step.run);
    for (const command of ["npm run typecheck", "npm run lint", "npm test", "npm run pack:smoke"]) assert.ok(commands.includes(command), `${platform} must run ${command}.`);
  }
});
test("npm publication requires both an explicit request and main", async () => {
  const { jobs } = await workflow("release");
  for (const publish of [false, true]) for (const ref of ["refs/heads/main", "refs/heads/feature"]) {
    const allowed = runInNewContext(jobs.publish.if, { inputs: { publish }, github: { ref } });
    assert.equal(allowed, publish && ref === "refs/heads/main");
  }
});
