// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";

const expression = (value) => `\u0024{{ ${value} }}`;
const release = readFileSync(".github/workflows/crates-release.yml", "utf8");
const preflight = readFileSync(".github/workflows/crates-package-preflight.yml", "utf8");
const selectedRun = expression("needs.verify-preflight.outputs.preflight_run_id");
const resolvedRun = expression("steps.resolve-attestation.outputs.preflight_run_id");
const currentRun = expression("github.run_id");
const downloads = [];

for (const [source, job, runId, identity, destinations] of [
  [release, "verify-preflight", resolvedRun, "steps.verify-source", ["zk/release-attestation", "zk/reviewed-crates"]],
  [release, "publish", selectedRun, "needs.verify-preflight", ["zk/release-attestation", "zk/reviewed-crates"]],
  [release, "finalize", selectedRun, "needs.verify-preflight", ["release-evidence", "release-evidence", "release-evidence"]],
  [preflight, "attest-reviewed-evidence", currentRun, "needs.verify-source-sha", ["release-attestation", "reviewed-crates"]],
]) {
  const jobBody = source.split(`  ${job}:\n`)[1]?.split(/^  [a-z][a-z-]+:\n/mu)[0];
  assert.ok(jobBody, job);
  const steps = [...jobBody.matchAll(/      - name: (Download [^\n]+)\n        env:\n((?: {10}[^\n]*\n)+)        run: >-\n((?: {10}[^\n]*\n)+)/gu)];
  downloads.push({ job, runId, identity, destinations, steps });
}

test("crate evidence downloads retain exact named artifacts, producing runs, and destinations", () => {
  for (const source of [release, preflight]) {
    assert.doesNotMatch(source, /actions\/download-artifact|NODE_NO_WARNINGS|no-deprecation/u);
  }
  const prefixes = ["crates-preflight", "crate-archives", "publication-ledger"];
  for (const { job, runId, identity, destinations, steps } of downloads) {
    assert.equal(steps.length, destinations.length, job);
    steps.forEach(([, , environment, command], index) => {
      assert.ok(environment.includes(`GH_TOKEN: ${expression("github.token")}\n`));
      assert.ok(environment.includes(`ARTIFACT_RUN_ID: ${index === 2 ? currentRun : runId}\n`));
      assert.ok(environment.includes(`ARTIFACT_NAME: reallyme-zk-${prefixes[index]}-${expression(`${identity}.outputs.release_version`)}-${expression(`${identity}.outputs.release_sha`)}\n`));
      assert.equal(command.trim().split(/\n\s*/u).join(" "),
        `gh run download "$ARTIFACT_RUN_ID" --repo "$GITHUB_REPOSITORY" --name "$ARTIFACT_NAME" --dir ${destinations[index]}`);
    });
  }
});

test("download commands preserve quoted arguments and propagate GitHub CLI failure", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-download-test-"));
  try {
    const argumentsPath = join(directory, "arguments.json");
    writeFileSync(join(directory, "gh"), `#!/usr/bin/env node
import { writeFileSync } from "node:fs";
writeFileSync(process.env.DOWNLOAD_ARGUMENTS_PATH, JSON.stringify(process.argv.slice(2)));
process.exit(Number(process.env.DOWNLOAD_STATUS));
`, { mode: 0o755 });
    for (const { steps, destinations } of downloads) {
      for (const [index, [, , , command]] of steps.entries()) {
        for (const status of [0, 17]) {
          const result = spawnSync("bash", ["-e", "-c", command.trim().split(/\n\s*/u).join(" ")], {
            cwd: directory,
            encoding: "utf8",
            timeout: 10_000,
            env: {
              ...process.env,
              PATH: `${directory}${delimiter}${process.env.PATH}`,
              ARTIFACT_RUN_ID: "12345",
              GITHUB_REPOSITORY: "reallyme/zk",
              ARTIFACT_NAME: "fixture with spaces;$(false)",
              DOWNLOAD_ARGUMENTS_PATH: argumentsPath,
              DOWNLOAD_STATUS: String(status),
            },
          });
          assert.equal(result.error, undefined);
          assert.equal(result.status, status, result.stderr);
          assert.deepEqual(JSON.parse(readFileSync(argumentsPath, "utf8")), [
            "run", "download", "12345", "--repo", "reallyme/zk",
            "--name", "fixture with spaces;$(false)", "--dir", destinations[index],
          ]);
        }
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
