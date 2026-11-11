// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./run-fuzz-smoke.sh", import.meta.url));
const manifest = readFileSync(new URL("../fuzz/Cargo.toml", import.meta.url), "utf8");
const targets = [...manifest.matchAll(/\[\[bin\]\]\s+name = "([a-z0-9_]+)"/gu)].map((match) => match[1]);
const prefix = "REALLYME_ZK";

function invoke({ overrides = {}, failingTarget = "", omitTarget = "" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "fuzz-runner-test-"));
  try {
    const bin = join(directory, "bin");
    const log = join(directory, "calls.jsonl");
    mkdirSync(bin);
    for (const target of targets) {
      const corpus = join(directory, "fuzz/corpus", target);
      mkdirSync(corpus, { recursive: true });
      writeFileSync(join(corpus, "seed"), "fixture");
      if (target === omitTarget) continue;
      writeFileSync(join(bin, target), `#!/usr/bin/env node
const fs = require("node:fs");
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ target: ${JSON.stringify(target)}, args: process.argv.slice(2) }) + "\\n");
process.exit(${target === failingTarget ? 23 : 0});
`, { mode: 0o755 });
    }
    const env = { ...process.env, [prefix + "_FUZZ_BINARY_DIRECTORY"]: bin,
      [prefix + "_FUZZ_MAX_TOTAL_TIME"]: "20", ...overrides };
    const result = spawnSync("bash", [script], { cwd: directory, env, encoding: "utf8" });
    let calls = [];
    try { calls = readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    return { result, calls };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("staged fuzz execution covers every manifest target with corpus and explicit bounds", () => {
  const { result, calls } = invoke();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(calls.map((call) => call.target).sort(), [...targets].sort());
  for (const call of calls) {
    assert.ok(call.args.includes("-max_total_time=20"));
    assert.ok(call.args.includes("-rss_limit_mb=4096"));
    assert.ok(call.args.includes(`fuzz/corpus/${call.target}`));
  }
});

test("unknown targets and invalid time limits fail without executing a fuzzer", () => {
  for (const overrides of [{ [prefix + "_FUZZ_TARGET"]: "../escape" }, { [prefix + "_FUZZ_MAX_TOTAL_TIME"]: "0" }]) {
    const { result, calls } = invoke({ overrides });
    assert.notEqual(result.status, 0);
    assert.deepEqual(calls, []);
  }
});

test("failed or absent executables fail qualification", () => {
  for (const input of [{ failingTarget: targets[0] }, { omitTarget: targets[0] }]) {
    assert.notEqual(invoke(input).result.status, 0);
  }
});
