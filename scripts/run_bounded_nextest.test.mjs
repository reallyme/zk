// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./run_bounded_nextest.mjs", import.meta.url));

function invoke({ ids = ["fixture::tests"], lane = "default", listStatus = 0, runStatus = 0, malformed = false } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "bounded-nextest-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const preload = join(directory, "mock.mjs");
    const binaries = Object.fromEntries(ids.map((id) => [id, { "binary-id": id }]));
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const calls = [];
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return args[1] === "list"
    ? { status: ${listStatus}, stdout: ${JSON.stringify(malformed ? "{" : JSON.stringify({ "rust-binaries": binaries }))} }
    : { status: ${runStatus}, stdout: "" };
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, lane], { encoding: "utf8" });
    const calls = existsSync(callsPath) ? JSON.parse(readFileSync(callsPath, "utf8")) : [];
    return { result, calls };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("bounded nextest executes valid binary and example targets with locked resolution", () => {
  const ids = ["fixture::bin/cli", "fixture::example/example", "fixture::tests"];
  const { result, calls } = invoke({ ids });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.slice(0, 4)), [
    ["cargo", "nextest", "list", "--locked"], ["cargo", "nextest", "run", "--locked"],
  ]);
  const filterIndex = calls[1].indexOf("--filterset");
  assert.equal(calls[1][filterIndex + 1], ids.map((id) => `binary_id(=${id})`).join(" | "));
});

test("all runtime lanes apply identical features during discovery and execution", () => {
  for (const lane of ["default", "native", "all-features"]) {
    const { result, calls } = invoke({ lane });
    assert.equal(result.status, 0, result.stderr);
    for (const call of calls) {
      assert.equal(call.includes("--no-default-features"), lane === "native");
      assert.equal(call.includes("--all-features"), lane === "all-features");
    }
  }
});

test("malformed discovery and filter injection stop before test execution", () => {
  for (const input of [{ ids: [] }, { malformed: true }, { listStatus: 23 },
    { ids: ["fixture)|all()"] }, { ids: ["fixture with whitespace"] }, { lane: "unknown" }]) {
    const { result, calls } = invoke(input);
    assert.notEqual(result.status, 0);
    assert.equal(calls.filter((call) => call[2] === "run").length, 0);
  }
});

test("a failed test batch cannot produce successful qualification", () => {
  const { result } = invoke({ runStatus: 23 });
  assert.notEqual(result.status, 0);
});
