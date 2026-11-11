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

const script = fileURLToPath(new URL("./check-platform-policy-delegation.mjs", import.meta.url));
const workflow = readFileSync(new URL("../.github/workflows/rust-ci.yml", import.meta.url), "utf8");

function invoke(source, lane) {
  const root = mkdtempSync(join(tmpdir(), "platform-delegation-test-"));
  try {
    mkdirSync(join(root, ".github/workflows"), { recursive: true });
    writeFileSync(join(root, ".github/workflows/rust-ci.yml"), source);
    return spawnSync(process.execPath, [script, lane], { cwd: root, encoding: "utf8" });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("platform delegation rejects trigger filters that could omit relevant source", () => {
  for (const lane of ["swift", "kotlin"]) {
    assert.equal(invoke(workflow, lane).status, 0);
    assert.notEqual(invoke(workflow.replace('  pull_request:\n', '  pull_request:\n    paths-ignore:\n      - "packages/**"\n'), lane).status, 0);
    assert.notEqual(invoke(workflow.replace('  pull_request:\n', '  pull_request:\n    paths:\n      - "crates/**"\n'), lane).status, 0);
  }
});

test("platform delegation rejects missing current-source providers or package checks", () => {
  for (const [lane, command] of [
    ["swift", "          scripts/build_swift_xcframework.sh"],
    ["kotlin", "          scripts/check-android-platform-jni-freshness.sh"],
    ["kotlin", "          :android-native:check"],
  ]) {
    const changed = workflow.replace(command, "");
    assert.notEqual(changed, workflow);
    assert.notEqual(invoke(changed, lane).status, 0);
  }
});


test("platform delegation rejects ungoverned conditional execution", () => {
  for (const [lane, fragment] of [
    ["swift", "if: needs.changes.outputs.swift == 'true'"],
    ["kotlin", "if: needs.changes.outputs.android == 'true'"],
    ["swift", "node scripts/select-ci-scope.mjs"],
    ["kotlin", "node scripts/require-ci-results.mjs"],
  ]) {
    assert.notEqual(invoke(workflow.replaceAll(fragment, ""), lane).status, 0);
  }
});
