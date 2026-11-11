// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const script = fileURLToPath(new URL("./verify_sdk_release_version.mjs", import.meta.url));
const version = "0.3.1";
const workflowPaths = [
  "swift-package-preflight", "swift-package-release",
].map((name) => `.github/workflows/${name}.yml`);
const packageAssignments = [
  ["packages/kotlin/build.gradle.kts", `version = "${version}"\n`],
  ["packages/kotlin/demo-android/build.gradle.kts", `    versionName = "${version}"\n`],
  ["Package.swift", `let ffiArtifactVersion = "${version}"\n`],
];

function checkFixture({ overridePath, overrideSource } = {}) {
  const root = mkdtempSync(join(tmpdir(), "zk-sdk-version-"));
  const write = (path, content) => {
    const destination = join(root, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, content);
  };
  try {
    for (const path of ["crates/api/Cargo.toml", "crates/artifacts/Cargo.toml", "crates/proto/Cargo.toml"]) {
      write(path, 'version = "0.3.0"\n');
    }
    for (const [path, content] of packageAssignments) {
      write(path, content);
    }
    for (const path of workflowPaths) {
      write(path, `on:\n  workflow_dispatch:\n    inputs:\n      version:\n` +
        `        required: true\n        type: string\n        default: ${version}\n`);
    }
    for (const name of ["crates-package-preflight", "sealed-release-package-attestation"]) {
      write(`.github/workflows/${name}.yml`, `on:\n  workflow_dispatch:\n    inputs:\n      version:\n` +
        "        required: true\n        type: string\n        default: 0.3.0\n");
    }
    if (overridePath !== undefined) {
      write(overridePath, overrideSource);
    }
    return spawnSync(process.execPath, [script, version], { cwd: root, encoding: "utf8" });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("SDK patch releases admit the existing Rust and sealed circuit package versions", () => {
  const result = checkFixture();
  assert.equal(result.status, 0, result.stderr);
});

for (const path of workflowPaths) {
  test(`rejects a stale release default in ${path}`, () => {
    const result = checkFixture({
      overridePath: path,
      overrideSource: "on:\n  workflow_dispatch:\n    inputs:\n      version:\n" +
        "        required: true\n        type: string\n        default: 0.3.0\n",
    });
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(`${path} is not bound to ${version}`));
  });
}

for (const [path, source] of packageAssignments) {
  for (const [reason, changed] of [
    ["stale", source.replace(version, "0.3.0")],
    ["missing", ""],
    ["duplicate", source + source],
    ["malformed", source.replace(version, "0.3.1-rc.1")],
  ]) {
    test(`rejects ${reason} SDK version in ${path}`, () => {
      const result = checkFixture({ overridePath: path, overrideSource: changed });
      assert.equal(result.status, 1);
      assert.ok(result.stderr.includes(path));
    });
  }
}
