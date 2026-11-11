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
const version = "0.3.0";
const workflowPaths = [
  "crates-package-preflight", "swift-package-preflight",
  "swift-package-release", "sealed-release-package-attestation",
].map((name) => `.github/workflows/${name}.yml`);

function checkFixture(staleWorkflow) {
  const root = mkdtempSync(join(tmpdir(), "zk-sdk-version-"));
  const write = (path, content) => {
    const destination = join(root, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, content);
  };
  try {
    for (const path of ["crates/api/Cargo.toml", "crates/artifacts/Cargo.toml", "crates/proto/Cargo.toml",
      "packages/kotlin/build.gradle.kts"]) {
      write(path, `version = "${version}"\n`);
    }
    write("packages/kotlin/demo-android/build.gradle.kts", `    versionName = "${version}"\n`);
    write("Package.swift", `let ffiArtifactVersion = "${version}"\n`);
    for (const path of workflowPaths) {
      write(path, `on:\n  workflow_dispatch:\n    inputs:\n      version:\n` +
        `        required: true\n        type: string\n        default: ${path === staleWorkflow ? "0.2.0" : version}\n`);
    }
    return spawnSync(process.execPath, [script, version], { cwd: root, encoding: "utf8" });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("package versions and release workflow defaults use the same version", () => {
  const result = checkFixture();
  assert.equal(result.status, 0, result.stderr);
});

for (const path of workflowPaths) {
  test(`rejects a stale release default in ${path}`, () => {
    const result = checkFixture(path);
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(`${path} is not bound to ${version}`));
  });
}
