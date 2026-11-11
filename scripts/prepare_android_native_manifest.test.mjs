#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { AndroidManifestError, prepareManifest } from "./prepare_android_native_manifest.mjs";

const checksum = "a".repeat(64);
const fixture = `val expectedAndroidJniSha256 = "${"0".repeat(64)}"
val expectedAndroidAarJniSha256 = "${"0".repeat(64)}"
val expectedAndroidCppSha256 = "${"b".repeat(64)}"
`;

test("binds both JNI checksums while preserving the pinned C++ runtime", () => {
  const result = prepareManifest(fixture, checksum);
  assert.equal(result.split(checksum).length - 1, 2);
  assert.ok(result.includes(`val expectedAndroidCppSha256 = "${"b".repeat(64)}"`));
  const realManifest = readFileSync("packages/kotlin/android-native/build.gradle.kts", "utf8");
  assert.equal(prepareManifest(realManifest, checksum).split(checksum).length - 1, 2);
});

test("rejects malformed checksums and ambiguous or missing assignments", () => {
  for (const invalid of [null, undefined, "", "a".repeat(63), "A".repeat(64), `${checksum}\n`]) {
    assert.throws(() => prepareManifest(fixture, invalid), AndroidManifestError);
  }
  for (const source of ["", `${fixture}${fixture}`, fixture.replace("expectedAndroidAarJniSha256", "removed")]) {
    assert.throws(() => prepareManifest(source, checksum), AndroidManifestError);
  }
});

test("refuses to bind a source manifest outside exact-commit GitHub CI", () => {
  const result = spawnSync(process.execPath, ["scripts/prepare_android_native_manifest.mjs"], {
    env: { ...process.env, GITHUB_ACTIONS: "false" }, encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /exact-github-ci-commit-required/u);
});

test("rejects a claimed CI commit that does not match the checkout", () => {
  const result = spawnSync(process.execPath, ["scripts/prepare_android_native_manifest.mjs"], {
    env: { ...process.env, GITHUB_ACTIONS: "true", GITHUB_SHA: "0".repeat(40) },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /ci-commit-mismatch/u);
});
