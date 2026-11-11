#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const artifactRoot = resolve(root, "release-artifacts/modern-v1-bb-6.0.0");
const manifestPath = resolve(root, "packages/kotlin/android-native/build.gradle.kts");
const MAX_NATIVE_LIBRARY_BYTES = 268_435_456;

export class AndroidManifestError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// CI tests the provider built from its exact commit, as the Swift lane does.
// Release manifests retain their immutable distribution checksums in Git.
export function prepareManifest(source, checksum) {
  if (typeof checksum !== "string" || !/^[0-9a-f]{64}$/u.test(checksum)) {
    throw new AndroidManifestError("invalid-checksum");
  }
  let manifest = source;
  for (const name of ["expectedAndroidJniSha256", "expectedAndroidAarJniSha256"]) {
    const assignment = new RegExp(`^val ${name} = "[0-9a-f]{64}"$`, "gmu");
    if ([...manifest.matchAll(assignment)].length !== 1) {
      throw new AndroidManifestError("ambiguous-manifest-assignment");
    }
    manifest = manifest.replace(assignment, `val ${name} = "${checksum}"`);
  }
  return manifest;
}

function main() {
  if (process.env.GITHUB_ACTIONS !== "true" || !/^[0-9a-f]{40}$/u.test(process.env.GITHUB_SHA ?? "")) {
    throw new AndroidManifestError("exact-github-ci-commit-required");
  }
  const commit = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: root, encoding: "utf8", timeout: 10_000, maxBuffer: 4096,
  });
  if (commit.error || commit.status !== 0 || commit.stdout.trim() !== process.env.GITHUB_SHA) {
    throw new AndroidManifestError("ci-commit-mismatch");
  }
  // Fix all inputs to this checkout's source outputs. Environment overrides
  // must not redirect admission to a different or diagnostic provider.
  const freshness = spawnSync(resolve(root, "scripts/check-android-platform-jni-freshness.sh"), [], {
    cwd: root,
    env: {
      ...process.env,
      REALLYME_ZK_LOCAL_ARTIFACT_ROOT: artifactRoot,
      PLATFORM_FFI_DIR: resolve(artifactRoot, "android-platform-ffi/arm64-v8a"),
      OUTPUT_ROOT: resolve(artifactRoot, "android-platform-jni"),
      OUTPUT_DIR: resolve(artifactRoot, "android-platform-jni/arm64-v8a"),
      METADATA_PATH: resolve(artifactRoot, "android-platform-jni/ReallyMeZKPlatformJNI.build.tsv"),
      EXPECTED_CARGO_FEATURES: "native",
    },
    stdio: "inherit", timeout: 120_000,
  });
  if (freshness.error || freshness.status !== 0) {
    throw new AndroidManifestError("current-source-admission-failed");
  }
  const library = resolve(artifactRoot, "android-platform-jni/arm64-v8a/libreallyme_zk_platform_jni.so");
  const status = lstatSync(library);
  if (!status.isFile() || status.size === 0 || status.size > MAX_NATIVE_LIBRARY_BYTES) {
    throw new AndroidManifestError("invalid-native-library");
  }
  const checksum = createHash("sha256").update(readFileSync(library)).digest("hex");
  const manifest = prepareManifest(readFileSync(manifestPath, "utf8"), checksum);
  writeFileSync(manifestPath, manifest);
  console.log("Android CI manifest bound to the admitted current-source provider");
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Android source manifest preparation failed: ${
      error instanceof AndroidManifestError ? error.code : "manifest-preparation-failed"}`);
    process.exitCode = 1;
  }
}
