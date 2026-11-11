#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { lstatSync, readFileSync } from "node:fs";

const versionPattern = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const [, , expectedVersion] = process.argv;
const fail = (reason) => {
  console.error(`SDK release version verification failed: ${reason}`);
  process.exit(1);
};
if (expectedVersion === undefined || !versionPattern.test(expectedVersion)) {
  fail("expected one semantic version without a leading v");
}

const readRegular = (path) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    fail(`${path} is inaccessible`);
  }
  if (status.isSymbolicLink() || !status.isFile() || status.size < 1 || status.size > 1_048_576) {
    fail(`${path} is not a bounded regular file`);
  }
  return readFileSync(path, "utf8");
};

const assignments = [
  ["crates/api/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["crates/artifacts/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["crates/proto/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["packages/kotlin/build.gradle.kts", /^version = "([^"]+)"$/gmu],
  ["packages/kotlin/demo-android/build.gradle.kts", /^\s+versionName = "([^"]+)"$/gmu],
  ["Package.swift", /^let ffiArtifactVersion = "([^"]+)"$/gmu],
];
const workflowVersionPattern = /^      version:\n(?: {8}[^\n]*\n)*? {8}default: ([0-9]+\.[0-9]+\.[0-9]+)$/gmu;
for (const workflow of [
  "crates-package-preflight", "swift-package-preflight",
  "swift-package-release", "sealed-release-package-attestation",
]) {
  assignments.push([`.github/workflows/${workflow}.yml`, workflowVersionPattern]);
}
for (const [path, pattern] of assignments) {
  const matches = [...readRegular(path).matchAll(pattern)];
  if (matches.length !== 1 || matches[0][1] !== expectedVersion) {
    fail(`${path} is not bound to ${expectedVersion}`);
  }
}
console.log(`Rust, Swift, and Kotlin ZK package versions are bound to ${expectedVersion}`);
