#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { PUBLIC_CRATE_NAMES as PUBLIC_CRATES } from "./public-crates.mjs";

import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const OUTPUT_DIRECTORY = "release-attestation";
const OUTPUT_PATH = `${OUTPUT_DIRECTORY}/crates-preflight.json`;
const MAX_CRATE_ARCHIVE_BYTES = 32 * 1024 * 1024;

const fail = (code) => {
  console.error(`release attestation creation failed: ${code}`);
  process.exit(1);
};

const parsePositiveInteger = (value, code) => {
  if (typeof value !== "string" || !POSITIVE_INTEGER_PATTERN.test(value)) {
    fail(code);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    fail(code);
  }
  return parsed;
};

const repository = process.env.GITHUB_REPOSITORY;
const releaseSha = process.env.RELEASE_SHA;
const version = process.env.RELEASE_VERSION;
if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
  fail("invalid-repository");
}
if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
  fail("invalid-release-sha");
}
if (typeof version !== "string" || !VERSION_PATTERN.test(version)) {
  fail("invalid-release-version");
}
const runId = parsePositiveInteger(process.env.GITHUB_RUN_ID, "invalid-run-id");
const runAttempt = parsePositiveInteger(process.env.GITHUB_RUN_ATTEMPT, "invalid-run-attempt");
if (runAttempt !== 1) {
  fail("rerun-cannot-create-release-attestation");
}

const targetDirectory = process.env.CARGO_TARGET_DIR ?? "target";
const packageArchives = PUBLIC_CRATES.map((name) => {
  const archivePath = path.join(targetDirectory, "package", `${name}-${version}.crate`);
  let status;
  let archive;
  try {
    status = lstatSync(archivePath);
    if (
      status.isSymbolicLink() ||
      !status.isFile() ||
      status.size === 0 ||
      status.size > MAX_CRATE_ARCHIVE_BYTES
    ) {
      fail("invalid-crate-archive");
    }
    archive = readFileSync(archivePath);
  } catch {
    fail("invalid-crate-archive");
  }
  return {
    file: `${name}-${version}.crate`,
    sha256: createHash("sha256").update(archive).digest("hex"),
    size: status.size,
  };
});

const attestation = {
  schema: "reallyme.zk.crates_preflight.v4",
  crates: packageArchives,
  repository,
  workflow: "crates-package-preflight.yml",
  run_id: runId,
  run_attempt: runAttempt,
  release_sha: releaseSha,
  version,
};

try {
  mkdirSync(OUTPUT_DIRECTORY, { recursive: true });
  writeFileSync(OUTPUT_PATH, `${JSON.stringify(attestation, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
} catch {
  fail("attestation-write-failed");
}
console.log("reviewed crates package attestation written");
