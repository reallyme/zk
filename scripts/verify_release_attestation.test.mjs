#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  ReleaseAttestationError,
  localPackageArchives,
  selectLatestPreflightRun,
  verifyAttestationDocument,
  verifyWorkflowRun,
  verifyReleaseAttestation,
} from "./verify_release_attestation.mjs";

import { PUBLIC_CRATE_NAMES } from "./public-crates.mjs";

const releaseSha = "a".repeat(40);
const expected = Object.freeze({
  repository: "reallyme/zk",
  runId: 123,
  releaseSha,
  releaseVersion: "0.2.1",
});
const attestation = (overrides = {}) => ({
  schema: "reallyme.zk.crates_preflight.v4",
  crates: PUBLIC_CRATE_NAMES.map((name, index) => ({
    file: `${name}-${expected.releaseVersion}.crate`, sha256: String(index + 1).repeat(64), size: 101 + index,
  })),
  repository: expected.repository,
  workflow: "crates-package-preflight.yml",
  run_id: expected.runId,
  run_attempt: 1,
  release_sha: releaseSha,
  version: expected.releaseVersion,
  ...overrides,
});
const workflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  ...overrides,
});
const listedWorkflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  display_title: `Crates package preflight ${expected.releaseVersion} @ ${releaseSha}`,
  ...overrides,
});

test("reviewed attestation accepts the exact run, SHA, and version", () => {
  assert.doesNotThrow(() => verifyAttestationDocument(attestation(), expected));
  assert.doesNotThrow(() =>
    verifyWorkflowRun(workflowRun(), {
      workflowId: 456,
      runId: expected.runId,
      releaseSha,
    }),
  );
});

test("package attestation is produced without global CI prerequisite run IDs", () => {
  const root = mkdtempSync(join(tmpdir(), "zk-package-attestation-"));
  try {
    const packageDirectory = join(root, "target", "package");
    mkdirSync(packageDirectory, { recursive: true });
    for (const name of PUBLIC_CRATE_NAMES) {
      writeFileSync(join(packageDirectory, `${name}-${expected.releaseVersion}.crate`), name);
    }
    const env = {
      ...process.env,
      CARGO_TARGET_DIR: join(root, "target"),
      GITHUB_REPOSITORY: expected.repository,
      GITHUB_RUN_ID: String(expected.runId),
      GITHUB_RUN_ATTEMPT: "1",
      RELEASE_SHA: releaseSha,
      RELEASE_VERSION: expected.releaseVersion,
    };
    for (const key of ["FUZZ_RUN_ID", "PROTOBUF_CI_RUN_ID", "RUST_CI_RUN_ID"]) delete env[key];
    const script = fileURLToPath(new URL("./write_release_attestation.mjs", import.meta.url));
    const result = spawnSync(process.execPath, [script], { cwd: root, env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const document = JSON.parse(readFileSync(join(root, "release-attestation", "crates-preflight.json"), "utf8"));
    assert.equal(Object.hasOwn(document, "prerequisites"), false);
    verifyAttestationDocument(document, {
      ...expected,
      packageArchives: localPackageArchives(expected.releaseVersion, { CARGO_TARGET_DIR: join(root, "target") }),
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("attestation rejects mismatched inputs and unreviewed fields", () => {
  for (const candidate of [
    attestation({ version: "0.1.0" }),
    attestation({ release_sha: "b".repeat(40) }),
    attestation({ run_id: 124 }),
    attestation({ extra: true }),
    attestation({ schema: "reallyme.zk.crates_preflight.v3" }),
    attestation({ prerequisites: { fuzz: 11 } }),
    attestation({ crates: [{ file: "wrong.crate", sha256: "1".repeat(64), size: 1 }] }),
  ]) {
    assert.throws(
      () => verifyAttestationDocument(candidate, expected),
      ReleaseAttestationError,
    );
  }
});

test("reviewed archive loading rejects symbolic links", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-reviewed-archives-"));
  try {
    for (const name of PUBLIC_CRATE_NAMES) {
      writeFileSync(join(directory, `${name}-${expected.releaseVersion}.crate`), name);
    }
    const archives = localPackageArchives(expected.releaseVersion, {
      RELEASE_ATTESTATION_CRATE_DIRECTORY: directory,
    });
    assert.equal(archives.length, 5);
    assert.ok(archives.every((archive) => archive.size > 0));

    const linkedArchive = join(directory, `reallyme-zk-api-${expected.releaseVersion}.crate`);
    unlinkSync(linkedArchive);
    symlinkSync(join(directory, `reallyme-zk-proto-${expected.releaseVersion}.crate`), linkedArchive);
    assert.throws(
      () =>
        localPackageArchives(expected.releaseVersion, {
          RELEASE_ATTESTATION_CRATE_DIRECTORY: directory,
        }),
      { name: "ReleaseAttestationError", code: "invalid-local-crate-archive" },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failed, rerun, wrong-branch, and wrong-workflow runs fail closed", () => {
  for (const candidate of [
    workflowRun({ conclusion: "failure" }),
    workflowRun({ run_attempt: 2 }),
    workflowRun({ head_branch: "feature" }),
    workflowRun({ workflow_id: 457 }),
    workflowRun({ path: ".github/workflows/other.yml@refs/heads/main" }),
  ]) {
    assert.throws(
      () =>
        verifyWorkflowRun(candidate, {
          workflowId: 456,
          runId: expected.runId,
          releaseSha,
        }),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution selects the latest exact successful preflight", () => {
  const latest = selectLatestPreflightRun(
    {
      workflow_runs: [
        listedWorkflowRun({ id: 121 }),
        listedWorkflowRun({ id: 123 }),
        listedWorkflowRun({ id: 124, head_sha: "b".repeat(40) }),
      ],
    },
    {
      workflowId: 456,
      releaseSha,
      releaseVersion: expected.releaseVersion,
    },
  );
  assert.equal(latest.id, 123);
});

test("newer failed, running, wrong-version, and rerun preflights fail closed", () => {
  const rejectedLatestRuns = [
    listedWorkflowRun({ id: 124, conclusion: "failure" }),
    listedWorkflowRun({ id: 124, conclusion: null, status: "in_progress" }),
    listedWorkflowRun({
      id: 124,
      display_title: `Crates package preflight 0.1.0 @ ${releaseSha}`,
    }),
    listedWorkflowRun({ id: 124, run_attempt: 2 }),
  ];
  for (const rejected of rejectedLatestRuns) {
    assert.throws(
      () =>
        selectLatestPreflightRun(
          { workflow_runs: [listedWorkflowRun({ id: 123 }), rejected] },
          {
            workflowId: 456,
            releaseSha,
            releaseVersion: expected.releaseVersion,
          },
        ),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution rejects missing and malformed workflow results", () => {
  for (const candidate of [{}, { workflow_runs: [] }, { workflow_runs: [null] }]) {
    assert.throws(
      () =>
        selectLatestPreflightRun(candidate, {
          workflowId: 456,
          releaseSha,
          releaseVersion: expected.releaseVersion,
        }),
      ReleaseAttestationError,
    );
  }
});

test("waiting rejects zero polling intervals before querying GitHub", () => {
  assert.throws(() => verifyReleaseAttestation({ env: {
    GITHUB_REPOSITORY: expected.repository,
    RELEASE_SHA: releaseSha,
    RELEASE_VERSION: expected.releaseVersion,
    GITHUB_SHA: releaseSha,
    GH_TOKEN: "test-placeholder",
    RELEASE_ATTESTATION_WAIT_SECONDS: "60",
    RELEASE_ATTESTATION_POLL_SECONDS: "0",
  } }), { name: "ReleaseAttestationError", code: "invalid-release-attestation-poll-seconds" });
});
