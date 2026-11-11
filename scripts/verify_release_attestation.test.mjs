#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ReleaseAttestationError,
  localPackageArchives,
  selectLatestPreflightRun,
  verifyAttestationDocument,
  verifyWorkflowRun,
  verifyReleaseAttestation,
} from "./verify_release_attestation.mjs";

const releaseSha = "a".repeat(40);
const expected = Object.freeze({
  repository: "reallyme/zk",
  runId: 123,
  releaseSha,
  releaseVersion: "0.2.1",
});
const attestation = (overrides = {}) => ({
  schema: "reallyme.zk.crates_preflight.v3",
  crates: [
    { file: "reallyme-zk-api-0.2.1.crate", sha256: "1".repeat(64), size: 101 },
    { file: "reallyme-zk-artifacts-0.2.1.crate", sha256: "2".repeat(64), size: 102 },
    { file: "reallyme-zk-proto-0.2.1.crate", sha256: "3".repeat(64), size: 103 },
  ],
  prerequisites: {
    fuzz: 11,
    protobuf_ci: 12,
    rust_ci: 13,
  },
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

test("attestation rejects mismatched inputs and unreviewed fields", () => {
  for (const candidate of [
    attestation({ version: "0.1.0" }),
    attestation({ release_sha: "b".repeat(40) }),
    attestation({ run_id: 124 }),
    attestation({ extra: true }),
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
    for (const name of ["reallyme-zk-api", "reallyme-zk-artifacts", "reallyme-zk-proto"]) {
      writeFileSync(join(directory, `${name}-${expected.releaseVersion}.crate`), name);
    }
    const archives = localPackageArchives(expected.releaseVersion, {
      RELEASE_ATTESTATION_CRATE_DIRECTORY: directory,
    });
    assert.equal(archives.length, 3);
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
