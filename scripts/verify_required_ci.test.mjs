#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  REQUIRED_WORKFLOWS,
  RequiredCiError,
  formatRequiredCiOutputs,
  resolveRequiredCiWithWait,
  selectRequiredCiRun,
} from "./verify_required_ci.mjs";

const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_ID = 41;
const NOW_MS = Date.parse("2026-09-29T12:00:00Z");

const workflowRun = (overrides = {}) => ({
  conclusion: "success",
  created_at: "2026-09-29T10:00:00Z",
  event: "push",
  head_branch: "main",
  head_sha: RELEASE_SHA,
  id: 100,
  path: ".github/workflows/rust-ci.yml",
  run_attempt: 1,
  status: "completed",
  updated_at: "2026-09-29T10:30:00Z",
  workflow_id: WORKFLOW_ID,
  ...overrides,
});

test("release qualification requires a complete manual Rust run", () => {
  const rust = REQUIRED_WORKFLOWS.find((requirement) => requirement.workflowFile === "rust-ci.yml");
  assert.ok(rust);
  assert.deepEqual(rust.allowedEvents, ["workflow_dispatch"]);
  const expected = { ...rust, releaseSha: RELEASE_SHA, workflowId: WORKFLOW_ID };
  assert.throws(() => selectRequiredCiRun({ workflow_runs: [workflowRun()] }, expected, NOW_MS),
    (error) => error instanceof RequiredCiError && error.code === "missing-required-ci-run:rust-ci.yml");
  const manual = workflowRun({ id: 101, event: "workflow_dispatch" });
  assert.equal(selectRequiredCiRun({ workflow_runs: [manual] }, expected, NOW_MS).id, 101);
  assert.equal(selectRequiredCiRun({ workflow_runs: [
    workflowRun({ conclusion: "failure" }), manual,
  ] }, expected, NOW_MS).id, 101);
});

test("zero-wait release admission never sleeps or polls pending evidence", () => {
  let attempts = 0;
  assert.throws(() => resolveRequiredCiWithWait({
    pollSeconds: 20, releaseSha: RELEASE_SHA, repository: "reallyme/zk", waitSeconds: 0,
    now: () => NOW_MS,
    resolve: () => { attempts += 1; throw new RequiredCiError("required-ci-run-pending:rust-ci.yml"); },
    sleep: () => assert.fail("zero-wait admission must not sleep"),
  }), RequiredCiError);
  assert.equal(attempts, 1);
});

test("accepts exact successful push and manually dispatched CI evidence", () => {
  for (const event of ["push", "workflow_dispatch"]) {
    const selected = selectRequiredCiRun(
      { workflow_runs: [workflowRun({ event })] },
      {
        releaseSha: RELEASE_SHA,
        allowedEvents: ["push", "workflow_dispatch"],
        workflowFile: "rust-ci.yml",
        workflowId: WORKFLOW_ID,
      },
      NOW_MS,
    );
    assert.equal(selected.event, event);
  }
});

test("the latest qualifying run must be completed and successful", () => {
  for (const latest of [
    workflowRun({ conclusion: "failure", id: 101 }),
    workflowRun({ conclusion: null, id: 101, status: "in_progress" }),
    workflowRun({ conclusion: "cancelled", id: 101 }),
    workflowRun({ conclusion: "skipped", id: 101 }),
  ]) {
    assert.throws(
      () =>
        selectRequiredCiRun(
          { workflow_runs: [workflowRun(), latest] },
          {
            releaseSha: RELEASE_SHA,
            allowedEvents: ["push", "workflow_dispatch"],
            workflowFile: "rust-ci.yml",
            workflowId: WORKFLOW_ID,
          },
          NOW_MS,
        ),
      RequiredCiError,
    );
  }
});

test("later successful qualification supersedes an earlier failure", () => {
  const expected = {
    releaseSha: RELEASE_SHA,
    allowedEvents: ["push", "workflow_dispatch"],
    workflowFile: "rust-ci.yml",
    workflowId: WORKFLOW_ID,
  };
  assert.equal(
    selectRequiredCiRun({ workflow_runs: [
      workflowRun({ id: 100, conclusion: "failure" }),
      workflowRun({ id: 101, event: "workflow_dispatch" }),
    ] }, expected, NOW_MS).id, 101,
  );
  assert.throws(
    () => selectRequiredCiRun({ total_count: 101, workflow_runs: [workflowRun()] }, expected, NOW_MS),
    (error) => error instanceof RequiredCiError && error.code === "incomplete-required-ci-run-list:rust-ci.yml",
  );
});

test("a successful retry qualifies, while a newer failed retry blocks admission", () => {
  const expected = {
    releaseSha: RELEASE_SHA, allowedEvents: ["workflow_dispatch"],
    workflowFile: "rust-ci.yml", workflowId: WORKFLOW_ID,
  };
  const prior = workflowRun({ id: 101, event: "workflow_dispatch", conclusion: "failure" });
  const successful = workflowRun({ id: 101, event: "workflow_dispatch", run_attempt: 2 });
  const selected = selectRequiredCiRun({ workflow_runs: [prior, successful] }, expected, NOW_MS);
  assert.equal(selected.id, 101);
  assert.equal(selected.runAttempt, 2);
  assert.throws(() => selectRequiredCiRun({ workflow_runs: [successful,
    workflowRun({ id: 101, event: "workflow_dispatch", run_attempt: 3, conclusion: "failure" }),
  ] }, expected, NOW_MS),
  (error) => error instanceof RequiredCiError && error.code === "required-ci-run-failed:rust-ci.yml");
});

test("rejects evidence from another workflow, branch, commit, or event", () => {
  const mismatches = [
    { workflow_id: WORKFLOW_ID + 1 },
    { path: ".github/workflows/fuzz.yml" },
    { head_branch: "release" },
    { head_sha: "fedcba9876543210fedcba9876543210fedcba98" },
    { event: "pull_request" },
  ];
  for (const mismatch of mismatches) {
    assert.throws(
      () =>
        selectRequiredCiRun(
          { workflow_runs: [workflowRun(mismatch)] },
          {
            releaseSha: RELEASE_SHA,
            allowedEvents: ["push", "workflow_dispatch"],
            workflowFile: "rust-ci.yml",
            workflowId: WORKFLOW_ID,
          },
          NOW_MS,
        ),
      RequiredCiError,
    );
  }
});

test("rejects stale, future, and internally inconsistent timestamps", () => {
  const invalidTimes = [
    { created_at: "2026-09-20T10:00:00Z", updated_at: "2026-09-20T11:00:00Z" },
    { created_at: "2026-09-20T10:00:00Z", updated_at: "2026-09-29T11:00:00Z", run_attempt: 2 },
    { created_at: "2026-09-29T13:00:00Z", updated_at: "2026-09-29T13:01:00Z" },
    { created_at: "2026-09-29T11:00:00Z", updated_at: "2026-09-29T10:00:00Z" },
    { updated_at: "not-a-timestamp" },
  ];
  for (const invalidTime of invalidTimes) {
    assert.throws(
      () =>
        selectRequiredCiRun(
          { workflow_runs: [workflowRun(invalidTime)] },
          {
            releaseSha: RELEASE_SHA,
            allowedEvents: ["push", "workflow_dispatch"],
            workflowFile: "rust-ci.yml",
            workflowId: WORKFLOW_ID,
          },
          NOW_MS,
        ),
      RequiredCiError,
    );
  }
});

test("waits only for missing or in-progress evidence", () => {
  let now = 0;
  let attempts = 0;
  const sleeps = [];
  const selected = resolveRequiredCiWithWait({
    pollSeconds: 3,
    releaseSha: RELEASE_SHA,
    repository: "reallyme/zk",
    waitSeconds: 10,
    now: () => now,
    resolve: () => {
      attempts += 1;
      if (attempts < 3) {
        throw new RequiredCiError("required-ci-run-pending:rust-ci.yml");
      }
      return [{ id: 91 }];
    },
    sleep: (seconds) => {
      sleeps.push(seconds);
      now += seconds * 1_000;
    },
  });
  assert.deepEqual(selected, [{ id: 91 }]);
  assert.deepEqual(sleeps, [3, 3]);

  assert.throws(
    () =>
      resolveRequiredCiWithWait({
        pollSeconds: 3,
        releaseSha: RELEASE_SHA,
        repository: "reallyme/zk",
        waitSeconds: 10,
        resolve: () => {
          throw new RequiredCiError("required-ci-run-failed:rust-ci.yml");
        },
      }),
    /required-ci-run-failed/u,
  );
});

test("formats every required workflow run as a stable GitHub output", () => {
  assert.equal(
    formatRequiredCiOutputs([{ id: 1 }, { id: 2 }, { id: 3 }]),
    [
      "rust_ci_run_id=1",
      "protobuf_ci_run_id=2",
      "fuzz_run_id=3",
    ].join("\n"),
  );
  assert.throws(() => formatRequiredCiOutputs([{ id: 1 }]), RequiredCiError);
});
