// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { verifySwiftReleasePreflight } from "./verify_swift_release_preflight.mjs";

const sha = "a".repeat(40);
const repository = "reallyme/zk";
const workflowPath = ".github/workflows/swift-package-preflight.yml";
const root = `repos/${repository}`;
const runPath = `${root}/actions/workflows/41/runs?branch=main&event=workflow_dispatch&head_sha=${sha}&per_page=100`;
const artifactPath = `${root}/actions/runs/57/artifacts?per_page=100`;
const env = Object.freeze({
  GITHUB_REPOSITORY: repository,
  GITHUB_SHA: sha,
  RELEASE_SHA: sha,
  RELEASE_VERSION: "0.3.0",
});

function fixture() {
  const timestamp = new Date().toISOString();
  const run = {
    id: 57,
    workflow_id: 41,
    path: workflowPath,
    event: "workflow_dispatch",
    head_branch: "main",
    head_sha: sha,
    status: "completed",
    conclusion: "success",
    run_attempt: 1,
    created_at: timestamp,
    updated_at: timestamp,
    display_title: "Swift package preflight 0.3.0",
  };
  const artifact = {
    id: 71,
    name: `swift-xcframework-0.3.0-${sha}`,
    expired: false,
    digest: `sha256:${"b".repeat(64)}`,
  };
  const main = { ref: "refs/heads/main", object: { sha } };
  const runs = { total_count: 1, workflow_runs: [run] };
  const artifacts = { total_count: 1, artifacts: [artifact] };
  const responses = new Map([
    [`${root}/git/ref/heads/main`, main],
    [`${root}/actions/workflows/swift-package-preflight.yml`, { id: 41, path: workflowPath }],
    [runPath, runs],
    [artifactPath, artifacts],
  ]);
  const query = (path) => {
    assert.ok(responses.has(path), path);
    return responses.get(path);
  };
  return { run, artifact, main, runs, artifacts, query };
}

test("selects the successful Swift preflight and the exact commit's archive", () => {
  const { query } = fixture();
  assert.equal(verifySwiftReleasePreflight({ env, query }), 57);
  assert.equal(verifySwiftReleasePreflight({ env: { ...env, SWIFT_PREFLIGHT_RUN_ID: "57" }, query }), 57);
});

test("rejects release input for a different workflow commit or moved main", () => {
  const { main, query } = fixture();
  assert.throws(
    () => verifySwiftReleasePreflight({ env: { ...env, GITHUB_SHA: "c".repeat(40) }, query }),
    /invalid-swift-release-input/u,
  );
  main.object.sha = "c".repeat(40);
  assert.throws(() => verifySwiftReleasePreflight({ env, query }), /release-sha-is-not-current-main/u);
});

test("requires the newest exact-commit Swift run to succeed", () => {
  const { runs, run, query } = fixture();
  runs.workflow_runs.push({ ...run, id: 58, conclusion: "failure" });
  runs.total_count = 2;
  assert.throws(() => verifySwiftReleasePreflight({ env, query }), /required-ci-run-failed/u);
});

test("rejects a preflight title for a different release version", () => {
  const { run, query } = fixture();
  run.display_title = "Swift package preflight 0.3.1";
  assert.throws(() => verifySwiftReleasePreflight({ env, query }), /swift-preflight-version-mismatch/u);
});

test("rejects expired, missing, and ambiguous artifacts", () => {
  const { artifact, artifacts, query } = fixture();
  artifact.expired = true;
  assert.throws(() => verifySwiftReleasePreflight({ env, query }), /missing-or-invalid-swift-preflight-artifact/u);
  artifacts.artifacts = [];
  artifacts.total_count = 0;
  assert.throws(() => verifySwiftReleasePreflight({ env, query }), /missing-or-invalid-swift-preflight-artifact/u);
  artifact.expired = false;
  artifacts.artifacts = [artifact, { ...artifact, id: 72 }];
  artifacts.total_count = 2;
  assert.throws(() => verifySwiftReleasePreflight({ env, query }), /missing-or-invalid-swift-preflight-artifact/u);
});

test("rejects a changed preflight run before publication", () => {
  const { query } = fixture();
  assert.throws(
    () => verifySwiftReleasePreflight({ env: { ...env, SWIFT_PREFLIGHT_RUN_ID: "56" }, query }),
    /swift-preflight-run-changed/u,
  );
});
