#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { RequiredCiError, selectRequiredCiRun } from "./verify_required_ci.mjs";

const WORKFLOW = "swift-package-preflight.yml";
const SHA = /^[0-9a-f]{40}$/u;
const VERSION = /^(?:0|[1-9][0-9]*)(?:[.](?:0|[1-9][0-9]*)){2}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const RUN_ID = /^[1-9][0-9]*$/u;

export class SwiftPreflightError extends Error {
  constructor(code) {
    super(code);
    this.name = "SwiftPreflightError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new SwiftPreflightError(code);
};

const queryGitHub = (path) => {
  const result = spawnSync("gh", ["api", path], {
    encoding: "utf8",
    maxBuffer: 1_048_576,
    timeout: 30_000,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error !== undefined || result.status !== 0) {
    fail("github-query-failed");
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail("invalid-github-response");
  }
};

export function verifySwiftReleasePreflight({ env = process.env, query = queryGitHub } = {}) {
  const {
    GITHUB_REPOSITORY: repository,
    GITHUB_SHA: workflowSha,
    RELEASE_SHA: releaseSha,
    RELEASE_VERSION: version,
    SWIFT_PREFLIGHT_RUN_ID: expectedRunId,
  } = env;
  if (
    typeof repository !== "string" || !REPOSITORY.test(repository) ||
    typeof releaseSha !== "string" || !SHA.test(releaseSha) || releaseSha !== workflowSha ||
    typeof version !== "string" || !VERSION.test(version)
  ) {
    fail("invalid-swift-release-input");
  }
  if (expectedRunId !== undefined && (typeof expectedRunId !== "string" || !RUN_ID.test(expectedRunId))) {
    fail("invalid-swift-preflight-run-id");
  }

  const root = `repos/${repository}`;
  const main = query(`${root}/git/ref/heads/main`);
  if (main?.ref !== "refs/heads/main" || main?.object?.sha !== releaseSha) {
    fail("release-sha-is-not-current-main");
  }
  const workflow = query(`${root}/actions/workflows/${WORKFLOW}`);
  if (!Number.isSafeInteger(workflow?.id) || workflow.id < 1 || workflow.path !== `.github/workflows/${WORKFLOW}`) {
    fail("invalid-swift-preflight-workflow");
  }

  const runs = query(`${root}/actions/workflows/${workflow.id}/runs?branch=main&event=workflow_dispatch&head_sha=${releaseSha}&per_page=100`);
  const run = selectRequiredCiRun(runs, {
    workflowFile: WORKFLOW,
    workflowId: workflow.id,
    allowedEvents: ["workflow_dispatch"],
    releaseSha,
  });
  if (expectedRunId !== undefined && String(run.id) !== expectedRunId) {
    fail("swift-preflight-run-changed");
  }
  const listedRun = runs.workflow_runs.find((candidate) => candidate.id === run.id);
  if (listedRun?.display_title !== `Swift package preflight ${version}`) {
    fail("swift-preflight-version-mismatch");
  }

  const inventory = query(`${root}/actions/runs/${run.id}/artifacts?per_page=100`);
  if (!Array.isArray(inventory?.artifacts) || inventory.total_count !== inventory.artifacts.length) {
    fail("invalid-swift-preflight-artifact-list");
  }
  const name = `swift-xcframework-${version}-${releaseSha}`;
  const matches = inventory.artifacts.filter((artifact) => artifact?.name === name);
  const artifact = matches[0];
  if (
    matches.length !== 1 || artifact.expired !== false ||
    !Number.isSafeInteger(artifact.id) || artifact.id < 1 ||
    typeof artifact.digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(artifact.digest)
  ) {
    fail("missing-or-invalid-swift-preflight-artifact");
  }
  return run.id;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const runId = verifySwiftReleasePreflight();
    if (process.env.GITHUB_OUTPUT) {
      appendFileSync(process.env.GITHUB_OUTPUT, `preflight_run_id=${runId}\n`, "utf8");
    }
    console.log("Reviewed Swift package preflight verified");
  } catch (error) {
    const code = error instanceof SwiftPreflightError
      ? error.code
      : error instanceof RequiredCiError ? error.message : "unexpected-failure";
    console.error(`Swift release preflight verification failed: ${code}`);
    process.exitCode = 1;
  }
}
