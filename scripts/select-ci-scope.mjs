#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { CiScopeError, classifyChangedPaths, fullCiScope } from "./ci-change-scope.mjs";

const MAX_DIFF_BYTES = 16 * 1024 * 1024;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const EMPTY_COMMIT = "0".repeat(40);

try {
  const { CI_EVENT_NAME: event, CI_BASE_SHA: base, CI_HEAD_SHA: head, GITHUB_OUTPUT: output } = process.env;
  if (typeof output !== "string" || output.length === 0) throw new CiScopeError("missing-output-path");
  let scope;
  if (event === "workflow_dispatch") {
    scope = fullCiScope();
  } else {
    if ((event !== "push" && event !== "pull_request") ||
        !COMMIT_PATTERN.test(base ?? "") || !COMMIT_PATTERN.test(head ?? "")) {
      throw new CiScopeError("invalid-diff-identity");
    }
    if (base === EMPTY_COMMIT) {
      scope = fullCiScope();
    } else {
      const result = spawnSync("git", ["diff", "--name-only", "--no-renames", "-z", base, head, "--"], {
        encoding: "utf8", maxBuffer: MAX_DIFF_BYTES, stdio: ["ignore", "pipe", "ignore"],
      });
      if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== "string" ||
          (result.stdout.length !== 0 && !result.stdout.endsWith("\0"))) {
        throw new CiScopeError("changed-path-discovery-failed");
      }
      scope = classifyChangedPaths(result.stdout.length === 0 ? [] : result.stdout.slice(0, -1).split("\0"));
    }
  }
  appendFileSync(output, Object.entries(scope).map(([lane, required]) => `${lane}=${required}\n`).join(""));
} catch (error) {
  const code = error instanceof CiScopeError ? error.code : "scope-selection-failed";
  console.error(`CI scope selection failed: ${code}`);
  process.exitCode = 1;
}
