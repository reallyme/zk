#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { CiScopeError, requireCiResults } from "./ci-change-scope.mjs";

try {
  if (process.env.RESULT_CHANGES !== "success") throw new CiScopeError("scope-discovery-not-successful");
  const scope = Object.create(null);
  for (const lane of ["source", "swift", "android", "ios", "circuits"]) {
    const value = process.env[`SCOPE_${lane.toUpperCase()}`];
    if (value !== "true" && value !== "false") throw new CiScopeError("invalid-lane-scope");
    scope[lane] = value === "true";
  }
  const results = Object.create(null);
  for (const job of ["rust-checks", "workspace-tests", "package-archives", "semver", "security-mutations",
    "public-crate-msrv", "swift-package", "kotlin-package", "android-target", "ios-target",
    "production-circuits", "public-artifacts"]) {
    results[job] = process.env[`RESULT_${job.replaceAll("-", "_").toUpperCase()}`];
  }
  requireCiResults(scope, results);
} catch (error) {
  const code = error instanceof CiScopeError ? error.code : "result-verification-failed";
  console.error(`CI result verification failed: ${code}`);
  process.exitCode = 1;
}
