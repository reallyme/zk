// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const MAX_CHANGED_PATHS = 100_000;
const MAX_PATH_BYTES = 4_096;
const SOURCE_POLICY_PATHS = new Set([
  "release-readiness-policy.lock.json",
  "scripts/verify_required_ci.mjs",
  "scripts/verify_required_ci.test.mjs",
  "scripts/ci-change-scope.mjs",
  "scripts/ci-change-scope.test.mjs",
  "scripts/select-ci-scope.mjs",
  "scripts/require-ci-results.mjs",
  "scripts/ci-workflow-policy.test.mjs",
]);

export class CiScopeError extends Error {
  constructor(code) {
    super(code);
    this.name = "CiScopeError";
    this.code = code;
  }
}

export const fullCiScope = () => ({ source: true, swift: true, android: true, ios: true, circuits: true });

// Unknown source roots deliberately select every lane. Adding a new dependency
// must not silently remove platform or proof coverage until its scope is reviewed.
export function classifyChangedPaths(paths) {
  if (!Array.isArray(paths) || paths.length > MAX_CHANGED_PATHS) {
    throw new CiScopeError("invalid-path-list");
  }
  const scope = { source: false, swift: false, android: false, ios: false, circuits: false };
  for (const path of paths) {
    if (typeof path !== "string" || path.length === 0 ||
        Buffer.byteLength(path) > MAX_PATH_BYTES || path.includes("\0") ||
        path.startsWith("/") || path.split("/").some((part) => part === ".." || part === "." || part === "")) {
      throw new CiScopeError("invalid-changed-path");
    }
    if (path.endsWith(".md")) continue;
    scope.source = true;
    // These files govern validation and release evidence, not runtime or
    // circuit inputs. Source policy tests cover them; a manual qualification
    // still selects every lane. Mixed runtime changes retain full coverage.
    if (SOURCE_POLICY_PATHS.has(path)) continue;
    if (path.startsWith("packages/swift/") || path === "Package.swift" || path === "Package.resolved") {
      scope.swift = true;
    } else if (path.startsWith("packages/kotlin/")) {
      scope.android = true;
    } else if (path.startsWith("packages/bbjs-provider/") || path.startsWith("fuzz/") || path === "deny.toml") {
      continue;
    } else {
      Object.assign(scope, fullCiScope());
    }
  }
  return scope;
}

export function requireCiResults(scope, results) {
  if (scope === null || typeof scope !== "object" ||
      Object.keys(scope).length !== 5 ||
      ["source", "swift", "android", "ios", "circuits"].some((lane) =>
        !Object.hasOwn(scope, lane) || typeof scope[lane] !== "boolean")) {
    throw new CiScopeError("invalid-lane-scope");
  }
  const requirements = new Map([
    ["rust-checks", scope.source], ["workspace-tests", scope.source],
    ["package-archives", scope.source], ["semver", scope.source],
    ["security-mutations", scope.source], ["public-crate-msrv", scope.source],
    ["swift-package", scope.swift], ["kotlin-package", scope.android],
    ["android-target", scope.android], ["ios-target", scope.ios],
    ["production-circuits", scope.circuits],
    ["public-artifacts", scope.android || scope.circuits],
  ]);
  if (results === null || typeof results !== "object" || Array.isArray(results) ||
      Object.keys(results).length !== requirements.size) {
    throw new CiScopeError("invalid-job-results");
  }
  for (const [job, required] of requirements) {
    const result = results[job];
    // A skipped dependency is admissible only when the classifier excluded it.
    // Cancellations and unexpected skips always fail the aggregate check.
    if (!Object.hasOwn(results, job) || (result !== "success" && !(required === false && result === "skipped"))) {
      throw new CiScopeError("required-job-not-successful");
    }
  }
}
