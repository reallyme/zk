// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { CiScopeError, classifyChangedPaths, fullCiScope, requireCiResults } from "./ci-change-scope.mjs";

const allJobs = ["rust-checks", "workspace-tests", "package-archives", "semver", "security-mutations",
  "public-crate-msrv", "swift-package", "kotlin-package", "android-target", "ios-target",
  "production-circuits", "public-artifacts"];
const allResults = (value) => Object.fromEntries(allJobs.map((job) => [job, value]));

test("documentation-only and empty changes select no expensive lanes", () => {
  for (const paths of [[], ["README.md", "docs/rust-publishing.md"]]) {
    assert.deepEqual(classifyChangedPaths(paths), {
      source: false, swift: false, android: false, ios: false, circuits: false,
    });
  }
});

test("package changes select their own platform without unrelated proving", () => {
  for (const path of ["packages/swift/Sources/Kit.swift", "Package.swift", "Package.resolved"]) {
    assert.deepEqual(classifyChangedPaths([path]), {
      source: true, swift: true, android: false, ios: false, circuits: false,
    });
  }
  assert.deepEqual(classifyChangedPaths(["packages/kotlin/src/Kit.kt"]), {
    source: true, swift: false, android: true, ios: false, circuits: false,
  });
  for (const path of ["packages/bbjs-provider/src/index.mjs", "fuzz/fuzz_targets/proof.rs", "deny.toml"]) {
    assert.deepEqual(classifyChangedPaths([path]), {
      source: true, swift: false, android: false, ios: false, circuits: false,
    });
  }
});

test("shared source, tools, locks, fixtures, and unknown roots select every lane", () => {
  for (const path of ["Cargo.lock", "Cargo.toml", ".cargo/config.toml", "rust-toolchain.toml",
    "crates/api/src/circuit.rs", "crates/noir-witness-core/src/lib.rs", "crates/backend-bb/src/lib.rs",
    "crates/proto/proto/schema.proto", "circuits/lib/src/lib.nr", "circuits/toolchain-lock.json",
    "vectors/binding.json", "provider_manifest.json", "scripts/prove.sh", ".github/workflows/rust-ci.yml",
    "docs/provenance/fixes.tsv", "requirements-circuits-ci.txt", "new-package/source.rs"]) {
    assert.deepEqual(classifyChangedPaths([path]), fullCiScope(), path);
  }
  const combined = classifyChangedPaths(["packages/swift/Source.swift", "packages/kotlin/Source.kt"]);
  assert.equal(combined.swift, true);
  assert.equal(combined.android, true);
  assert.equal(combined.circuits, false);
});

test("CI evidence changes retain source validation without unrelated native builds", () => {
  const paths = ["release-readiness-policy.lock.json", "scripts/verify_required_ci.mjs",
    "scripts/verify_required_ci.test.mjs", "scripts/ci-change-scope.mjs", "scripts/ci-change-scope.test.mjs",
    "scripts/select-ci-scope.mjs", "scripts/require-ci-results.mjs", "scripts/ci-workflow-policy.test.mjs",
    ".github/workflows/crates-package-preflight.yml", ".github/workflows/crates-release.yml",
    "scripts/check_release_readiness.mjs", "scripts/check_release_readiness.test.mjs",
    "scripts/check-release-readiness-policy-lock.mjs", "scripts/check-release-readiness-policy-lock.test.mjs",
    "scripts/verify_release_source.mjs", "scripts/verify_release_source.test.mjs",
    "scripts/verify_release_attestation.mjs", "scripts/verify_release_attestation.test.mjs",
    "scripts/write_release_attestation.mjs", "scripts/package-diagnostics.mjs",
    "scripts/package-diagnostics.test.mjs", "scripts/package-inventory-policy.mjs",
    "scripts/crate-artifact-downloads.test.mjs",
    "scripts/package-inventory-policy.test.mjs", "scripts/publish-crates-in-order.mjs",
    "scripts/publish-crates-in-order.test.mjs"];
  for (const path of paths) {
    assert.deepEqual(classifyChangedPaths([path]), {
      source: true, swift: false, android: false, ios: false, circuits: false,
    }, path);
    assert.deepEqual(classifyChangedPaths([path, "crates/backend-bb/src/lib.rs"]), fullCiScope());
  }
  const results = allResults("success");
  for (const job of ["swift-package", "kotlin-package", "android-target", "ios-target",
    "production-circuits", "public-artifacts"]) results[job] = "skipped";
  assert.doesNotThrow(() => requireCiResults(classifyChangedPaths(paths), results));
  results["rust-checks"] = "skipped";
  assert.throws(() => requireCiResults(classifyChangedPaths(paths), results), CiScopeError);
});

test("malformed and oversized paths cannot disable validation", () => {
  for (const paths of [null, {}, [null], [""], ["../secret"], ["/tmp/source"], ["a//b"],
    ["a/./b"], ["a\0b"], ["a".repeat(4_097)], new Array(100_001).fill("README.md"),
    ["Cargo.toml", "../invalid-after-full-scope"]]) {
    assert.throws(() => classifyChangedPaths(paths), CiScopeError);
  }
  // Git filenames may contain whitespace, Unicode, and newlines. They select
  // conservative coverage rather than being split into fabricated paths.
  assert.deepEqual(classifyChangedPaths(["new/é\nsource.rs"]), fullCiScope());
});

test("every required job must succeed; only deliberately unselected jobs may skip", () => {
  requireCiResults(fullCiScope(), allResults("success"));
  const docs = classifyChangedPaths(["README.md"]);
  requireCiResults(docs, allResults("skipped"));
  for (const job of allJobs) {
    for (const value of ["skipped", "failure", "cancelled", "", undefined]) {
      assert.throws(() => requireCiResults(fullCiScope(), { ...allResults("success"), [job]: value }), CiScopeError);
    }
    assert.throws(() => requireCiResults(docs, { ...allResults("skipped"), [job]: "failure" }), CiScopeError);
  }
  assert.throws(() => requireCiResults({}, allResults("success")), CiScopeError);
  assert.throws(() => requireCiResults(fullCiScope(), {}), CiScopeError);
  assert.throws(() => requireCiResults(fullCiScope(), { ...allResults("success"), extra: "success" }), CiScopeError);
  const kotlin = classifyChangedPaths(["packages/kotlin/Source.kt"]);
  const selected = { ...allResults("success"), "swift-package": "skipped", "ios-target": "skipped", "production-circuits": "skipped" };
  requireCiResults(kotlin, selected);
  assert.throws(() => requireCiResults(kotlin, { ...selected, "public-artifacts": "skipped" }), CiScopeError);
});

test("scope adapter preserves NUL-delimited filenames and fails on Git errors", () => {
  const root = mkdtempSync(join(tmpdir(), "zk-ci-scope-"));
  const script = fileURLToPath(new URL("./select-ci-scope.mjs", import.meta.url));
  try {
    const bin = join(root, "bin");
    mkdirSync(bin);
    const git = join(bin, "git");
    writeFileSync(git, '#!/usr/bin/env node\nprocess.stdout.write(Buffer.from(process.env.TEST_DIFF_BASE64 ?? "", "base64")); process.exitCode = Number(process.env.TEST_GIT_STATUS ?? 0);\n');
    chmodSync(git, 0o755);
    const run = (overrides = {}) => {
      const output = join(root, "output");
      writeFileSync(output, "");
      const result = spawnSync(process.execPath, [script], {
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, GITHUB_OUTPUT: output,
          CI_EVENT_NAME: "pull_request", CI_BASE_SHA: "1".repeat(40), CI_HEAD_SHA: "2".repeat(40),
          TEST_DIFF_BASE64: Buffer.from("packages/kotlin/Source.kt\0").toString("base64"), ...overrides },
      });
      return { ...result, output: readFileSync(output, "utf8") };
    };
    const kotlin = run();
    assert.equal(kotlin.status, 0, kotlin.stderr);
    assert.match(kotlin.output, /android=true\n/u);
    assert.match(kotlin.output, /circuits=false\n/u);
    for (const overrides of [{ TEST_GIT_STATUS: "1" }, { TEST_DIFF_BASE64: Buffer.from("unterminated").toString("base64") },
      { CI_BASE_SHA: "--exec=malicious" }, { CI_EVENT_NAME: "workflow_run" }]) {
      const rejected = run(overrides);
      assert.equal(rejected.status, 1);
      assert.equal(rejected.output, "");
    }
    for (const overrides of [{ CI_EVENT_NAME: "workflow_dispatch", CI_BASE_SHA: "" },
      { CI_EVENT_NAME: "push", CI_BASE_SHA: "0".repeat(40) }]) {
      const full = run(overrides);
      assert.equal(full.status, 0);
      assert.equal(full.output.includes("false"), false);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("aggregate adapter fails when scope discovery or a selected job did not succeed", () => {
  const script = fileURLToPath(new URL("./require-ci-results.mjs", import.meta.url));
  const environment = { ...process.env, RESULT_CHANGES: "success" };
  for (const lane of ["source", "swift", "android", "ios", "circuits"]) {
    environment[`SCOPE_${lane.toUpperCase()}`] = "true";
  }
  for (const job of allJobs) environment[`RESULT_${job.replaceAll("-", "_").toUpperCase()}`] = "success";
  const run = (overrides) => spawnSync(process.execPath, [script], {
    encoding: "utf8", env: { ...environment, ...overrides },
  });
  assert.equal(run({}).status, 0);
  for (const invalid of [{ RESULT_CHANGES: "failure" }, { RESULT_CHANGES: "skipped" },
    { SCOPE_CIRCUITS: "" }, { RESULT_PRODUCTION_CIRCUITS: "skipped" }, { RESULT_ANDROID_TARGET: "cancelled" }]) {
    assert.equal(run(invalid).status, 1);
  }
});
