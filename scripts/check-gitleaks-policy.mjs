#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { appendFileSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const paths = [
  "crates/noir-witness-core/tests/circuit_boundary_contracts.rs",
  "packages/swift/Tests/ReallyMeZKTests/ReallyMeZKNativeTransportTestSupport.swift",
  "packages/swift/Tests/ReallyMeZKTests/ReallyMeZKStatusQualifiedClaimBundleTests.swift",
  "scripts/check-mobile-demo-fixture-pins.test.mjs",
  "scripts/generate-claim-family-fixtures.py",
  "scripts/stage-demo-mobile-assets.mjs",
  "scripts/proto-hardening/zk-scalar-policy.mjs",
  "scripts/test-claim-family-fixed-depth.py",
];

class ScannerPolicyError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

let temporary;
try {
  if (process.argv.length !== 3) throw new ScannerPolicyError("invalid-arguments");
  const binary = resolve(process.argv[2]);
  temporary = mkdtempSync(join(tmpdir(), "zk-gitleaks-policy-"));
  const fixtures = join(temporary, "fixtures");
  const report = join(temporary, "findings.json");
  for (const path of paths) {
    const destination = join(fixtures, path);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(root, path), destination);
  }
  const scan = (expectedPaths) => {
    const result = spawnSync(binary, ["dir", "--config", join(root, ".gitleaks.toml"),
      "--redact", "--no-banner", "--report-format", "json", "--report-path", report, "."],
    { cwd: fixtures, stdio: "ignore", timeout: 30_000 });
    if (result.error || result.status !== (expectedPaths.length === 0 ? 0 : 1)) {
      throw new ScannerPolicyError("unexpected-scan-status");
    }
    const findings = JSON.parse(readFileSync(report, "utf8"));
    if (!Array.isArray(findings) || findings.length !== expectedPaths.length ||
        findings.some((finding) => finding?.RuleID !== "generic-api-key" ||
          !expectedPaths.includes(finding?.File)) ||
        new Set(findings.map((finding) => finding.File)).size !== expectedPaths.length) {
      throw new ScannerPolicyError("unexpected-scan-findings");
    }
  };
  scan([]);
  // These opaque random test markers have no credential authority. A separate
  // marker in every allowlisted file proves the exceptions do not hide secrets.
  for (const path of paths) {
    appendFileSync(join(fixtures, path), `\napi_key = "${randomBytes(32).toString("hex")}"\n`);
  }
  scan(paths);
  // The public identifier is exempt only in its reviewed owning file.
  copyFileSync(join(root, paths[0]), join(fixtures, "control.rs"));
  scan([...paths, "control.rs"]);
  console.log("Secret scanner exceptions and positive detection verified");
} catch (error) {
  const code = error instanceof ScannerPolicyError ? error.code : "policy-check-failed";
  console.error(`secret scanner policy check failed: ${code}`);
  process.exitCode = 1;
} finally {
  if (temporary !== undefined) rmSync(temporary, { recursive: true, force: true });
}
