#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";

const fail = () => {
  console.error("platform policy delegation is incomplete");
  process.exit(1);
};

const lane = process.argv[2];
if (process.argv.length !== 3 || (lane !== "swift" && lane !== "kotlin")) {
  fail();
}

const workflow = readFileSync(".github/workflows/rust-ci.yml", "utf8");
const pullRequest = workflow.slice(workflow.indexOf("  pull_request:"), workflow.indexOf("  push:"));
const triggerLines = pullRequest.split("\n").map((line) => line.trim())
  .filter((line) => line.length > 0 && !line.startsWith("#"));
const allPullRequests = triggerLines.length === 1 && triggerLines[0] === "pull_request:";
const sourcePullRequests = triggerLines.length === 3 && triggerLines[0] === "pull_request:" &&
  triggerLines[1] === "paths-ignore:" && /^- ["']\*\*\/\*[.]md["']$/u.test(triggerLines[2]);
if (!allPullRequests && !sourcePullRequests) {
  fail();
}

const jobName = lane === "swift" ? "swift-package" : "kotlin-package";
const marker = `  ${jobName}:\n`;
const start = workflow.indexOf(marker);
if (start < 0) {
  fail();
}
const tail = workflow.slice(start + marker.length);
const nextJob = tail.search(/^  [a-z0-9][a-z0-9-]*:\n/mu);
const job = nextJob < 0 ? tail : tail.slice(0, nextJob);
const required = lane === "swift" ? [
  "runs-on: xcode-27",
  "packages/swift/scripts/check-format.sh",
  "packages/swift/scripts/check-lint.sh",
  "scripts/build_swift_xcframework.sh",
  "scripts/prepare_swift_binary_manifest.mjs",
  "scripts/check-apple-platform-ffi-freshness.sh",
  "swift build -Xswiftc -warnings-as-errors",
  "swift test -Xswiftc -warnings-as-errors",
] : [
  "runs-on: ubuntu-24.04",
  "needs: [changes, public-artifacts, android-target]",
  "android-native-source-${{ github.sha }}",
  "scripts/check-android-platform-jni-freshness.sh",
  "java-version: |",
  "            17",
  "            21",
  "ktlintCheck",
  "detekt",
  "compileKotlin",
  ":demo-android:compileDebugKotlin",
  ":demo-android:testDebugUnitTest",
  ":android-native:check",
];
const scope = lane === "swift" ? "swift" : "android";
if (!job.includes(`if: needs.changes.outputs.${scope} == 'true'`) ||
    !workflow.includes("node scripts/select-ci-scope.mjs") ||
    !workflow.includes("node scripts/require-ci-results.mjs") ||
    job.includes("continue-on-error:")) {
  fail();
}
if (required.some((item) => !job.includes(item))) {
  fail();
}

console.log(`${lane} source policy execution is delegated to Rust CI`);
