#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";

const MAX_METADATA_BYTES = 1_048_576;
const MAX_BINARY_COUNT = 4_096;
const MAX_BINARY_ID_BYTES = 512;
const MACOS_CONCURRENCY = 1;
const MACOS_BINARIES_PER_BATCH = 16;
const DEFAULT_CONCURRENCY = 4;
const BINARIES_PER_BATCH =
  process.platform === "darwin" ? MACOS_BINARIES_PER_BATCH : DEFAULT_CONCURRENCY;
const TEST_THREADS =
  process.platform === "darwin" ? MACOS_CONCURRENCY : DEFAULT_CONCURRENCY;
// Nextest uses kind/name for Cargo binary targets. Filter operators and
// whitespace stay excluded so metadata cannot broaden a batch selection.
const SAFE_BINARY_ID = /^[A-Za-z0-9_.:+/-]+$/u;

const laneArguments = new Map([
  ["default", []],
  ["native", ["--no-default-features", "--features", "native"]],
  ["all-features", ["--all-features"]],
]);

const fail = (message) => {
  console.error(`bounded nextest failed: ${message}`);
  process.exit(1);
};

const lane = process.argv[2];
if (process.argv.length !== 3 || !laneArguments.has(lane)) {
  fail("expected exactly one lane: default, native, or all-features");
}

const selectedLaneArguments = laneArguments.get(lane);
if (!Array.isArray(selectedLaneArguments)) {
  fail("selected lane has no configured Cargo arguments");
}

const isRecord = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const list = spawnSync(
  "cargo",
  [
    "nextest",
    "list",
    "--locked",
    "--workspace",
    ...selectedLaneArguments,
    "--list-type",
    "binaries-only",
    "--message-format",
    "json",
  ],
  {
    encoding: "utf8",
    maxBuffer: MAX_METADATA_BYTES,
    stdio: ["ignore", "pipe", "inherit"],
  },
);

if (list.error !== undefined) {
  fail("nextest binary discovery metadata could not be started");
}
if (list.status !== 0) {
  fail("nextest binary discovery metadata did not complete successfully");
}
if (typeof list.stdout !== "string" || list.stdout.length === 0) {
  fail("nextest binary discovery metadata is empty");
}
if (Buffer.byteLength(list.stdout, "utf8") > MAX_METADATA_BYTES) {
  fail("nextest binary discovery metadata exceeds the accepted boundary");
}

let metadata;
try {
  metadata = JSON.parse(list.stdout);
} catch {
  fail("nextest binary discovery metadata is not valid JSON");
}

if (!isRecord(metadata) || !isRecord(metadata["rust-binaries"])) {
  fail("nextest binary discovery metadata has an invalid shape");
}

const binaries = metadata["rust-binaries"];
const binaryIds = Object.keys(binaries).sort();
if (binaryIds.length === 0 || binaryIds.length > MAX_BINARY_COUNT) {
  fail("nextest binary count is outside the accepted boundary");
}

for (const binaryId of binaryIds) {
  const descriptor = binaries[binaryId];
  if (
    Buffer.byteLength(binaryId, "utf8") === 0 ||
    Buffer.byteLength(binaryId, "utf8") > MAX_BINARY_ID_BYTES ||
    !SAFE_BINARY_ID.test(binaryId) ||
    !isRecord(descriptor) ||
    descriptor["binary-id"] !== binaryId
  ) {
    fail("nextest binary discovery metadata contains an invalid binary identifier");
  }
}

const totalBatches = Math.ceil(binaryIds.length / BINARIES_PER_BATCH);
for (let offset = 0; offset < binaryIds.length; offset += BINARIES_PER_BATCH) {
  const batch = binaryIds.slice(offset, offset + BINARIES_PER_BATCH);
  const filter = batch.map((binaryId) => `binary_id(=${binaryId})`).join(" | ");
  const batchNumber = Math.floor(offset / BINARIES_PER_BATCH) + 1;
  console.log(
    `bounded nextest: ${lane} batch ${batchNumber}/${totalBatches} (${batch.length} binaries)`,
  );

  const run = spawnSync(
    "cargo",
    [
      "nextest",
      "run",
      "--locked",
      "--workspace",
      ...selectedLaneArguments,
      "--test-threads",
      String(TEST_THREADS),
      "--no-fail-fast",
      "--no-tests",
      "pass",
      "--filterset",
      filter,
    ],
    { stdio: "inherit" },
  );
  if (run.error !== undefined) {
    fail("a nextest batch could not be started");
  }
  if (run.status !== 0) {
    fail(`nextest batch ${batchNumber} did not complete successfully`);
  }
}

console.log(`bounded nextest: ${lane} completed ${binaryIds.length} binaries`);
