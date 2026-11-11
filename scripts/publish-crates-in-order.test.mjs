// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish-crates-in-order.mjs", import.meta.url));

function runFixture({ mode = "publish", scenario = "success", requirement = "^0.2.2", version = "0.2.2" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "zk-publish-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const ledgerPath = join(directory, "publication-ledger.json");
    const packageDirectory = join(directory, "package");
    const reviewedDirectory = join(directory, "reviewed");
    mkdirSync(packageDirectory);
    mkdirSync(reviewedDirectory);
    for (const name of ["reallyme-zk-api", "reallyme-zk-artifacts", "reallyme-zk-proto"]) {
      const file = `${name}-${version}.crate`;
      const archive = Buffer.from(`reviewed:${file}`);
      writeFileSync(join(packageDirectory, file), archive);
      writeFileSync(
        join(reviewedDirectory, file),
        scenario === "reviewed-mismatch" && name === "reallyme-zk-api"
          ? Buffer.from("different")
          : archive,
      );
    }
    const preload = join(directory, "mock.mjs");
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
let artifactPackageAttempts = 0;
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command === "curl") {
    const outputPath = args[args.indexOf("--output") + 1];
    const file = outputPath.split("/").at(-1);
    writeFileSync(outputPath, Buffer.from(\`reviewed:\${file}\`));
    return ok;
  }
  if (command !== "cargo") return { ...ok, status: 99 };
  if (args[0] === "metadata") return { ...ok, stdout: JSON.stringify({
    target_directory: ${JSON.stringify(directory)},
    packages: [
      { name: "reallyme-zk-api", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
      { name: "reallyme-zk-artifacts", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-zk-api", source: null, path: "crates/api",
          kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-zk-proto", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
    ],
  }) };
  if (args[0] === "package") {
    const packageName = args[args.indexOf("-p") + 1];
    if (scenario === "package-index-lag" && packageName === "reallyme-zk-artifacts") {
      artifactPackageAttempts += 1;
      if (artifactPackageAttempts === 1) {
        return { ...ok, status: 101,
          stderr: "no matching package named \\x60reallyme-zk-api\\x60 found" };
      }
    }
    return ok;
  }
  if (args[0] !== "publish") return { ...ok, status: 99 };
  attempts += 1;
  if (scenario === "exhausted" || (scenario === "retry" && attempts === 1)) {
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        ...process.env,
        PUBLICATION_LEDGER_PATH: ledgerPath,
        RELEASE_SHA: "a".repeat(40),
        RELEASE_VERSION: version,
        REVIEWED_CRATE_DIRECTORY: reviewedDirectory,
      },
    });
    assert.equal(result.error, undefined);
    return {
      ...result,
      calls: JSON.parse(readFileSync(callsPath, "utf8")),
      ledger:
        mode === "publish" && scenario !== "failure"
          ? JSON.parse(readFileSync(ledgerPath, "utf8"))
          : undefined,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    ["reallyme-zk-api", "reallyme-zk-artifacts", "reallyme-zk-proto"]);
  assert.equal(result.ledger.state, "completed");
  assert.deepEqual(result.ledger.crates.map((crate) => crate.state), [
    "published",
    "published",
    "published",
  ]);
});

test("publication rejects package bytes that differ from the reviewed archives", () => {
  const result = runFixture({ scenario: "reviewed-mismatch" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /differs from reviewed preflight bytes/u);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 0);
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-zk-api"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
});

test("transient rate limits retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("registry index lag during dependent archive creation retries without partial failure", () => {
  const result = runFixture({ scenario: "package-index-lag" });
  assert.equal(result.status, 0, result.stderr);
  const artifactPackages = result.calls.filter(
    (call) => call[1] === "package" && call[3] === "reallyme-zk-artifacts",
  );
  assert.equal(artifactPackages.length, 2);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
  assert.deepEqual(
    result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    ["reallyme-zk-api", "reallyme-zk-artifacts", "reallyme-zk-proto"],
  );
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
});

test("zero-major caret requirements match Cargo compatibility boundaries", () => {
  for (const [requirement, version, accepted] of [
    ["^0.0.1", "0.0.1", true],
    ["^0.0.1", "0.0.2", false],
    ["^0.2.1", "0.2.2", true],
    ["^0.2.2", "0.3.0", false],
    ["^0.2.1junk", "0.2.2", false],
  ]) {
    const result = runFixture({ mode: "order", requirement, version });
    assert.equal(result.status === 0, accepted, `${requirement} / ${version}`);
    assert.ok(result.calls.every((call) => call[1] === "metadata"));
  }
});

test("archive mode recreates package bytes without compiling or publishing", () => {
  const result = runFixture({ mode: "archive" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(
    result.calls.map((call) => call.slice(0, 2)),
    [
      ["cargo", "metadata"],
      ["cargo", "package"],
    ],
  );
});
