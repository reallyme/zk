#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

import {
  ReleaseAttestationError,
  localPackageArchives,
  selectLatestPreflightRun,
  verifyAttestationDocument,
  verifyWorkflowRun,
  verifyReleaseAttestation,
} from "./verify_release_attestation.mjs";

import { PUBLIC_CRATE_NAMES } from "./public-crates.mjs";

const releaseSha = "a".repeat(40);
const expected = Object.freeze({
  repository: "reallyme/zk",
  runId: 123,
  runAttempt: 1,
  releaseSha,
  releaseVersion: "0.2.1",
});
const attestation = (overrides = {}) => ({
  schema: "reallyme.zk.crates_preflight.v4",
  crates: PUBLIC_CRATE_NAMES.map((name, index) => ({
    file: `${name}-${expected.releaseVersion}.crate`, sha256: String(index + 1).repeat(64), size: 101 + index,
  })),
  repository: expected.repository,
  workflow: "crates-package-preflight.yml",
  run_id: expected.runId,
  run_attempt: 1,
  release_sha: releaseSha,
  version: expected.releaseVersion,
  ...overrides,
});
const workflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  ...overrides,
});
const listedWorkflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  display_title: `Crates package preflight ${expected.releaseVersion} @ ${releaseSha}`,
  ...overrides,
});

function runVerificationCli({ attempt = 2, evidenceAttempt = attempt, detailAttempt = attempt,
  conclusion = "success", status = "completed", pinnedAttempt = attempt, waitSeconds = "0",
  tamperArchive = false, resolvesOnly = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "zk-preflight-retry-"));
  try {
    const archives = join(root, "archives");
    mkdirSync(archives);
    for (const name of PUBLIC_CRATE_NAMES) {
      writeFileSync(join(archives, `${name}-${expected.releaseVersion}.crate`), name);
    }
    const document = attestation({
      run_attempt: evidenceAttempt,
      crates: localPackageArchives(expected.releaseVersion, { RELEASE_ATTESTATION_CRATE_DIRECTORY: archives }),
    });
    const documentPath = join(root, "attestation.json");
    writeFileSync(documentPath, JSON.stringify(document));
    if (tamperArchive) {
      writeFileSync(join(archives, `${PUBLIC_CRATE_NAMES[0]}-${expected.releaseVersion}.crate`), "altered");
    }
    const callsPath = join(root, "calls.json");
    writeFileSync(callsPath, "[]");
    const listed = listedWorkflowRun({ run_attempt: attempt, conclusion, status });
    const detailed = workflowRun({ run_attempt: detailAttempt, conclusion, status });
    const preload = join(root, "github-fixture.mjs");
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
const calls = [];
const record = (value) => {
  calls.push(value);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
};
Atomics.wait = () => { record(["wait"]); throw new Error("unexpected-test-wait"); };
childProcess.spawnSync = (command, args) => {
  record([command, ...args]);
  if (command !== "gh" || args[0] !== "api") return { status: 99, stdout: "", stderr: "" };
  const endpoint = args[1];
  let payload;
  if (endpoint.endsWith("/actions/workflows/crates-package-preflight.yml")) payload = { id: 456 };
  else if (endpoint.includes("/actions/workflows/456/runs?")) payload = { workflow_runs: [${JSON.stringify(listed)}] };
  else if (endpoint.endsWith("/actions/runs/123")) payload = ${JSON.stringify(detailed)};
  else if (endpoint.endsWith("/git/ref/heads/main")) payload = { object: { sha: ${JSON.stringify(releaseSha)} } };
  else return { status: 99, stdout: "", stderr: "" };
  return { status: 0, stdout: JSON.stringify(payload), stderr: "" };
};
syncBuiltinESMExports();
`);
    const output = join(root, "output");
    const script = fileURLToPath(new URL("./verify_release_attestation.mjs", import.meta.url));
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script], {
      encoding: "utf8", timeout: 10_000,
      env: { ...process.env,
        GITHUB_REPOSITORY: expected.repository, GITHUB_SHA: releaseSha, GH_TOKEN: "fixture-token",
        RELEASE_SHA: releaseSha, RELEASE_VERSION: expected.releaseVersion,
        ...(resolvesOnly ? {} : { PREFLIGHT_RUN_ID: String(expected.runId), PREFLIGHT_RUN_ATTEMPT: String(pinnedAttempt) }),
        RELEASE_ATTESTATION_RESOLVE_ONLY: resolvesOnly ? "1" : "0",
        RELEASE_ATTESTATION_PATH: documentPath, RELEASE_ATTESTATION_CRATE_DIRECTORY: archives,
        RELEASE_ATTESTATION_WAIT_SECONDS: waitSeconds, RELEASE_ATTESTATION_POLL_SECONDS: "1",
        RELEASE_ATTESTATION_WRITE_GITHUB_OUTPUT: "1", GITHUB_OUTPUT: output,
      },
    });
    assert.equal(result.error, undefined);
    return { ...result, calls: JSON.parse(readFileSync(callsPath, "utf8")),
      output: result.status === 0 ? readFileSync(output, "utf8") : "" };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("successful preflight retries retain valid signed package evidence and pin the admitted attempt", () => {
  const resolved = runVerificationCli({ resolvesOnly: true });
  assert.equal(resolved.status, 0, resolved.stderr);
  assert.match(resolved.output, /preflight_run_id=123\npreflight_run_attempt=2\n/u);
  assert.equal(resolved.calls.length, 2);
  for (const evidenceAttempt of [1, 2]) {
    const result = runVerificationCli({ evidenceAttempt });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.output, /preflight_run_attempt=2\n/u);
    assert.ok(result.calls.some((call) => call[2]?.includes(`head_sha=${releaseSha}`)));
  }
});

test("changed or future retry attempts cannot replace reviewed release evidence", () => {
  for (const [options, code] of [
    [{ evidenceAttempt: 3 }, "attestation-input-mismatch"],
    [{ detailAttempt: 3 }, "preflight-run-mismatch"],
    [{ pinnedAttempt: 1 }, "preflight-run-attempt-changed"],
    [{ evidenceAttempt: 1, tamperArchive: true }, "package-archive-digest-mismatch"],
  ]) {
    const result = runVerificationCli(options);
    assert.notEqual(result.status, 0);
    assert.ok(result.stderr.includes(code), result.stderr);
  }
});

test("terminal preflight failures fail promptly instead of polling for the wait duration", () => {
  const result = runVerificationCli({ conclusion: "failure", waitSeconds: "3600" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /latest-preflight-run-not-successful/u);
  assert.match(result.stderr, /Repair and rerun/u);
  assert.equal(result.calls.some((call) => call[0] === "wait"), false);
  const pending = runVerificationCli({ conclusion: null, status: "in_progress" });
  assert.match(pending.stderr, /latest-preflight-run-pending/u);
  assert.match(pending.stderr, /Wait for Crates Package Preflight/u);
});

test("attempt identifiers must be positive safe integers", () => {
  for (const attempt of [undefined, 0, -1, "2", 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => verifyAttestationDocument(attestation({ run_attempt: attempt }), expected), ReleaseAttestationError);
    assert.throws(() => verifyWorkflowRun(workflowRun({ run_attempt: attempt }), {
      workflowId: 456, runId: expected.runId, runAttempt: attempt, releaseSha,
    }), ReleaseAttestationError);
  }
});

test("release provenance shell gate admits the approved archive set and rejects incomplete or extra evidence", () => {
  // CLI doubles isolate shell control flow; document validation is exercised
  // independently below with the production verifier.
  const workflow = readFileSync(".github/workflows/crates-release.yml", "utf8");
  const command = workflow.match(
    /      - name: Verify provenance, source identity, and reviewed bytes[\s\S]*?        run: \|\n((?: {10}[^\n]*\n|\n)+)/u,
  )?.[1]?.replace(/^ {10}/gmu, "");
  assert.ok(command, "the release verification step must be executable by this regression test");
  const root = mkdtempSync(join(tmpdir(), "zk-release-shell-gate-"));
  try {
    mkdirSync(join(root, "bin"));
    mkdirSync(join(root, "scripts"));
    mkdirSync(join(root, "release-attestation"));
    mkdirSync(join(root, "reviewed-crates"));
    copyFileSync("scripts/public-crates.mjs", join(root, "scripts", "public-crates.mjs"));
    writeFileSync(join(root, "release-attestation", "crates-preflight.json"), "{}");
    const gh = join(root, "bin", "gh");
    writeFileSync(gh, `#!${process.execPath}
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
if (args[0] !== "attestation" || args[1] !== "verify") process.exit(2);
for (const flag of ["--repo", "--signer-workflow", "--source-digest", "--source-ref", "--deny-self-hosted-runners"]) {
  if (!args.includes(flag)) process.exit(2);
}
if (args[2] === process.env.TEST_REJECT_PROVENANCE) process.exit(1);
appendFileSync(process.env.TEST_VERIFICATION_LOG, args[2] + "\\n");
`);
    const node = join(root, "bin", "node");
    writeFileSync(node, `#!${process.execPath}
import { appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "scripts/verify_release_attestation.mjs") {
  appendFileSync(process.env.TEST_VERIFICATION_LOG, "document-verified\\n");
} else {
  const result = spawnSync(process.env.TEST_NODE_EXECUTABLE, args, { stdio: "inherit" });
  process.exitCode = result.status ?? 1;
}
`);
    chmodSync(gh, 0o755);
    chmodSync(node, 0o755);
    const files = PUBLIC_CRATE_NAMES.map((name) => `reviewed-crates/${name}-${expected.releaseVersion}.crate`);
    for (const file of files) writeFileSync(join(root, file), file);
    const log = join(root, "verification.log");
    const run = (overrides = {}) => {
      writeFileSync(log, "");
      const result = spawnSync("bash", ["-e", "-o", "pipefail", "-c", command], {
        cwd: root,
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${join(root, "bin")}${delimiter}${process.env.PATH}`,
          GITHUB_REPOSITORY: expected.repository,
          RELEASE_SHA: releaseSha,
          TEST_NODE_EXECUTABLE: process.execPath,
          TEST_VERIFICATION_LOG: log,
          TEST_REJECT_PROVENANCE: "",
          ...overrides,
        },
      });
      return { ...result, calls: readFileSync(log, "utf8").trim().split("\n") };
    };
    const accepted = run();
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(accepted.calls[0], "release-attestation/crates-preflight.json");
    assert.equal(accepted.calls.at(-1), "document-verified");
    assert.deepEqual(accepted.calls.slice(1, -1).sort(), [...files].sort());
    unlinkSync(join(root, files[0]));
    const missing = run();
    assert.notEqual(missing.status, 0);
    assert.equal(missing.calls.includes("document-verified"), false);
    writeFileSync(join(root, files[0]), files[0]);
    const extraFile = join(root, "reviewed-crates", "unapproved.crate");
    writeFileSync(extraFile, "extra");
    assert.notEqual(run().status, 0);
    unlinkSync(extraFile);
    for (const file of ["release-attestation/crates-preflight.json", files[0]]) {
      const rejected = run({ TEST_REJECT_PROVENANCE: file });
      assert.notEqual(rejected.status, 0);
      assert.equal(rejected.calls.includes("document-verified"), false);
    }
    for (const file of files) unlinkSync(join(root, file));
    const empty = run();
    assert.notEqual(empty.status, 0);
    assert.equal(empty.calls.includes("document-verified"), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reviewed attestation accepts the exact run, SHA, and version", () => {
  assert.doesNotThrow(() => verifyAttestationDocument(attestation(), expected));
  assert.doesNotThrow(() =>
    verifyWorkflowRun(workflowRun(), {
      workflowId: 456,
      runId: expected.runId,
      runAttempt: expected.runAttempt,
      releaseSha,
    }),
  );
});

test("package attestation is produced without global CI prerequisite run IDs", () => {
  const root = mkdtempSync(join(tmpdir(), "zk-package-attestation-"));
  try {
    const packageDirectory = join(root, "target", "package");
    mkdirSync(packageDirectory, { recursive: true });
    for (const name of PUBLIC_CRATE_NAMES) {
      writeFileSync(join(packageDirectory, `${name}-${expected.releaseVersion}.crate`), name);
    }
    const env = {
      ...process.env,
      CARGO_TARGET_DIR: join(root, "target"),
      GITHUB_REPOSITORY: expected.repository,
      GITHUB_RUN_ID: String(expected.runId),
      GITHUB_RUN_ATTEMPT: "1",
      RELEASE_SHA: releaseSha,
      RELEASE_VERSION: expected.releaseVersion,
    };
    for (const key of ["FUZZ_RUN_ID", "PROTOBUF_CI_RUN_ID", "RUST_CI_RUN_ID"]) delete env[key];
    const script = fileURLToPath(new URL("./write_release_attestation.mjs", import.meta.url));
    for (const attempt of [1, 2]) {
      const documentPath = join(root, "release-attestation", "crates-preflight.json");
      if (attempt > 1) unlinkSync(documentPath);
      const result = spawnSync(process.execPath, [script], {
        cwd: root, env: { ...env, GITHUB_RUN_ATTEMPT: String(attempt) }, encoding: "utf8",
      });
      assert.equal(result.status, 0, result.stderr);
      const document = JSON.parse(readFileSync(documentPath, "utf8"));
      assert.equal(Object.hasOwn(document, "prerequisites"), false);
      assert.equal(document.run_attempt, attempt);
      verifyAttestationDocument(document, {
        ...expected, runAttempt: attempt,
        packageArchives: localPackageArchives(expected.releaseVersion, { CARGO_TARGET_DIR: join(root, "target") }),
      });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("attestation rejects mismatched inputs and unreviewed fields", () => {
  for (const candidate of [
    attestation({ version: "0.1.0" }),
    attestation({ release_sha: "b".repeat(40) }),
    attestation({ run_id: 124 }),
    attestation({ extra: true }),
    attestation({ schema: "reallyme.zk.crates_preflight.v3" }),
    attestation({ prerequisites: { fuzz: 11 } }),
    attestation({ crates: [{ file: "wrong.crate", sha256: "1".repeat(64), size: 1 }] }),
  ]) {
    assert.throws(
      () => verifyAttestationDocument(candidate, expected),
      ReleaseAttestationError,
    );
  }
});

test("reviewed archive loading rejects symbolic links", () => {
  const directory = mkdtempSync(join(tmpdir(), "zk-reviewed-archives-"));
  try {
    for (const name of PUBLIC_CRATE_NAMES) {
      writeFileSync(join(directory, `${name}-${expected.releaseVersion}.crate`), name);
    }
    const archives = localPackageArchives(expected.releaseVersion, {
      RELEASE_ATTESTATION_CRATE_DIRECTORY: directory,
    });
    assert.equal(archives.length, 5);
    assert.ok(archives.every((archive) => archive.size > 0));

    const linkedArchive = join(directory, `reallyme-zk-api-${expected.releaseVersion}.crate`);
    unlinkSync(linkedArchive);
    symlinkSync(join(directory, `reallyme-zk-proto-${expected.releaseVersion}.crate`), linkedArchive);
    assert.throws(
      () =>
        localPackageArchives(expected.releaseVersion, {
          RELEASE_ATTESTATION_CRATE_DIRECTORY: directory,
        }),
      { name: "ReleaseAttestationError", code: "invalid-local-crate-archive" },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failed, changed-attempt, wrong-branch, and wrong-workflow runs fail closed", () => {
  for (const candidate of [
    workflowRun({ conclusion: "failure" }),
    workflowRun({ run_attempt: 2 }),
    workflowRun({ head_branch: "feature" }),
    workflowRun({ workflow_id: 457 }),
    workflowRun({ path: ".github/workflows/other.yml@refs/heads/main" }),
  ]) {
    assert.throws(
      () =>
        verifyWorkflowRun(candidate, {
          workflowId: 456,
          runId: expected.runId,
          runAttempt: expected.runAttempt,
          releaseSha,
        }),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution selects the latest exact successful preflight", () => {
  const latest = selectLatestPreflightRun(
    {
      workflow_runs: [
        listedWorkflowRun({ id: 121 }),
        listedWorkflowRun({ id: 123 }),
        listedWorkflowRun({ id: 124, head_sha: "b".repeat(40) }),
      ],
    },
    {
      workflowId: 456,
      releaseSha,
      releaseVersion: expected.releaseVersion,
    },
  );
  assert.equal(latest.id, 123);
});

test("newer failed, running, and wrong-version preflights fail closed", () => {
  const rejectedLatestRuns = [
    listedWorkflowRun({ id: 124, conclusion: "failure" }),
    listedWorkflowRun({ id: 124, conclusion: null, status: "in_progress" }),
    listedWorkflowRun({
      id: 124,
      display_title: `Crates package preflight 0.1.0 @ ${releaseSha}`,
    }),
  ];
  for (const rejected of rejectedLatestRuns) {
    assert.throws(
      () =>
        selectLatestPreflightRun(
          { workflow_runs: [listedWorkflowRun({ id: 123 }), rejected] },
          {
            workflowId: 456,
            releaseSha,
            releaseVersion: expected.releaseVersion,
          },
        ),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution rejects missing and malformed workflow results", () => {
  for (const candidate of [{}, { workflow_runs: [] }, { workflow_runs: [null] }]) {
    assert.throws(
      () =>
        selectLatestPreflightRun(candidate, {
          workflowId: 456,
          releaseSha,
          releaseVersion: expected.releaseVersion,
        }),
      ReleaseAttestationError,
    );
  }
});

test("waiting rejects zero polling intervals before querying GitHub", () => {
  assert.throws(() => verifyReleaseAttestation({ env: {
    GITHUB_REPOSITORY: expected.repository,
    RELEASE_SHA: releaseSha,
    RELEASE_VERSION: expected.releaseVersion,
    GITHUB_SHA: releaseSha,
    GH_TOKEN: "test-placeholder",
    RELEASE_ATTESTATION_WAIT_SECONDS: "60",
    RELEASE_ATTESTATION_POLL_SECONDS: "0",
  } }), { name: "ReleaseAttestationError", code: "invalid-release-attestation-poll-seconds" });
});
