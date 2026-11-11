#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  COMMON_CREDENTIAL_ROOT_SOURCE_PATHS,
  ModernSourceLockError,
  PERSONA_CREDENTIAL_EVIDENCE_SOURCE_PATHS,
  validateModernCircuitSourceLock,
} from "./check-modern-circuit-source-lock.mjs";

const circuitsRoot = join(process.cwd(), "circuits");
const lockPath = join(circuitsRoot, "modern-circuit-source-lock.tsv");
const currentLock = readFileSync(lockPath, "utf8");
const registryPaths = currentLock
  .trimEnd()
  .split("\n")
  .slice(1)
  .map((line) => line.split("\t")[0])
  .sort();

test("modern circuit source lock admits the canonical common-credential-root and prepared sets", () => {
  assert.doesNotThrow(() =>
    validateModernCircuitSourceLock({
      circuitsRoot,
      lockPath,
      registryPaths,
    }),
  );
});

test("modern circuit source lock rejects a substituted prepared source path", () => {
  const changedRegistry = registryPaths.map((path) =>
    path === PERSONA_CREDENTIAL_EVIDENCE_SOURCE_PATHS[0]
      ? "poseidon2/families/persona_credential_evidence_v1/retired_claim"
      : path,
  );
  assert.throws(
    () =>
      validateModernCircuitSourceLock({
        circuitsRoot,
        lockPath,
        registryPaths: changedRegistry,
      }),
    (error) =>
      error instanceof ModernSourceLockError &&
      error.code === "PERSONA_CREDENTIAL_EVIDENCE_SOURCE_SET_MISMATCH",
  );
});

test("modern circuit source lock rejects a missing common-credential-root row", () => {
  const temporary = mkdtempSync(join(tmpdir(), "reallyme-zk-source-lock-missing."));
  try {
    const changed = currentLock
      .split("\n")
      .filter((line) => !line.startsWith(`${COMMON_CREDENTIAL_ROOT_SOURCE_PATHS[0]}\t`))
      .join("\n");
    const changedLockPath = join(temporary, "modern-circuit-source-lock.tsv");
    writeFileSync(changedLockPath, changed);

    assert.throws(
      () =>
        validateModernCircuitSourceLock({
          circuitsRoot,
          lockPath: changedLockPath,
          registryPaths,
        }),
      (error) =>
        error instanceof ModernSourceLockError &&
        error.code === "SOURCE_LOCK_COUNT_MISMATCH",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("modern circuit source lock rejects a stale common-credential-root digest", () => {
  const temporary = mkdtempSync(join(tmpdir(), "reallyme-zk-source-lock-stale."));
  try {
    const changed = currentLock.replace(
      new RegExp(`(${COMMON_CREDENTIAL_ROOT_SOURCE_PATHS[1]}\\t[^\\t]+\\t)[0-9a-f]{64}`, "u"),
      "$10000000000000000000000000000000000000000000000000000000000000000",
    );
    const changedLockPath = join(temporary, "modern-circuit-source-lock.tsv");
    writeFileSync(changedLockPath, changed);

    assert.throws(
      () =>
        validateModernCircuitSourceLock({
          circuitsRoot,
          lockPath: changedLockPath,
          registryPaths,
        }),
      (error) =>
        error instanceof ModernSourceLockError &&
        error.code === "SOURCE_LOCK_STALE_DIGEST",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
