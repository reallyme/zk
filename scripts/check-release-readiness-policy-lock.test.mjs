#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  ReleaseReadinessPolicyLockError,
  checkReleaseReadinessPolicyLock,
} from "./check-release-readiness-policy-lock.mjs";

const sha256Hex = (source) => createHash("sha256").update(source).digest("hex");

const writeFixtureFile = (root, path, source) => {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, source);
};

const writeLock = (root, lock) => {
  writeFileSync(join(root, "release-readiness-policy.lock.json"), JSON.stringify(lock, null, 2));
};

const fixtureLock = (source) => ({
  schemaVersion: 1,
  releaseReadinessVersion: "0.7.0",
  hashedFiles: [
    {
      path: "scripts/check_release_readiness.mjs",
      role: "consumer policy declaration",
      sha256: sha256Hex(source),
    },
  ],
  requiredFragments: [
    {
      path: "scripts/check_release_readiness.mjs",
      contains: ["reallyme-release-readiness", "v0.7.0"],
    },
  ],
});

test("accepts reviewed release-readiness policy lock", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-policy-lock-"));
  try {
    const source = "npm exec -- reallyme-release-readiness --policy-only\n// v0.7.0\n";
    writeFixtureFile(temporary, "scripts/check_release_readiness.mjs", source);
    writeLock(temporary, fixtureLock(source));

    assert.doesNotThrow(() => checkReleaseReadinessPolicyLock({ root: temporary }));
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects drift in locked release-readiness policy source", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-policy-lock-"));
  try {
    const source = "npm exec -- reallyme-release-readiness --policy-only\n// v0.7.0\n";
    writeFixtureFile(temporary, "scripts/check_release_readiness.mjs", `${source}// drift\n`);
    writeLock(temporary, fixtureLock(source));

    assert.throws(
      () => checkReleaseReadinessPolicyLock({ root: temporary }),
      (error) =>
        error instanceof ReleaseReadinessPolicyLockError &&
        error.code === "policy-file-drift:scripts/check_release_readiness.mjs",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects unlocked required policy fragments", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-policy-lock-"));
  try {
    const source = "npm exec -- reallyme-release-readiness --policy-only\n// v0.7.0\n";
    const lock = fixtureLock(source);
    lock.requiredFragments[0].path = ".github/workflows/rust-ci.yml";
    writeFixtureFile(temporary, "scripts/check_release_readiness.mjs", source);
    writeFixtureFile(temporary, ".github/workflows/rust-ci.yml", source);
    writeLock(temporary, lock);

    assert.throws(
      () => checkReleaseReadinessPolicyLock({ root: temporary }),
      (error) =>
        error instanceof ReleaseReadinessPolicyLockError &&
        error.code === "fragment-file-not-hashed",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects traversal paths before reading locked files", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-policy-lock-"));
  try {
    const source = "npm exec -- reallyme-release-readiness --policy-only\n// v0.7.0\n";
    const lock = fixtureLock(source);
    lock.hashedFiles[0].path = "../outside.mjs";
    writeFixtureFile(temporary, "scripts/check_release_readiness.mjs", source);
    writeLock(temporary, lock);

    assert.throws(
      () => checkReleaseReadinessPolicyLock({ root: temporary }),
      (error) =>
        error instanceof ReleaseReadinessPolicyLockError &&
        error.code === "invalid-path",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects locked files that are symlinks", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-policy-lock-"));
  try {
    const source = "npm exec -- reallyme-release-readiness --policy-only\n// v0.7.0\n";
    writeFixtureFile(temporary, "outside.mjs", source);
    mkdirSync(join(temporary, "scripts"), { recursive: true });
    symlinkSync("../outside.mjs", join(temporary, "scripts/check_release_readiness.mjs"));
    writeLock(temporary, fixtureLock(source));

    assert.throws(
      () => checkReleaseReadinessPolicyLock({ root: temporary }),
      (error) =>
        error instanceof ReleaseReadinessPolicyLockError &&
        error.code === "symlink-not-allowed",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects locked files below symlinked directories", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-policy-lock-"));
  try {
    const source = "npm exec -- reallyme-release-readiness --policy-only\n// v0.7.0\n";
    mkdirSync(join(temporary, "real-scripts"), { recursive: true });
    writeFileSync(join(temporary, "real-scripts/check_release_readiness.mjs"), source);
    symlinkSync("real-scripts", join(temporary, "scripts"));
    writeLock(temporary, fixtureLock(source));

    assert.throws(
      () => checkReleaseReadinessPolicyLock({ root: temporary }),
      (error) =>
        error instanceof ReleaseReadinessPolicyLockError &&
        error.code === "symlink-not-allowed",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
