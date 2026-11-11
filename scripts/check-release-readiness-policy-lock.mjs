#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const LOCK_PATH = "release-readiness-policy.lock.json";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SEMVER_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const RELATIVE_PATH_PATTERN = /^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/u;
const EXPECTED_SCHEMA_VERSION = 1;
const EXPECTED_RELEASE_READINESS_VERSION = "0.7.0";

const TOP_LEVEL_KEYS = Object.freeze([
  "hashedFiles",
  "releaseReadinessVersion",
  "requiredFragments",
  "schemaVersion",
]);
const HASHED_FILE_KEYS = Object.freeze(["path", "role", "sha256"]);
const FRAGMENT_KEYS = Object.freeze(["contains", "path"]);
const MAX_LOCKED_FILE_BYTES = 2 * 1024 * 1024;

export class ReleaseReadinessPolicyLockError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseReadinessPolicyLockError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseReadinessPolicyLockError(code);
};

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

const assertExactKeys = (value, expectedKeys, code) => {
  const actual = Object.keys(value).sort();
  if (
    actual.length !== expectedKeys.length ||
    actual.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(code);
  }
};

const assertSafeRelativePath = (path) => {
  if (
    typeof path !== "string" ||
    !RELATIVE_PATH_PATTERN.test(path) ||
    path.startsWith(".git/") ||
    path.split("/").some((segment) => segment === "." || segment === "..") ||
    path.includes("//") ||
    path.startsWith("/")
  ) {
    fail("invalid-path");
  }
};

const readRegularFile = (root, path) => {
  assertSafeRelativePath(path);
  const rootPath = realpathSync(resolve(root));
  const absolutePath = resolve(rootPath, path);
  if (absolutePath !== rootPath && !absolutePath.startsWith(`${rootPath}${sep}`)) {
    fail("path-escapes-repository");
  }
  let cursor = rootPath;
  for (const segment of path.split("/")) {
    cursor = resolve(cursor, segment);
    let metadata;
    try {
      metadata = lstatSync(cursor);
    } catch {
      fail("missing-file");
    }
    if (metadata.isSymbolicLink()) {
      fail("symlink-not-allowed");
    }
  }
  let descriptor;
  try {
    descriptor = openSync(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    fail("missing-file");
  }
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) {
      fail("not-regular-file");
    }
    if (metadata.size > MAX_LOCKED_FILE_BYTES) {
      fail("file-too-large");
    }
    const bytes = Buffer.alloc(metadata.size);
    let offset = 0;
    while (offset < bytes.length) {
      const bytesRead = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) {
        fail("short-read");
      }
      offset += bytesRead;
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
};

const readLockFile = (root, path) => {
  assertSafeRelativePath(path);
  const rootPath = realpathSync(resolve(root));
  const absolutePath = resolve(rootPath, path);
  if (absolutePath !== rootPath && !absolutePath.startsWith(`${rootPath}${sep}`)) {
    fail("path-escapes-repository");
  }
  let metadata;
  try {
    metadata = lstatSync(absolutePath);
  } catch {
    fail("missing-file");
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    fail("not-regular-file");
  }
  return readRegularFile(root, path);
};

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

const parseLock = (bytes) => {
  let lock;
  try {
    lock = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("invalid-json");
  }
  if (!isRecord(lock)) {
    fail("invalid-lock");
  }
  assertExactKeys(lock, TOP_LEVEL_KEYS, "unexpected-lock-fields");
  return lock;
};

const assertStringArray = (value, code) => {
  if (!Array.isArray(value) || value.length === 0) {
    fail(code);
  }
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0) {
      fail(code);
    }
  }
};

export const checkReleaseReadinessPolicyLock = ({
  root = process.cwd(),
  lockPath = LOCK_PATH,
} = {}) => {
  const lock = parseLock(readLockFile(root, lockPath));
  if (lock.schemaVersion !== EXPECTED_SCHEMA_VERSION) {
    fail("unsupported-schema");
  }
  if (
    typeof lock.releaseReadinessVersion !== "string" ||
    !SEMVER_PATTERN.test(lock.releaseReadinessVersion) ||
    lock.releaseReadinessVersion !== EXPECTED_RELEASE_READINESS_VERSION
  ) {
    fail("unexpected-release-readiness-version");
  }

  if (!Array.isArray(lock.hashedFiles) || lock.hashedFiles.length === 0) {
    fail("missing-hashed-files");
  }
  const hashedPaths = new Set();
  for (const entry of lock.hashedFiles) {
    if (!isRecord(entry)) {
      fail("invalid-hashed-file");
    }
    assertExactKeys(entry, HASHED_FILE_KEYS, "unexpected-hashed-file-fields");
    assertSafeRelativePath(entry.path);
    if (hashedPaths.has(entry.path)) {
      fail("duplicate-hashed-file");
    }
    hashedPaths.add(entry.path);
    if (typeof entry.role !== "string" || entry.role.length === 0) {
      fail("invalid-hashed-file-role");
    }
    if (typeof entry.sha256 !== "string" || !SHA256_PATTERN.test(entry.sha256)) {
      fail("invalid-sha256");
    }
    const actual = sha256Hex(readRegularFile(root, entry.path));
    if (actual !== entry.sha256) {
      fail(`policy-file-drift:${entry.path}`);
    }
  }

  if (!Array.isArray(lock.requiredFragments) || lock.requiredFragments.length === 0) {
    fail("missing-required-fragments");
  }
  for (const rule of lock.requiredFragments) {
    if (!isRecord(rule)) {
      fail("invalid-fragment-rule");
    }
    assertExactKeys(rule, FRAGMENT_KEYS, "unexpected-fragment-rule-fields");
    assertSafeRelativePath(rule.path);
    if (!hashedPaths.has(rule.path)) {
      fail("fragment-file-not-hashed");
    }
    assertStringArray(rule.contains, "invalid-fragment-list");
    const source = readRegularFile(root, rule.path).toString("utf8");
    for (const fragment of rule.contains) {
      if (!source.includes(fragment)) {
        fail(`missing-required-fragment:${rule.path}`);
      }
    }
  }
};

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    checkReleaseReadinessPolicyLock();
  } catch (error) {
    if (error instanceof ReleaseReadinessPolicyLockError) {
      console.error(`release-readiness policy lock check failed: ${error.code}`);
      process.exit(1);
    }
    console.error("release-readiness policy lock check failed: unexpected-error");
    process.exit(1);
  }
}
