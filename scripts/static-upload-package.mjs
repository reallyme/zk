// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync, rmSync, rmdirSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

const MAX_OBJECTS = 256;
const MAX_OBJECT_BYTES = 512_000_000;
const HASH_BUFFER_BYTES = 1_048_576;

export class StaticUploadError extends Error {
  constructor(code) {
    super(code);
    this.name = "StaticUploadError";
    this.code = code;
  }
}
const fail = (code) => { throw new StaticUploadError(code); };

export function sha256File(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || !Number.isSafeInteger(metadata.size) || metadata.size < 1 || metadata.size > MAX_OBJECT_BYTES) {
      fail("invalid-object-size");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(HASH_BUFFER_BYTES);
    let consumed = 0;
    let read;
    while ((read = readSync(descriptor, buffer, 0, buffer.length, null)) !== 0) {
      if (read > metadata.size - consumed) fail("object-changed-during-read");
      consumed += read;
      hash.update(buffer.subarray(0, read));
    }
    if (consumed !== metadata.size) fail("object-changed-during-read");
    return hash.digest("hex");
  } finally {
    closeSync(descriptor);
  }
}

function objectKey(url) {
  let parsed;
  try { parsed = new URL(url); } catch { fail("invalid-object-url"); }
  if (parsed.origin !== "https://static.reallyme.net" || parsed.username || parsed.password || parsed.search || parsed.hash ||
      !/^\/zk\/[A-Za-z0-9._/-]+$/u.test(parsed.pathname)) fail("invalid-object-url");
  const key = parsed.pathname.slice(1);
  if (key.split("/").some((part) => part === "" || part === "." || part === "..")) fail("invalid-object-key");
  return key;
}

function inspectTree(root, prefix, files, directories) {
  const path = join(root, prefix);
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail("mirror-directory-invalid");
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const name = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isSymbolicLink()) fail("mirror-symlink");
    if (entry.isDirectory()) {
      inspectTree(root, name, files, directories);
      directories.push(name);
    } else if (entry.isFile()) {
      files.push(name);
    } else {
      fail("mirror-entry-invalid");
    }
  }
}

// A complete set is admitted before housekeeping. Failed validation preserves
// every existing object. Published historical objects remain in the inventory.
export function synchronizeStaticMirror({ rows, outputRoot, checkOnly = false }) {
  try {
    if (!Array.isArray(rows) || rows.length === 0 || rows.length > MAX_OBJECTS || typeof outputRoot !== "string") {
      fail("invalid-upload-inventory");
    }
    const root = resolve(outputRoot);
    const files = [];
    const directories = [];
    inspectTree(root, "", files, directories);
    const keys = new Set();
    for (const row of rows) {
      if (!Array.isArray(row) || row.length !== 4 || row.some((item) => typeof item !== "string" || item.length > 4096) ||
          !/^[0-9a-f]{64}$/u.test(row[2])) fail("invalid-upload-record");
      const [path, url, digest] = row;
      const key = objectKey(url);
      if (!key.split("/").includes(digest)) fail("object-key-hash-mismatch");
      if (keys.has(key)) fail("duplicate-object-key");
      if (!isAbsolute(path) || resolve(path) !== join(root, key)) fail("object-outside-mirror");
      if (!files.includes(key)) fail("mirror-object-missing");
      if (sha256File(path) !== digest) fail("source-hash-mismatch");
      keys.add(key);
    }
    const extra = files.filter((file) => !keys.has(file));
    const unusedDirectories = directories.filter((directory) => ![...keys].some((key) => key.startsWith(`${directory}/`)));
    if (checkOnly && (extra.length !== 0 || unusedDirectories.length !== 0)) fail("mirror-has-extra-entries");
    for (const file of extra) rmSync(join(root, file));
    for (const directory of unusedDirectories) rmdirSync(join(root, directory));
    return [...keys].sort();
  } catch (error) {
    if (error instanceof StaticUploadError) throw error;
    throw new StaticUploadError("mirror-io-failed");
  }
}
