// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import {
  closeSync, copyFileSync, fstatSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readSync, renameSync, rmSync, writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const MAX_OBJECTS = 256;
const MAX_OBJECT_BYTES = 512_000_000;
const HASH_BUFFER_BYTES = 1_048_576;
const CACHE_CONTROL = "public, max-age=31536000, immutable";

export class StaticUploadError extends Error {
  constructor(code) {
    super(code);
    this.name = "StaticUploadError";
    this.code = code;
  }
}

const fail = (code) => { throw new StaticUploadError(code); };

function sha256File(path) {
  const descriptor = openSync(path, "r");
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || !Number.isSafeInteger(metadata.size) ||
        metadata.size < 1 || metadata.size > MAX_OBJECT_BYTES) {
      fail("invalid-object-size");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(HASH_BUFFER_BYTES);
    let read;
    let consumed = 0;
    while ((read = readSync(descriptor, buffer, 0, buffer.length, null)) !== 0) {
      if (read > metadata.size - consumed) fail("object-changed-during-read");
      consumed += read;
      hash.update(buffer.subarray(0, read));
    }
    if (consumed !== metadata.size) fail("object-changed-during-read");
    return { sha256: hash.digest("hex"), bytes: metadata.size };
  } finally {
    closeSync(descriptor);
  }
}

function contentType(key) {
  if (key.endsWith(".zip")) return "application/zip";
  if (key.endsWith(".tar")) return "application/x-tar";
  return "application/octet-stream";
}

function sourcePath(root, path) {
  if (!isAbsolute(path)) fail("source-path-not-absolute");
  const absolute = resolve(path);
  if (!absolute.startsWith(`${root}${sep}`)) fail("source-outside-artifact-root");
  let cursor = root;
  for (const segment of relative(root, absolute).split(sep)) {
    cursor = join(cursor, segment);
    if (lstatSync(cursor).isSymbolicLink()) fail("source-symlink");
  }
  return absolute;
}

function objectKey(url) {
  let parsed;
  try { parsed = new URL(url); } catch { fail("invalid-object-url"); }
  if (parsed.origin !== "https://static.reallyme.net" || parsed.username ||
      parsed.password || parsed.search || parsed.hash ||
      !/^\/zk\/[A-Za-z0-9._/-]+$/u.test(parsed.pathname)) {
    fail("invalid-object-url");
  }
  const key = parsed.pathname.slice(1);
  if (key.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
    fail("invalid-object-key");
  }
  return key;
}

function assertOutputAbsent(outputRoot) {
  try {
    lstatSync(outputRoot);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    fail("output-status-unavailable");
  }
  // Never merge a new candidate with an older upload package. Operators review
  // a complete immutable set, and an existing package stays available on error.
  fail("output-already-exists");
}

export function stageStaticUpload({ rows, artifactRoot, outputRoot }) {
  let temporary;
  try {
    if (!Array.isArray(rows) || rows.length === 0 || rows.length > MAX_OBJECTS ||
        typeof artifactRoot !== "string" || typeof outputRoot !== "string") {
      fail("invalid-upload-inventory");
    }
    const root = resolve(artifactRoot);
    const output = resolve(outputRoot);
    if (root === output || root.startsWith(`${output}${sep}`) || output.startsWith(`${root}${sep}`)) {
      fail("output-overlaps-source");
    }
    const rootStatus = lstatSync(root);
    if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("invalid-artifact-root");
    assertOutputAbsent(output);
    const keys = new Set();
    const objects = [];
    for (const row of rows) {
      if (!Array.isArray(row) || row.length !== 4 ||
          row.some((value) => typeof value !== "string" || value.length > 4096) ||
          !/^[0-9a-f]{64}$/u.test(row[2])) {
        fail("invalid-upload-record");
      }
      const [path, url, expected, label] = row;
      const key = objectKey(url);
      if (!key.split("/").includes(expected)) {
        fail("object-key-hash-mismatch");
      }
      if (keys.has(key)) fail("duplicate-object-key");
      keys.add(key);
      const source = sourcePath(root, path);
      const identity = sha256File(source);
      if (identity.sha256 !== expected) fail("source-hash-mismatch");
      objects.push({ key, url, source: relative(root, source).split(sep).join("/"),
        sha256: expected, bytes: identity.bytes, contentType: contentType(key),
        cacheControl: CACHE_CONTROL, label });
    }
    objects.sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0);
    mkdirSync(dirname(output), { recursive: true });
    temporary = mkdtempSync(join(dirname(output), ".static-upload-"));
    for (const object of objects) {
      const destination = join(temporary, "objects", object.key);
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(join(root, object.source), destination);
      const copied = sha256File(destination);
      if (copied.sha256 !== object.sha256 || copied.bytes !== object.bytes) {
        fail("staged-object-mismatch");
      }
    }
    const manifest = { schemaVersion: 1, bucket: "static",
      publicBaseUrl: "https://static.reallyme.net/zk/", objects };
    writeFileSync(join(temporary, "upload-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    writeFileSync(join(temporary, "SHA256SUMS"),
      objects.map((object) => `${object.sha256}  objects/${object.key}\n`).join(""));
    renameSync(temporary, output);
    temporary = undefined;
    return manifest;
  } catch (error) {
    if (error instanceof StaticUploadError) throw error;
    throw new StaticUploadError("upload-staging-io-failed");
  } finally {
    if (temporary !== undefined) rmSync(temporary, { recursive: true, force: true });
  }
}
