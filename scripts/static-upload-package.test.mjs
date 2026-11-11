// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { synchronizeStaticMirror, StaticUploadError } from "./static-upload-package.mjs";

function fixture(run) {
  const directory = mkdtempSync(join(tmpdir(), "r2-mirror-test-"));
  try {
    const outputRoot = join(directory, "r2");
    const payload = Buffer.from("public artifact fixture\n");
    const digest = createHash("sha256").update(payload).digest("hex");
    const key = `zk/swift/${digest}/fixture.zip`;
    const path = join(outputRoot, key);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, payload);
    const row = [path, `https://static.reallyme.net/${key}`, digest, "Fixture"];
    run({ directory, outputRoot, row, key, payload });
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}
const reason = (code) => (error) => error instanceof StaticUploadError && error.code === code;

test("the mirror contains exactly the bucket keys and no upload wrappers or metadata", () => {
  fixture(({ outputRoot, row, key, payload }) => {
    assert.deepEqual(synchronizeStaticMirror({ rows: [row], outputRoot }), [key]);
    assert.deepEqual(synchronizeStaticMirror({ rows: [row], outputRoot }), [key]);
    assert.deepEqual(readdirSync(outputRoot), ["zk"]);
    assert.deepEqual(readFileSync(row[0]), payload);
    for (const name of ["objects", "SHA256SUMS", "upload-manifest.json"]) {
      assert.equal(existsSync(join(outputRoot, name)), false);
    }
  });
});

test("refresh removes stale keys, empty directories, and Finder files after admission", () => {
  fixture(({ outputRoot, row }) => {
    const stale = join(outputRoot, "zk/swift/old/stale.zip");
    mkdirSync(dirname(stale), { recursive: true });
    writeFileSync(stale, "old");
    writeFileSync(join(outputRoot, ".DS_Store"), "Finder");
    assert.throws(() => synchronizeStaticMirror({ rows: [row], outputRoot, checkOnly: true }), reason("mirror-has-extra-entries"));
    synchronizeStaticMirror({ rows: [row], outputRoot });
    assert.equal(existsSync(dirname(stale)), false);
    assert.equal(existsSync(join(outputRoot, ".DS_Store")), false);
    synchronizeStaticMirror({ rows: [row], outputRoot, checkOnly: true });
  });
});

test("failed admission preserves the complete existing tree", () => {
  fixture(({ outputRoot, row }) => {
    const previous = join(outputRoot, "previous");
    writeFileSync(previous, "preserve");
    writeFileSync(row[0], "altered");
    assert.throws(() => synchronizeStaticMirror({ rows: [row], outputRoot }), reason("source-hash-mismatch"));
    assert.equal(readFileSync(previous, "utf8"), "preserve");
    rmSync(row[0]);
    assert.throws(() => synchronizeStaticMirror({ rows: [row], outputRoot }), reason("mirror-object-missing"));
    assert.equal(readFileSync(previous, "utf8"), "preserve");
  });
});

test("retained published objects are preserved with the current release inventory", () => {
  fixture(({ outputRoot, row, key }) => {
    const payload = Buffer.from("published version\n");
    const digest = createHash("sha256").update(payload).digest("hex");
    const retainedKey = `zk/swift/${digest}/fixture.zip`;
    const retainedPath = join(outputRoot, retainedKey);
    mkdirSync(dirname(retainedPath), { recursive: true });
    writeFileSync(retainedPath, payload);
    const retained = [retainedPath, `https://static.reallyme.net/${retainedKey}`, digest, "Published"];
    assert.deepEqual(synchronizeStaticMirror({ rows: [row, retained], outputRoot }), [key, retainedKey].sort());
    assert.deepEqual(readFileSync(retainedPath), payload);
  });
});

test("mirror admission rejects symlinks without following or removing their target", () => {
  fixture(({ directory, outputRoot, row }) => {
    const outside = join(directory, "outside");
    writeFileSync(outside, "preserve");
    symlinkSync(outside, join(outputRoot, "link"));
    assert.throws(() => synchronizeStaticMirror({ rows: [row], outputRoot }), reason("mirror-symlink"));
    assert.equal(readFileSync(outside, "utf8"), "preserve");
  });
});

test("mirror objects require the exact canonical local path and digest key", () => {
  fixture(({ directory, outputRoot, row }) => {
    assert.throws(() => synchronizeStaticMirror({ rows: [[join(directory, "outside"), ...row.slice(1)]], outputRoot }), reason("object-outside-mirror"));
    const changed = [row[0], row[1].replace(row[2], "0".repeat(64)), row[2], row[3]];
    assert.throws(() => synchronizeStaticMirror({ rows: [changed], outputRoot }), reason("object-key-hash-mismatch"));
    assert.throws(() => synchronizeStaticMirror({ rows: [row, row], outputRoot }), reason("duplicate-object-key"));
    for (const url of ["http://static.reallyme.net/zk/file", "https://example.com/zk/file", `${row[1]}?token=private`]) {
      assert.throws(() => synchronizeStaticMirror({ rows: [[row[0], url, row[2], row[3]]], outputRoot }), reason("invalid-object-url"));
    }
  });
});

test("empty and oversized objects fail before allocating the payload", () => {
  fixture(({ outputRoot, row }) => {
    for (const bytes of [0, 512_000_001]) {
      truncateSync(row[0], bytes);
      assert.throws(() => synchronizeStaticMirror({ rows: [row], outputRoot }), reason("invalid-object-size"));
    }
  });
});

test("empty and malformed inventories fail closed", () => {
  fixture(({ outputRoot, row }) => {
    for (const rows of [[], Array.from({ length: 257 }, () => row)]) {
      assert.throws(() => synchronizeStaticMirror({ rows, outputRoot }), reason("invalid-upload-inventory"));
    }
    assert.throws(() => synchronizeStaticMirror({ rows: [[]], outputRoot }), reason("invalid-upload-record"));
  });
});
