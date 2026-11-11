// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { stageStaticUpload, StaticUploadError } from "./static-upload-package.mjs";

function fixture(run) {
  const directory = mkdtempSync(join(tmpdir(), "static-upload-test-"));
  try {
    const artifactRoot = join(directory, "artifacts");
    const outputRoot = join(directory, "upload");
    mkdirSync(artifactRoot);
    const path = join(artifactRoot, "fixture.zip");
    const payload = Buffer.from("public artifact fixture\n");
    writeFileSync(path, payload);
    const sha256 = createHash("sha256").update(payload).digest("hex");
    const row = [path, `https://static.reallyme.net/zk/swift/${sha256}/fixture.zip`, sha256, "Fixture"];
    run({ directory, artifactRoot, outputRoot, row, payload });
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

const reason = (code) => (error) => error instanceof StaticUploadError && error.code === code;

test("staging creates only the exact object tree and separate portable upload metadata", () => {
  fixture(({ artifactRoot, outputRoot, row, payload, directory }) => {
    const manifest = stageStaticUpload({ rows: [row], artifactRoot, outputRoot });
    assert.equal(manifest.bucket, "static");
    assert.equal(manifest.objects.length, 1);
    const object = manifest.objects[0];
    assert.equal(object.key, `zk/swift/${row[2]}/fixture.zip`);
    assert.equal(object.contentType, "application/zip");
    assert.equal(object.cacheControl, "public, max-age=31536000, immutable");
    assert.deepEqual(readFileSync(join(outputRoot, "objects", object.key)), payload);
    const metadata = readFileSync(join(outputRoot, "upload-manifest.json"), "utf8");
    assert.ok(!metadata.includes(directory));
    assert.deepEqual(JSON.parse(metadata), manifest);
    assert.equal(readFileSync(join(outputRoot, "SHA256SUMS"), "utf8"), `${row[2]}  objects/${object.key}\n`);
    assert.equal(existsSync(join(outputRoot, "objects/upload-manifest.json")), false);
  });
});

test("staging rejects altered source bytes without creating an upload directory", () => {
  fixture(({ artifactRoot, outputRoot, row }) => {
    writeFileSync(row[0], "changed");
    assert.throws(() => stageStaticUpload({ rows: [row], artifactRoot, outputRoot }), reason("source-hash-mismatch"));
    assert.equal(existsSync(outputRoot), false);
  });
});

test("staging rejects duplicate keys, ambiguous URLs, and uploads outside the approved prefix", () => {
  fixture(({ artifactRoot, outputRoot, row }) => {
    assert.throws(() => stageStaticUpload({ rows: [row, row], artifactRoot, outputRoot }), reason("duplicate-object-key"));
    for (const url of ["https://example.com/zk/file", "http://static.reallyme.net/zk/file",
      "https://static.reallyme.net/other/file", "https://static.reallyme.net/zk/../../file",
      "https://static.reallyme.net/zk/file?token=private", "https://static.reallyme.net/zk/%2fetc"]) {
      assert.throws(() => stageStaticUpload({ rows: [[row[0], url, row[2], row[3]]], artifactRoot, outputRoot }), reason("invalid-object-url"));
    }
    assert.equal(existsSync(outputRoot), false);
  });
});

test("staging rejects source symlinks, outside files, and output overlapping its source", () => {
  fixture(({ artifactRoot, outputRoot, row, directory, payload }) => {
    const linked = join(artifactRoot, "link.zip");
    symlinkSync(row[0], linked);
    assert.throws(() => stageStaticUpload({ rows: [[linked, ...row.slice(1)]], artifactRoot, outputRoot }), reason("source-symlink"));
    const outside = join(directory, "outside.zip");
    writeFileSync(outside, payload);
    assert.throws(() => stageStaticUpload({ rows: [[outside, ...row.slice(1)]], artifactRoot, outputRoot }), reason("source-outside-artifact-root"));
    for (const output of [artifactRoot, join(artifactRoot, "upload"), directory]) {
      assert.throws(() => stageStaticUpload({ rows: [row], artifactRoot, outputRoot: output }), reason("output-overlaps-source"));
    }
  });
});

test("staging preserves an existing reviewed package", () => {
  fixture(({ artifactRoot, outputRoot, row }) => {
    mkdirSync(outputRoot);
    writeFileSync(join(outputRoot, "reviewed"), "preserve");
    assert.throws(() => stageStaticUpload({ rows: [row], artifactRoot, outputRoot }), reason("output-already-exists"));
    assert.equal(readFileSync(join(outputRoot, "reviewed"), "utf8"), "preserve");
  });
});

test("content-addressed keys must encode the exact payload digest", () => {
  fixture(({ artifactRoot, outputRoot, row }) => {
    const changed = [row[0], row[1].replace(row[2], "0".repeat(64)), row[2], row[3]];
    assert.throws(() => stageStaticUpload({ rows: [changed], artifactRoot, outputRoot }), reason("object-key-hash-mismatch"));
    const versioned = [row[0], "https://static.reallyme.net/zk/maven/me/really/zk/0.3.0/zk-0.3.0.jar", row[2], row[3]];
    assert.throws(() => stageStaticUpload({ rows: [versioned], artifactRoot, outputRoot }), reason("object-key-hash-mismatch"));
  });
});

test("empty and oversized objects fail before allocating their payload", () => {
  fixture(({ artifactRoot, outputRoot, row }) => {
    for (const bytes of [0, 512_000_001]) {
      truncateSync(row[0], bytes);
      assert.throws(() => stageStaticUpload({ rows: [row], artifactRoot, outputRoot }), reason("invalid-object-size"));
    }
  });
});

test("staging rejects empty, malformed, and oversized inventories", () => {
  fixture(({ artifactRoot, outputRoot, row }) => {
    for (const rows of [[], Array.from({ length: 257 }, () => row)]) {
      assert.throws(() => stageStaticUpload({ rows, artifactRoot, outputRoot }), reason("invalid-upload-inventory"));
    }
    for (const rows of [[[]], [[row[0], row[1], "wrong", row[3]]]]) {
      assert.throws(() => stageStaticUpload({ rows, artifactRoot, outputRoot }), reason("invalid-upload-record"));
    }
  });
});
