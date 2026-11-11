#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  SealedReleaseCandidateError,
  extractCandidateArchive,
  inspectCandidateRelease,
} from "./verify_sealed_release_candidate.mjs";

const BLOCK_BYTES = 512;
const releaseSha = "a".repeat(40);
const releaseVersion = "0.1.0";
const archiveSha256 = "c".repeat(64);
const temporaryRoots = [];

test.after(() => {
  for (const root of temporaryRoots) {
    rmSync(root, { force: true, recursive: true });
  }
});

const temporaryRoot = () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "reallyme-zk-candidate-test-")));
  temporaryRoots.push(root);
  return root;
};

const writeAscii = (buffer, offset, length, value) => {
  const encoded = Buffer.from(value, "ascii");
  if (encoded.length > length) {
    throw new RangeError("test fixture field is too long");
  }
  encoded.copy(buffer, offset);
};

const writeOctal = (buffer, offset, length, value) => {
  const encoded = value.toString(8).padStart(length - 1, "0");
  writeAscii(buffer, offset, length - 1, encoded);
  buffer[offset + length - 1] = 0;
};

const tarHeader = ({ name, size, type = "0" }) => {
  const header = Buffer.alloc(BLOCK_BYTES);
  writeAscii(header, 0, 100, name);
  writeOctal(header, 100, 8, type === "5" ? 0o700 : 0o600);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeAscii(header, 257, 6, "ustar");
  writeAscii(header, 263, 2, "00");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeAscii(header, 148, 6, checksum.toString(8).padStart(6, "0"));
  header[154] = 0;
  header[155] = 0x20;
  return header;
};

const createTar = (entries) => {
  const chunks = [];
  for (const entry of entries) {
    const data = entry.data ?? Buffer.alloc(0);
    chunks.push(tarHeader({ name: entry.name, size: data.length, type: entry.type }));
    if (data.length > 0) {
      chunks.push(data);
      const padding = (BLOCK_BYTES - (data.length % BLOCK_BYTES)) % BLOCK_BYTES;
      if (padding > 0) {
        chunks.push(Buffer.alloc(padding));
      }
    }
  }
  chunks.push(Buffer.alloc(BLOCK_BYTES * 2));
  return Buffer.concat(chunks);
};

const writeArchive = (root, bytes) => {
  const path = join(root, "candidate.tar");
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  return { path, sha256 };
};

test("candidate release metadata selects one exact draft asset", () => {
  const root = temporaryRoot();
  const metadataPath = join(root, "release.json");
  const outputPath = join(root, "github-output");
  writeFileSync(
    metadataPath,
    JSON.stringify({
      assets: [
        {
          id: 41,
          digest: `sha256:${archiveSha256}`,
          name: "reallyme-zk-sealed-release-0.1.0.tar",
          size: 2048,
          state: "uploaded",
        },
      ],
      draft: true,
      prerelease: false,
      tag_name: "zk-candidate-v0.1.0",
      target_commitish: releaseSha,
    }),
  );

  const result = inspectCandidateRelease({
    archiveSha256,
    metadataPath,
    outputPath,
    releaseSha,
    releaseVersion,
  });

  assert.deepEqual(result, {
    assetId: 41,
    assetName: "reallyme-zk-sealed-release-0.1.0.tar",
  });
  assert.equal(
    readFileSync(outputPath, "utf8"),
    "asset_id=41\nasset_name=reallyme-zk-sealed-release-0.1.0.tar\n",
  );
});

test("published or wrong-source candidate metadata fails closed", () => {
  const root = temporaryRoot();
  const metadataPath = join(root, "release.json");
  writeFileSync(
    metadataPath,
    JSON.stringify({
      assets: [
        {
          id: 41,
          digest: `sha256:${archiveSha256}`,
          name: "reallyme-zk-sealed-release-0.1.0.tar",
          size: 2048,
          state: "uploaded",
        },
      ],
      draft: false,
      prerelease: false,
      tag_name: "zk-candidate-v0.1.0",
      target_commitish: "b".repeat(40),
    }),
  );

  assert.throws(
    () =>
      inspectCandidateRelease({
        archiveSha256,
        metadataPath,
        outputPath: join(root, "github-output"),
        releaseSha,
        releaseVersion,
      }),
    (error) =>
      error instanceof SealedReleaseCandidateError &&
      error.code === "candidate-release-identity-mismatch",
  );
});

test("bounded ustar extraction admits one canonical sealed release", () => {
  const root = temporaryRoot();
  const archive = writeArchive(
    root,
    createTar([
      { name: "v1/0.1.0/index.pb", data: Buffer.from([1, 2, 3]) },
      { name: "v1/0.1.0/packages/manifest.pb", data: Buffer.from([4, 5]) },
    ]),
  );
  const outputPath = join(root, "extracted");

  const result = extractCandidateArchive({
    archivePath: archive.path,
    expectedSha256: archive.sha256,
    outputPath,
    releaseVersion,
  });

  assert.equal(result.entryCount, 2);
  assert.equal(result.extractedBytes, 5);
  assert.deepEqual(readFileSync(join(outputPath, "v1", "0.1.0", "index.pb")), Buffer.from([1, 2, 3]));
});

test("candidate extraction rejects non-POSIX tar magic and version", () => {
  for (const mutateHeader of [
    (header) => { header[262] = 0x20; }, // GNU tar uses a space after ustar.
    (header) => { header[263] = 0x20; }, // The version must be exactly 00.
  ]) {
    const root = temporaryRoot();
    const bytes = createTar([{ name: "v1/0.1.0/index.pb", data: Buffer.from([1]) }]);
    const header = bytes.subarray(0, BLOCK_BYTES);
    mutateHeader(header);
    header.fill(0x20, 148, 156);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeAscii(header, 148, 6, checksum.toString(8).padStart(6, "0"));
    header[154] = 0;
    header[155] = 0x20;
    const archive = writeArchive(root, bytes);
    assert.throws(
      () => extractCandidateArchive({
        archivePath: archive.path,
        expectedSha256: archive.sha256,
        outputPath: join(root, "extracted"),
        releaseVersion,
      }),
      (error) => error instanceof SealedReleaseCandidateError && error.code === "invalid-tar-format",
    );
  }
});

test("path traversal and link entries are rejected", () => {
  for (const entries of [
    [
      { name: "v1/0.1.0/index.pb", data: Buffer.from([1]) },
      { name: "v1/0.1.0/../../../escape", data: Buffer.from([2]) },
    ],
    [
      { name: "v1/0.1.0/index.pb", data: Buffer.from([1]) },
      { name: "v1/0.1.0/link", type: "2" },
    ],
  ]) {
    const root = temporaryRoot();
    const archive = writeArchive(root, createTar(entries));
    assert.throws(
      () =>
        extractCandidateArchive({
          archivePath: archive.path,
          expectedSha256: archive.sha256,
          outputPath: join(root, "extracted"),
          releaseVersion,
        }),
      SealedReleaseCandidateError,
    );
  }
});

test("digest mismatch and duplicate entries are rejected", () => {
  const digestRoot = temporaryRoot();
  const digestArchive = writeArchive(
    digestRoot,
    createTar([{ name: "v1/0.1.0/index.pb", data: Buffer.from([1]) }]),
  );
  assert.throws(
    () =>
      extractCandidateArchive({
        archivePath: digestArchive.path,
        expectedSha256: "0".repeat(64),
        outputPath: join(digestRoot, "extracted"),
        releaseVersion,
      }),
    (error) =>
      error instanceof SealedReleaseCandidateError && error.code === "archive-digest-mismatch",
  );

  const duplicateRoot = temporaryRoot();
  const duplicateArchive = writeArchive(
    duplicateRoot,
    createTar([
      { name: "v1/0.1.0/index.pb", data: Buffer.from([1]) },
      { name: "v1/0.1.0/index.pb", data: Buffer.from([2]) },
    ]),
  );
  assert.throws(
    () =>
      extractCandidateArchive({
        archivePath: duplicateArchive.path,
        expectedSha256: duplicateArchive.sha256,
        outputPath: join(duplicateRoot, "extracted"),
        releaseVersion,
      }),
    (error) =>
      error instanceof SealedReleaseCandidateError && error.code === "duplicate-archive-path",
  );
});
