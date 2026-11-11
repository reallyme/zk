#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ARCHIVE_BLOCK_BYTES = 512;
const HASH_BUFFER_BYTES = 64 * 1024;
const TAR_MAGIC = Buffer.from("ustar\0", "ascii");
const TAR_VERSION = Buffer.from("00", "ascii");
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_EXTRACTED_BYTES = 96 * 1024 * 1024;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 512;
const MAX_RELEASE_ASSETS = 64;
const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const ARCHIVE_PATH_PATTERN = /^[A-Za-z0-9._/-]+$/u;

export class SealedReleaseCandidateError extends Error {
  constructor(code) {
    super(code);
    this.name = "SealedReleaseCandidateError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new SealedReleaseCandidateError(code);
};

const isRecord = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isBoundedString = (value) =>
  typeof value === "string" && value.length > 0 && value.length <= 255;

const parseReleaseAsset = (value) => {
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value.id) ||
    value.id <= 0 ||
    typeof value.digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.digest) ||
    !isBoundedString(value.name) ||
    !Number.isSafeInteger(value.size) ||
    value.size <= 0 ||
    value.size > MAX_ARCHIVE_BYTES ||
    value.state !== "uploaded"
  ) {
    fail("invalid-release-metadata");
  }
  return Object.freeze({
    digest: value.digest,
    id: value.id,
    name: value.name,
  });
};

const parseCandidateRelease = (value) => {
  if (
    !isRecord(value) ||
    !Array.isArray(value.assets) ||
    value.assets.length > MAX_RELEASE_ASSETS ||
    typeof value.draft !== "boolean" ||
    typeof value.prerelease !== "boolean" ||
    !isBoundedString(value.tag_name) ||
    !isBoundedString(value.target_commitish)
  ) {
    fail("invalid-release-metadata");
  }
  return Object.freeze({
    assets: Object.freeze(value.assets.map(parseReleaseAsset)),
    draft: value.draft,
    prerelease: value.prerelease,
    tagName: value.tag_name,
    targetCommitish: value.target_commitish,
  });
};

const requireVersion = (value) => {
  if (typeof value !== "string" || !VERSION_PATTERN.test(value)) {
    fail("invalid-release-version");
  }
  return value;
};

const requireReleaseSha = (value) => {
  if (typeof value !== "string" || !FULL_SHA_PATTERN.test(value)) {
    fail("invalid-release-sha");
  }
  return value;
};

const requireSha256 = (value) => {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail("invalid-archive-sha256");
  }
  return value;
};

const requireRegularFile = (path, maximumBytes, code) => {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    fail(code);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail(code);
  }
  if (!Number.isSafeInteger(metadata.size) || metadata.size <= 0 || metadata.size > maximumBytes) {
    fail(code);
  }
  return metadata.size;
};

const addChecked = (left, right, code) => {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result < left || result < right) {
    fail(code);
  }
  return result;
};

const readExact = (descriptor, buffer, position, code) => {
  let offset = 0;
  while (offset < buffer.length) {
    const read = readSync(descriptor, buffer, offset, buffer.length - offset, position + offset);
    if (!Number.isSafeInteger(read) || read <= 0) {
      fail(code);
    }
    offset = addChecked(offset, read, code);
  }
};

const isZeroBlock = (buffer) => buffer.every((byte) => byte === 0);

const parseAscii = (buffer, start, end, code) => {
  let finish = start;
  while (finish < end && buffer[finish] !== 0) {
    const byte = buffer[finish];
    if (byte < 0x20 || byte > 0x7e) {
      fail(code);
    }
    finish += 1;
  }
  return buffer.subarray(start, finish).toString("ascii");
};

const parseOctal = (buffer, start, end, code) => {
  const encoded = parseAscii(buffer, start, end, code).trim();
  if (!/^[0-7]+$/u.test(encoded)) {
    fail(code);
  }
  const value = Number.parseInt(encoded, 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(code);
  }
  return value;
};

const requireHeaderChecksum = (header) => {
  const expected = parseOctal(header, 148, 156, "invalid-tar-checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual = addChecked(
      actual,
      index >= 148 && index < 156 ? 0x20 : header[index],
      "invalid-tar-checksum",
    );
  }
  if (actual !== expected) {
    fail("invalid-tar-checksum");
  }
};

const requireArchivePath = (rawPath, releaseVersion, isDirectory) => {
  const withoutTrailingSlash = rawPath.endsWith("/") ? rawPath.slice(0, -1) : rawPath;
  if (
    withoutTrailingSlash.length === 0 ||
    withoutTrailingSlash.length > 240 ||
    !ARCHIVE_PATH_PATTERN.test(withoutTrailingSlash) ||
    withoutTrailingSlash.startsWith("/") ||
    withoutTrailingSlash.includes("//") ||
    withoutTrailingSlash.includes("\\")
  ) {
    fail("invalid-archive-path");
  }
  const components = withoutTrailingSlash.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    fail("invalid-archive-path");
  }
  const permittedRoots = [`v1/${releaseVersion}`, "v1/poseidon2", "v1/sha256"];
  const isContainerDirectory =
    isDirectory &&
    (withoutTrailingSlash === "v1" || permittedRoots.includes(withoutTrailingSlash));
  const isPermittedMember = permittedRoots.some((root) =>
    withoutTrailingSlash.startsWith(`${root}/`),
  );
  if (!isContainerDirectory && !isPermittedMember) {
    fail("archive-path-outside-release");
  }
  if (normalize(withoutTrailingSlash).split(sep).join("/") !== withoutTrailingSlash) {
    fail("invalid-archive-path");
  }
  return withoutTrailingSlash;
};

const requireEmptyOutputPath = (outputPath) => {
  if (typeof outputPath !== "string" || !isAbsolute(outputPath)) {
    fail("invalid-output-root");
  }
  const parent = dirname(outputPath);
  let parentMetadata;
  try {
    parentMetadata = lstatSync(parent);
  } catch {
    fail("invalid-output-root");
  }
  if (!parentMetadata.isDirectory() || parentMetadata.isSymbolicLink() || realpathSync(parent) !== parent) {
    fail("invalid-output-root");
  }
  try {
    lstatSync(outputPath);
    fail("output-root-exists");
  } catch (error) {
    if (error instanceof SealedReleaseCandidateError) {
      throw error;
    }
  }
  mkdirSync(outputPath, { mode: 0o700 });
};

const requireArchiveDigest = (archive, expectedHex) => {
  const actual = createHash("sha256").update(archive).digest();
  const expected = Buffer.from(expectedHex, "hex");
  try {
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      fail("archive-digest-mismatch");
    }
  } finally {
    actual.fill(0);
    expected.fill(0);
  }
};

const writeArchiveFile = (archive, sourcePosition, fileBytes, destinationPath) => {
  const destinationDescriptor = openSync(
    destinationPath,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    let copied = 0;
    while (copied < fileBytes) {
      const remaining = fileBytes - copied;
      const requested = Math.min(HASH_BUFFER_BYTES, remaining);
      const sourceOffset = addChecked(sourcePosition, copied, "archive-length-overflow");
      const sourceEnd = addChecked(sourceOffset, requested, "archive-length-overflow");
      if (sourceEnd > archive.length) {
        fail("truncated-tar-entry");
      }
      const buffer = archive.subarray(sourceOffset, sourceEnd);
      let written = 0;
      while (written < requested) {
        const count = writeSync(destinationDescriptor, buffer, written, requested - written);
        if (!Number.isSafeInteger(count) || count <= 0 || count > requested - written) {
          fail("archive-write-failed");
        }
        written = addChecked(written, count, "archive-length-overflow");
      }
      copied = addChecked(copied, requested, "archive-length-overflow");
    }
    fsyncSync(destinationDescriptor);
  } finally {
    closeSync(destinationDescriptor);
  }
};

const requireZeroRemainder = (archive, start) => {
  if (!archive.subarray(start).every((byte) => byte === 0)) {
    fail("nonzero-data-after-tar-terminator");
  }
};

const inspectCandidateReleaseImpl = ({
  archiveSha256,
  metadataPath,
  releaseSha,
  releaseVersion,
  outputPath,
}) => {
  const expectedArchiveDigest = requireSha256(archiveSha256);
  requireReleaseSha(releaseSha);
  requireVersion(releaseVersion);
  requireRegularFile(metadataPath, 2 * 1024 * 1024, "invalid-release-metadata");
  let decoded;
  try {
    decoded = JSON.parse(readFileSync(metadataPath, "utf8"));
  } catch {
    fail("invalid-release-metadata");
  }
  const parsed = parseCandidateRelease(decoded);
  const expectedTag = `zk-candidate-v${releaseVersion}`;
  const expectedAssetName = `reallyme-zk-sealed-release-${releaseVersion}.tar`;
  if (
    parsed.tagName !== expectedTag ||
    parsed.targetCommitish !== releaseSha ||
    (!parsed.draft && !parsed.prerelease)
  ) {
    fail("candidate-release-identity-mismatch");
  }
  const matchingAssets = parsed.assets.filter((asset) => asset.name === expectedAssetName);
  if (
    matchingAssets.length !== 1 ||
    matchingAssets[0].digest !== `sha256:${expectedArchiveDigest}`
  ) {
    fail("candidate-release-asset-mismatch");
  }
  if (typeof outputPath !== "string" || !isAbsolute(outputPath)) {
    fail("invalid-github-output");
  }
  appendFileSync(outputPath, `asset_id=${matchingAssets[0].id}\nasset_name=${expectedAssetName}\n`, {
    encoding: "utf8",
  });
  return Object.freeze({ assetId: matchingAssets[0].id, assetName: expectedAssetName });
};

const extractCandidateArchiveImpl = ({ archivePath, expectedSha256, releaseVersion, outputPath }) => {
  const version = requireVersion(releaseVersion);
  const expectedDigest = requireSha256(expectedSha256);
  const archiveBytes = requireRegularFile(archivePath, MAX_ARCHIVE_BYTES, "invalid-candidate-archive");
  if (archiveBytes % ARCHIVE_BLOCK_BYTES !== 0) {
    fail("invalid-tar-length");
  }
  const descriptor = openSync(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let archive;
  try {
    const openedMetadata = fstatSync(descriptor);
    if (!openedMetadata.isFile() || openedMetadata.size !== archiveBytes) {
      fail("candidate-archive-changed");
    }
    // Parse and extract the exact bytes that were hashed. Re-reading a mutable
    // descriptor after the digest check admits content changed in place.
    archive = Buffer.alloc(archiveBytes);
    readExact(descriptor, archive, 0, "archive-read-failed");
  } finally {
    closeSync(descriptor);
  }
  requireArchiveDigest(archive, expectedDigest);
  requireEmptyOutputPath(outputPath);
  const seenPaths = new Set();
  let position = 0;
  let extractedBytes = 0;
  let entryCount = 0;
  let foundIndex = false;
  for (;;) {
    if (archiveBytes - position < ARCHIVE_BLOCK_BYTES) {
      fail("missing-tar-terminator");
    }
    const headerEnd = addChecked(position, ARCHIVE_BLOCK_BYTES, "archive-length-overflow");
    const header = archive.subarray(position, headerEnd);
    position = addChecked(position, ARCHIVE_BLOCK_BYTES, "archive-length-overflow");
    if (isZeroBlock(header)) {
      if (archiveBytes - position < ARCHIVE_BLOCK_BYTES) {
        fail("missing-tar-terminator");
      }
      const terminator = archive.subarray(position, position + ARCHIVE_BLOCK_BYTES);
      position = addChecked(position, ARCHIVE_BLOCK_BYTES, "archive-length-overflow");
      if (!isZeroBlock(terminator)) {
        fail("missing-tar-terminator");
      }
      requireZeroRemainder(archive, position);
      break;
    }

    entryCount = addChecked(entryCount, 1, "archive-entry-count-overflow");
    if (entryCount > MAX_ARCHIVE_ENTRIES) {
      fail("too-many-archive-entries");
    }
    requireHeaderChecksum(header);
    if (
      !header.subarray(257, 263).equals(TAR_MAGIC) ||
      !header.subarray(263, 265).equals(TAR_VERSION)
    ) {
      fail("invalid-tar-format");
    }
    const name = parseAscii(header, 0, 100, "invalid-archive-path");
    const prefix = parseAscii(header, 345, 500, "invalid-archive-path");
    const rawPath = prefix.length === 0 ? name : `${prefix}/${name}`;
    const type = header[156];
    const isDirectory = type === 0x35;
    const isRegularFile = type === 0 || type === 0x30;
    if (!isDirectory && !isRegularFile) {
      fail("unsupported-tar-entry-type");
    }
    const relativePath = requireArchivePath(rawPath, version, isDirectory);
    if (seenPaths.has(relativePath)) {
      fail("duplicate-archive-path");
    }
    seenPaths.add(relativePath);
    const fileBytes = parseOctal(header, 124, 136, "invalid-tar-size");
    if (isDirectory && fileBytes !== 0) {
      fail("directory-entry-has-data");
    }
    if (fileBytes > MAX_FILE_BYTES) {
      fail("archive-file-too-large");
    }
    extractedBytes = addChecked(extractedBytes, fileBytes, "archive-length-overflow");
    if (extractedBytes > MAX_EXTRACTED_BYTES) {
      fail("archive-content-too-large");
    }
    const destinationPath = join(outputPath, ...relativePath.split("/"));
    if (isDirectory) {
      mkdirSync(destinationPath, { mode: 0o700, recursive: true });
    } else {
      mkdirSync(dirname(destinationPath), { mode: 0o700, recursive: true });
      writeArchiveFile(archive, position, fileBytes, destinationPath);
      if (relativePath === `v1/${version}/index.pb`) {
        foundIndex = true;
      }
    }
    const paddedBytes = Math.ceil(fileBytes / ARCHIVE_BLOCK_BYTES) * ARCHIVE_BLOCK_BYTES;
    position = addChecked(position, paddedBytes, "archive-length-overflow");
    if (position > archiveBytes) {
      fail("truncated-tar-entry");
    }
  }
  if (!foundIndex || entryCount === 0) {
    fail("sealed-release-index-missing");
  }
  const indexMetadata = statSync(join(outputPath, "v1", version, "index.pb"));
  if (!indexMetadata.isFile() || indexMetadata.size <= 0) {
    fail("sealed-release-index-missing");
  }
  return Object.freeze({ entryCount, extractedBytes });
};

const mapIoFailure = (operation) => {
  try {
    return operation();
  } catch (error) {
    if (error instanceof SealedReleaseCandidateError) {
      throw error;
    }
    fail("candidate-io-failed");
  }
};

export const inspectCandidateRelease = (arguments_) =>
  mapIoFailure(() => inspectCandidateReleaseImpl(arguments_));

export const extractCandidateArchive = (arguments_) =>
  mapIoFailure(() => extractCandidateArchiveImpl(arguments_));

const main = () => {
  const [mode, ...arguments_] = process.argv.slice(2);
  if (mode === "metadata" && arguments_.length === 5) {
    inspectCandidateRelease({
      metadataPath: arguments_[0],
      releaseSha: arguments_[1],
      releaseVersion: arguments_[2],
      archiveSha256: arguments_[3],
      outputPath: arguments_[4],
    });
    console.log("sealed release candidate metadata accepted");
    return;
  }
  if (mode === "extract" && arguments_.length === 4) {
    extractCandidateArchive({
      archivePath: arguments_[0],
      expectedSha256: arguments_[1],
      releaseVersion: arguments_[2],
      outputPath: arguments_[3],
    });
    console.log("sealed release candidate archive accepted");
    return;
  }
  fail("invalid-arguments");
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    main();
  } catch (error) {
    const code =
      error instanceof SealedReleaseCandidateError ? error.code : "unexpected-candidate-failure";
    console.error(`sealed release candidate rejected: ${code}`);
    process.exit(1);
  }
}
