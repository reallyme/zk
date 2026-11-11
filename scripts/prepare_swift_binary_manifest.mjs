#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageManifest = resolve(repositoryRoot, "Package.swift");
const usage =
  "usage: node scripts/prepare_swift_binary_manifest.mjs <version> <swiftpm-checksum> [--local-artifact-path <relative-path>]";
const versionPattern = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const checksumPattern = /^[0-9a-f]{64}$/u;

export class SwiftManifestError extends Error {
  constructor(code) {
    super(code);
    this.name = "SwiftManifestError";
    this.code = code;
  }
}

const fail = (message) => {
  console.error(`prepare Swift binary manifest failed: ${message}`);
  process.exit(1);
};

const parseLocalArtifactPath = (options) => {
  if (options.length === 0) {
    return "";
  }
  if (options.length !== 2 || options[0] !== "--local-artifact-path") {
    throw new SwiftManifestError("invalid-arguments");
  }
  const value = options[1];
  if (value === undefined || value.length === 0) {
    throw new SwiftManifestError("empty-local-artifact-path");
  }
  if (value.startsWith("/") || value.includes("\\")) {
    throw new SwiftManifestError("absolute-or-non-posix-local-artifact-path");
  }
  if (!/^[A-Za-z0-9._/-]+$/u.test(value)) {
    throw new SwiftManifestError("unsupported-local-artifact-path-character");
  }
  const normalized = posix.normalize(value);
  if (normalized === "." || normalized.startsWith("../") || normalized.includes("/../")) {
    throw new SwiftManifestError("local-artifact-path-escapes-package-root");
  }
  return normalized;
};

const replaceSingleAssignment = (source, variableName, value) => {
  const pattern = new RegExp(`^let ${variableName} = "[^"]*"$`, "gmu");
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1) {
    throw new SwiftManifestError(`${variableName}-assignment-count`);
  }
  return source.replace(pattern, `let ${variableName} = "${value}"`);
};

export const prepareManifest = (source, version, checksum, localArtifactPath = "") => {
  if (!versionPattern.test(version)) {
    throw new SwiftManifestError("invalid-version");
  }
  if (!checksumPattern.test(checksum)) {
    throw new SwiftManifestError("invalid-checksum");
  }
  const normalizedLocalArtifactPath =
    localArtifactPath.length === 0 ? "" : parseLocalArtifactPath(["--local-artifact-path", localArtifactPath]);
  let manifest = replaceSingleAssignment(source, "ffiArtifactChecksum", checksum);
  manifest = replaceSingleAssignment(manifest, "ffiArtifactVersion", version);
  manifest = replaceSingleAssignment(
    manifest,
    "ffiArtifactLocalPathOverride",
    normalizedLocalArtifactPath,
  );
  return manifest;
};

const main = () => {
  const [, invokedPath, version, checksum, ...options] = process.argv;
  if (invokedPath === undefined || resolve(invokedPath) !== fileURLToPath(import.meta.url)) {
    return;
  }
  if (version === undefined || checksum === undefined) {
    fail(usage);
  }
  let localArtifactPath;
  try {
    localArtifactPath = parseLocalArtifactPath(options);
  } catch (error) {
    fail(error instanceof SwiftManifestError ? error.code : "invalid arguments");
  }
  try {
    const manifest = readFileSync(packageManifest, "utf8");
    writeFileSync(packageManifest, prepareManifest(manifest, version, checksum, localArtifactPath));
  } catch (error) {
    fail(error instanceof SwiftManifestError ? error.code : "could not update Package.swift");
  }
};

main();
