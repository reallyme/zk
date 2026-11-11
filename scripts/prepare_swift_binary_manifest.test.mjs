#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { prepareManifest, SwiftManifestError } from "./prepare_swift_binary_manifest.mjs";

const fixture = `let ffiArtifactChecksum = "${"0".repeat(64)}"
let ffiArtifactVersion = "0.1.0"
let ffiArtifactLocalPathOverride = ""
`;
const checksum = "a".repeat(64);

test("binds version, checksum, and a normalized repository-local artifact", () => {
  const manifest = prepareManifest(
    fixture,
    "0.2.0",
    checksum,
    "build/swift/ReallyMeZKPlatformFFI.xcframework",
  );
  assert.match(manifest, new RegExp(`ffiArtifactChecksum = "${checksum}"`, "u"));
  assert.match(manifest, /ffiArtifactVersion = "0\.2\.0"/u);
  assert.match(manifest, /ffiArtifactLocalPathOverride = "build\/swift\/ReallyMeZKPlatformFFI\.xcframework"/u);
});

test("rejects malformed release inputs", () => {
  for (const [version, digest, path] of [
    ["v0.2.0", checksum, ""],
    ["0.2.0", "A".repeat(64), ""],
    ["0.2.0", checksum, "../ReallyMeZKPlatformFFI.xcframework"],
    ["0.2.0", checksum, "/tmp/ReallyMeZKPlatformFFI.xcframework"],
  ]) {
    assert.throws(() => prepareManifest(fixture, version, digest, path), SwiftManifestError);
  }
});

test("rejects ambiguous manifest assignments", () => {
  assert.throws(
    () => prepareManifest(`${fixture}${fixture}`, "0.2.0", checksum),
    (error) => error instanceof SwiftManifestError && error.code.endsWith("assignment-count"),
  );
});
