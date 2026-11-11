// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import { artifactByPath, artifacts, localPath, mirrorArtifacts, mirrorRoot, repositoryRoot, retainedArtifacts, ReleaseArtifactPathError } from "./release-artifact-manifest.mjs";

const swiftId = "swiftpm/ReallyMeZKPlatformFFI.xcframework.zip";
const swiftDigest = "60505f149fcf345a3c6132478aeed05dbc8ee8a7b245d96a7fedeeee4d27d341";

test("the Swift archive has exactly its checksum-addressed R2 key", () => {
  assert.equal(localPath(swiftId), join(mirrorRoot, "zk/swift", swiftDigest, "ReallyMeZKPlatformFFI.xcframework.zip"));
  assert.equal(artifactByPath(swiftId).sha256, swiftDigest);
});

test("built candidates use the same key scheme with their computed checksum", () => {
  const digest = "a".repeat(64);
  assert.equal(localPath(swiftId, digest), join(mirrorRoot, "zk/swift", digest, "ReallyMeZKPlatformFFI.xcframework.zip"));
  assert.equal(artifactByPath(swiftId).sha256, swiftDigest);
});

test("every mirror object preserves its remote key and fixed payload identity", () => {
  assert.equal(mirrorArtifacts.length, 7);
  for (const artifact of mirrorArtifacts) {
    assert.equal(localPath(artifact.path), join(mirrorRoot, "zk", artifact.remotePath));
    assert.ok(artifact.remotePath.split("/").includes(artifact.sha256));
  }
  assert.equal(retainedArtifacts.length, 1);
  assert.equal(retainedArtifacts[0].sha256, "da09e0d12c29c9173867374a74af93edf7ce1c16037e34ca6efd43aa9a42471b");
  assert.ok(Object.isFrozen(artifacts));
  assert.ok(Object.isFrozen(mirrorArtifacts));
  assert.ok(artifacts.every(Object.isFrozen));
});

test("native working files resolve separately under the common build root", () => {
  assert.equal(localPath("apple-platform-ffi"), join(repositoryRoot, "build/native/apple-platform-ffi"));
});

test("invalid identifiers and digest overrides have typed path failures", () => {
  for (const path of [null, undefined, "", "../outside", "/outside", "a/../outside", "a\\outside"]) {
    assert.throws(() => localPath(path), (error) => error instanceof ReleaseArtifactPathError && error.code === "invalid-artifact-path");
  }
  for (const digest of ["a".repeat(63), "../outside", "G".repeat(64)]) {
    assert.throws(() => localPath(swiftId, digest), (error) => error instanceof ReleaseArtifactPathError && error.code === "invalid-artifact-digest");
  }
  assert.throws(() => artifactByPath("unknown"), (error) => error instanceof ReleaseArtifactPathError && error.code === "unknown-artifact");
});
