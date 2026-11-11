// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

export const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
export const artifactRoot = resolve(process.env.REALLYME_ZK_LOCAL_ARTIFACT_ROOT ?? join(repositoryRoot, "build/native"));
export const mirrorRoot = resolve(process.env.REALLYME_ZK_R2_MIRROR_ROOT ?? join(repositoryRoot, "build/r2"));

export const artifacts = [
  {
    path: "swiftpm/ReallyMeZKPlatformFFI.xcframework.zip",
    remotePath: "swift/60505f149fcf345a3c6132478aeed05dbc8ee8a7b245d96a7fedeeee4d27d341/ReallyMeZKPlatformFFI.xcframework.zip",
    sha256: "60505f149fcf345a3c6132478aeed05dbc8ee8a7b245d96a7fedeeee4d27d341",
    distribution: true,
    label: "SwiftPM binary target XCFramework",
  },
  {
    path: "rust-cli/darwin-arm64/reallyme-zk",
    remotePath: "cli/macos-arm64/aabec6a9db4ef63177c48faa7217cbaa87fa8d9ab472af273b4a7904dd3d84bf/reallyme-zk",
    sha256: "aabec6a9db4ef63177c48faa7217cbaa87fa8d9ab472af273b4a7904dd3d84bf",
    distribution: true,
    label: "Rust CLI darwin arm64 binary",
  },
  {
    path: "mobile-circuit-artifacts-persona-credential-evidence-v1.tar",
    remotePath: "circuits/74990876329b137dc0bc073360423d64d08b8f0a50872639c4ed0dbfcffe89a9/mobile-circuits.tar",
    sha256: "74990876329b137dc0bc073360423d64d08b8f0a50872639c4ed0dbfcffe89a9",
    distribution: true,
    label: "Mobile circuit runtime artifact package",
  },
  {
    path: "cdn/crs/bn254_g1.prover",
    remotePath: "crs/0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5/bn254_g1.prover",
    sha256: "0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5",
    distribution: true,
    label: "BN254 prover CRS",
  },
  {
    path: "cdn/crs/bn254_g1.dat",
    remotePath: "crs/ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd/bn254_g1.dat",
    sha256: "ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd",
    distribution: true,
    label: "BN254 full G1 source CRS",
  },
  {
    path: "cdn/crs/bn254_g2.dat",
    remotePath: "crs/01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f/bn254_g2.dat",
    sha256: "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f",
    distribution: true,
    label: "BN254 verifier G2 CRS",
  },
  {
    path: "android-platform-jni/arm64-v8a/libreallyme_zk_platform_jni.so",
    sha256: "b7f7069cf1a859c5cb9ff27b29bb5dc5b5d04164fc00e8dcbf9dbf255f1c716b",
    distribution: false,
    label: "Android JNI library before AAR packaging",
  },
  {
    path: "android-platform-jni/arm64-v8a/libc++_shared.so",
    sha256: "7466ed097631a564ed6bff0b47768caa76bf03270d2047b5a65c03f497b824df",
    distribution: false,
    label: "Android C++ runtime before AAR packaging",
  },
];

// Published SDK versions keep their immutable binary target available.
export const retainedArtifacts = [{
  path: "swiftpm/0.3.0/ReallyMeZKPlatformFFI.xcframework.zip",
  remotePath: "swift/da09e0d12c29c9173867374a74af93edf7ce1c16037e34ca6efd43aa9a42471b/ReallyMeZKPlatformFFI.xcframework.zip",
  sha256: "da09e0d12c29c9173867374a74af93edf7ce1c16037e34ca6efd43aa9a42471b",
  distribution: true,
  label: "Published Swift 0.3.0 XCFramework",
}];
export const mirrorArtifacts = [...artifacts.filter((artifact) => artifact.distribution), ...retainedArtifacts];
const knownArtifacts = [...artifacts, ...retainedArtifacts];
for (const artifact of knownArtifacts) Object.freeze(artifact);
Object.freeze(artifacts);
Object.freeze(retainedArtifacts);
Object.freeze(mirrorArtifacts);

export class ReleaseArtifactPathError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseArtifactPathError";
    this.code = code;
  }
}

export function artifactByPath(path) {
  const artifact = knownArtifacts.find((candidate) => candidate.path === path);
  if (artifact === undefined) throw new ReleaseArtifactPathError("unknown-artifact");
  return artifact;
}

export function localPath(path, digest) {
  if (typeof path !== "string" || !/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u.test(path) ||
      path.split("/").some((part) => part === "." || part === "..")) {
    throw new ReleaseArtifactPathError("invalid-artifact-path");
  }
  const artifact = knownArtifacts.find((candidate) => candidate.path === path);
  if (artifact?.distribution === true) {
    if (digest !== undefined && (typeof digest !== "string" || !/^[0-9a-f]{64}$/u.test(digest))) {
      throw new ReleaseArtifactPathError("invalid-artifact-digest");
    }
    const key = digest === undefined ? artifact.remotePath : artifact.remotePath.replace(artifact.sha256, digest);
    return join(mirrorRoot, "zk", key);
  }
  if (digest !== undefined || path.split("/").some((part) => part === "..") || path.startsWith("/")) {
    throw new ReleaseArtifactPathError("invalid-artifact-path");
  }
  return join(artifactRoot, path);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , path, digest, extra] = process.argv;
  try {
    if (path === undefined || extra !== undefined) throw new ReleaseArtifactPathError("invalid-arguments");
    artifactByPath(path);
    console.log(localPath(path, digest));
  } catch (error) {
    if (!(error instanceof ReleaseArtifactPathError)) throw error;
    console.error(`release artifact path failed: ${error.code}`);
    process.exitCode = 1;
  }
}
