// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PlatformFacadePinPolicyError,
  readPlatformFacadePinSources,
  validatePlatformFacadePins,
} from "./check-platform-facade-pins.mjs";

const sources = readPlatformFacadePinSources(new URL("../", import.meta.url));

test("accepts current platform facade pins", () => {
  assert.doesNotThrow(() => validatePlatformFacadePins(sources));
});

test("allows matching SDK patch versions independently of the Rust release", () => {
  const changed = {
    ...sources,
    packageSwift: sources.packageSwift.replace(/^let ffiArtifactVersion = "[^"]+"$/mu,
      'let ffiArtifactVersion = "0.3.2"'),
    kotlinRootBuild: sources.kotlinRootBuild.replace(/^version = "[^"]+"$/mu,
      'version = "0.3.2"'),
  };
  assert.doesNotThrow(() => validatePlatformFacadePins(changed));
});

test("rejects differing Swift and Kotlin SDK versions", () => {
  const changed = {
    ...sources,
    kotlinRootBuild: sources.kotlinRootBuild.replace(/^version = "[^"]+"$/mu,
      'version = "0.3.2"'),
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "SDK_FACADE_VERSIONS_DIVERGE",
  );
});

test("rejects a missing Swift SDK version pin", () => {
  const changed = {
    ...sources,
    packageSwift: sources.packageSwift.replace(/^let ffiArtifactVersion = "[^"]+"$/mu, ""),
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "SWIFT_FACADE_VERSION_MISSING",
  );
});

test("rejects Swift runtime older than generated facade", () => {
  const changed = {
    ...sources,
    packageSwift: sources.packageSwift.replace('exact: "1.39.0"', 'exact: "1.37.0"'),
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "SWIFT_RUNTIME_OLDER_THAN_GENERATOR",
  );
});

test("allows Swift runtime newer than generated facade", () => {
  const changed = {
    ...sources,
    packageSwift: sources.packageSwift.replace('exact: "1.39.0"', 'exact: "1.40.0"'),
  };
  assert.doesNotThrow(() => validatePlatformFacadePins(changed));
});

test("rejects Java lite runtime older than generated facade", () => {
  const changed = {
    ...sources,
    kotlinProtoGeneratedBuild: sources.kotlinProtoGeneratedBuild.replace(
      "protobuf-javalite:4.36.2",
      "protobuf-javalite:4.34.0",
    ),
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "JAVALITE_RUNTIME_OLDER_THAN_GENERATED",
  );
});

test("rejects Kotlin lite runtime older than generated facade", () => {
  const changed = {
    ...sources,
    kotlinProtoGeneratedBuild: sources.kotlinProtoGeneratedBuild.replace(
      "protobuf-kotlin-lite:4.36.2",
      "protobuf-kotlin-lite:4.34.0",
    ),
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "KOTLIN_LITE_RUNTIME_OLDER_THAN_GENERATED",
  );
});

test("rejects generated Java version that does not match Buf generator", () => {
  const changed = {
    ...sources,
    generatedJava: sources.generatedJava.replace(
      "Protobuf Java Version: 4.35.1",
      "Protobuf Java Version: 4.34.0",
    ),
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "GENERATED_JAVA_VERSION_MISMATCH",
  );
});

test("rejects Kotlin subproject hardcoded package versions", () => {
  const changed = {
    ...sources,
    kotlinSubprojectBuilds: {
      ...sources.kotlinSubprojectBuilds,
      protoGenerated: `${sources.kotlinSubprojectBuilds.protoGenerated}\nversion = "0.1.0"\n`,
    },
  };
  assert.throws(
    () => validatePlatformFacadePins(changed),
    (error) =>
      error instanceof PlatformFacadePinPolicyError &&
      error.code === "KOTLIN_SUBPROJECT_VERSION_PIN_protoGenerated",
  );
});
