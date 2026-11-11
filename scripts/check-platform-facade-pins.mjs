#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SWIFT_PROTO_PACKAGE = "https://github.com/apple/swift-protobuf.git";
const PROTOBUF_JAVALITE = "com.google.protobuf:protobuf-javalite";
const PROTOBUF_KOTLIN_LITE = "com.google.protobuf:protobuf-kotlin-lite";

export class PlatformFacadePinPolicyError extends Error {
  constructor(code) {
    super(code);
    this.name = "PlatformFacadePinPolicyError";
    this.code = code;
  }
}

export function validatePlatformFacadePins(sources) {
  const swiftGenerator = requireRegex(
    sources.bufGen,
    /buf[.]build\/apple\/swift:v([0-9]+[.][0-9]+[.][0-9]+)/u,
    "SWIFT_GENERATOR_PIN_MISSING",
  );
  const swiftRuntime = requireRegex(
    sources.packageSwift,
    /url:\s*"https:\/\/github[.]com\/apple\/swift-protobuf[.]git"[\s\S]*?exact:\s*"([0-9]+[.][0-9]+[.][0-9]+)"/u,
    "SWIFT_RUNTIME_PIN_MISSING",
  );
  if (!sources.packageSwift.includes(SWIFT_PROTO_PACKAGE)) {
    throw new PlatformFacadePinPolicyError("SWIFT_RUNTIME_SOURCE_CHANGED");
  }
  if (compareSemver(swiftRuntime, swiftGenerator) < 0) {
    throw new PlatformFacadePinPolicyError("SWIFT_RUNTIME_OLDER_THAN_GENERATOR");
  }

  const javaGenerator = requireRegex(
    sources.bufGen,
    /buf[.]build\/protocolbuffers\/java:v([0-9]+)[.]([0-9]+)/u,
    "JAVA_GENERATOR_PIN_MISSING",
  );
  const kotlinGenerator = requireRegex(
    sources.bufGen,
    /buf[.]build\/protocolbuffers\/kotlin:v([0-9]+)[.]([0-9]+)/u,
    "KOTLIN_GENERATOR_PIN_MISSING",
  );
  if (javaGenerator !== kotlinGenerator) {
    throw new PlatformFacadePinPolicyError("PROTOBUF_GENERATOR_PINS_DIVERGE");
  }

  const generatedJavaRuntime = requireRegex(
    sources.generatedJava,
    /Protobuf Java Version:\s*([0-9]+[.][0-9]+[.][0-9]+)/u,
    "GENERATED_JAVA_VERSION_MISSING",
  );
  const expectedGeneratedJavaRuntime = protobufGeneratorRuntimeVersion(javaGenerator);
  if (generatedJavaRuntime !== expectedGeneratedJavaRuntime) {
    throw new PlatformFacadePinPolicyError("GENERATED_JAVA_VERSION_MISMATCH");
  }

  const javaliteRuntime = gradleDependencyVersion(
    sources.kotlinProtoGeneratedBuild,
    PROTOBUF_JAVALITE,
    "JAVALITE_RUNTIME_PIN_MISSING",
  );
  const kotlinLiteRuntime = gradleDependencyVersion(
    sources.kotlinProtoGeneratedBuild,
    PROTOBUF_KOTLIN_LITE,
    "KOTLIN_LITE_RUNTIME_PIN_MISSING",
  );
  if (compareSemver(javaliteRuntime, generatedJavaRuntime) < 0) {
    throw new PlatformFacadePinPolicyError("JAVALITE_RUNTIME_OLDER_THAN_GENERATED");
  }
  if (compareSemver(kotlinLiteRuntime, generatedJavaRuntime) < 0) {
    throw new PlatformFacadePinPolicyError("KOTLIN_LITE_RUNTIME_OLDER_THAN_GENERATED");
  }

  const kotlinFacadeVersion = requireRegex(
    sources.kotlinRootBuild,
    /^version\s*=\s*"([0-9]+[.][0-9]+[.][0-9]+)"$/mu,
    "KOTLIN_FACADE_VERSION_MISSING",
  );
  for (const [name, source] of Object.entries(sources.kotlinSubprojectBuilds)) {
    if (/^\s*version\s*=\s*"[0-9]+[.][0-9]+[.][0-9]+"/mu.test(source)) {
      throw new PlatformFacadePinPolicyError(`KOTLIN_SUBPROJECT_VERSION_PIN_${name}`);
    }
  }
  if (!sources.kotlinRootBuild.includes("version = rootProject.version")) {
    throw new PlatformFacadePinPolicyError("KOTLIN_SUBPROJECT_VERSION_INHERITANCE_MISSING");
  }
  if (!sources.kotlinAndroidNativeBuild.includes("version = rootProject.version.toString()")) {
    throw new PlatformFacadePinPolicyError("ANDROID_NATIVE_VERSION_INHERITANCE_MISSING");
  }
  if (!sources.kotlinAndroidNativeBuild.includes(`zk-android-\${rootProject.version}.aar`)) {
    throw new PlatformFacadePinPolicyError("ANDROID_NATIVE_AAR_PATH_VERSION_INHERITANCE_MISSING");
  }
  const swiftFacadeVersion = requireRegex(
    sources.packageSwift,
    /^let ffiArtifactVersion = "([0-9]+[.][0-9]+[.][0-9]+)"$/mu,
    "SWIFT_FACADE_VERSION_MISSING",
  );
  if (kotlinFacadeVersion !== swiftFacadeVersion) {
    throw new PlatformFacadePinPolicyError("SDK_FACADE_VERSIONS_DIVERGE");
  }
}

export function readPlatformFacadePinSources(repoRoot) {
  return Object.freeze({
    bufGen: readFileSync(new URL("buf.gen.yaml", repoRoot), "utf8"),
    generatedJava: readFileSync(new URL("gen/java/zk/reallyme/zk/v1/Manifest.java", repoRoot), "utf8"),
    kotlinAndroidNativeBuild: readFileSync(new URL("packages/kotlin/android-native/build.gradle.kts", repoRoot), "utf8"),
    kotlinProtoGeneratedBuild: readFileSync(new URL("packages/kotlin/proto-generated/build.gradle.kts", repoRoot), "utf8"),
    kotlinRootBuild: readFileSync(new URL("packages/kotlin/build.gradle.kts", repoRoot), "utf8"),
    kotlinSubprojectBuilds: Object.freeze({
      androidNative: readFileSync(new URL("packages/kotlin/android-native/build.gradle.kts", repoRoot), "utf8"),
      demo: readFileSync(new URL("packages/kotlin/demo/build.gradle.kts", repoRoot), "utf8"),
      demoAndroid: readFileSync(new URL("packages/kotlin/demo-android/build.gradle.kts", repoRoot), "utf8"),
      demoShared: readFileSync(new URL("packages/kotlin/demo-shared/build.gradle.kts", repoRoot), "utf8"),
      protoCodec: readFileSync(new URL("packages/kotlin/proto-codec/build.gradle.kts", repoRoot), "utf8"),
      protoGenerated: readFileSync(new URL("packages/kotlin/proto-generated/build.gradle.kts", repoRoot), "utf8"),
    }),
    packageSwift: readFileSync(new URL("Package.swift", repoRoot), "utf8"),
  });
}

function gradleDependencyVersion(source, dependency, code) {
  const escaped = dependency.replaceAll(".", "[.]");
  return requireRegex(source, new RegExp(`${escaped}:([0-9]+[.][0-9]+[.][0-9]+)`, "u"), code);
}

function protobufGeneratorRuntimeVersion(generatorVersion) {
  const [major, minor] = generatorVersion.split(".").map((part) => Number.parseInt(part, 10));
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor)) {
    throw new PlatformFacadePinPolicyError("PROTOBUF_GENERATOR_VERSION_MALFORMED");
  }
  return `4.${major}.${minor}`;
}

function compareSemver(left, right) {
  const leftParts = semverParts(left);
  const rightParts = semverParts(right);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] - rightParts[index];
    }
  }
  return 0;
}

function semverParts(version) {
  const parts = version.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 3 || parts.some((part) => !Number.isSafeInteger(part))) {
    throw new PlatformFacadePinPolicyError("SEMVER_MALFORMED");
  }
  return parts;
}

function requireRegex(source, pattern, code) {
  const match = pattern.exec(source);
  if (match === null) {
    throw new PlatformFacadePinPolicyError(code);
  }
  if (match.length === 3) {
    return `${match[1]}.${match[2]}`;
  }
  return match[1];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const repoRoot = new URL("../", import.meta.url);
  try {
    validatePlatformFacadePins(readPlatformFacadePinSources(repoRoot));
    process.stdout.write("platform facade pin policy passed\n");
  } catch (error) {
    if (error instanceof PlatformFacadePinPolicyError) {
      process.stderr.write(`platform facade pin policy failed: ${error.code}\n`);
      process.exitCode = 1;
    } else {
      throw error;
    }
  }
}
