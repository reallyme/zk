#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ZK_SCALAR_FIELD_CLASSIFICATIONS } from "./proto-hardening/zk-scalar-policy.mjs";
import {
  SWIFT_DEMO_PROJECT_PATH,
  validateSwiftDemoBundleProjectBoundarySource,
} from "./swift-demo-project-boundary.mjs";

const coreUrl =
  typeof process.env.RELEASE_READINESS_CORE_URL === "string" &&
  process.env.RELEASE_READINESS_CORE_URL.length > 0
    ? process.env.RELEASE_READINESS_CORE_URL
    : new URL("./release-readiness/core.mjs", import.meta.url).href;
const { createReleaseReadinessContext } = await import(coreUrl);

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const releaseReadinessVersion = "0.7.0";
process.env.RELEASE_READINESS_ENFORCED_VERSION ??= releaseReadinessVersion;

const supportedArguments = new Set([
  "--generated-freshness",
  "--policy-only",
  "--rust-release-packages",
]);
const suppliedArguments = process.argv.slice(2);
for (const argument of suppliedArguments) {
  if (!supportedArguments.has(argument)) {
    console.error(`release readiness check failed: unsupported argument ${argument}`);
    process.exit(2);
  }
}
if (new Set(suppliedArguments).size !== suppliedArguments.length) {
  console.error("release readiness check failed: duplicate arguments are not allowed");
  process.exit(2);
}

const generatedFreshnessMode = suppliedArguments.includes("--generated-freshness");
const policyOnlyMode = suppliedArguments.includes("--policy-only");
const rustReleasePackagesMode = suppliedArguments.includes("--rust-release-packages");
const fullPlatformVerificationMode =
  !generatedFreshnessMode && !policyOnlyMode && !rustReleasePackagesMode;
if (
  Number(generatedFreshnessMode) +
    Number(policyOnlyMode) +
    Number(rustReleasePackagesMode) >
  1
) {
  console.error("release readiness check failed: validation modes are mutually exclusive");
  process.exit(2);
}

if (rustReleasePackagesMode) {
  const releaseVersion = process.env.RELEASE_VERSION;
  if (!/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(releaseVersion ?? "")) {
    console.error("release readiness check failed: RELEASE_VERSION must be an exact semver release");
    process.exit(2);
  }
  for (const manifestPath of [
    "../crates/api/Cargo.toml",
    "../crates/artifacts/Cargo.toml",
    "../crates/proto/Cargo.toml",
    "../crates/proto-codec/Cargo.toml",
    "../crates/backend-bb/Cargo.toml",
  ]) {
    const manifest = readFileSync(new URL(manifestPath, import.meta.url), "utf8");
    if (!manifest.includes(`version = "${releaseVersion}"`)) {
      console.error(
        "release readiness check failed: RELEASE_VERSION does not match the public Rust wave",
      );
      process.exit(1);
    }
  }
}

const readiness = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

function failReleaseReadiness(message) {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
}

function assertSwiftDemoBundleProjectBoundary() {
  const projectPath = SWIFT_DEMO_PROJECT_PATH;
  const source = readFileSync(resolve(repoRoot, projectPath), "utf8");
  const failure = validateSwiftDemoBundleProjectBoundarySource(source, projectPath);
  if (failure !== null) {
    failReleaseReadiness(failure);
  }
}

function assertNoDocumentationSpdxHeaders() {
  const tracked = spawnSync(
    "git",
    ["ls-files", "-z", "--", "*.md", "*.txt"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (tracked.status !== 0) {
    readiness.fail("unable to enumerate tracked documentation");
  }
  for (const path of tracked.stdout.split("\0").filter(Boolean)) {
    const absolutePath = resolve(repoRoot, path);
    if (!existsSync(absolutePath)) {
      continue;
    }
    const source = readFileSync(absolutePath, "utf8");
    if (
      source.includes("SPDX-FileCopyrightText:") ||
      source.includes("SPDX-License-Identifier:")
    ) {
      readiness.fail(`${path} must not carry an SPDX header`);
    }
  }
}

function runRepositoryCommand(label, command, args) {
  const result = spawnSync(command, args, { cwd: repoRoot, stdio: "inherit" });
  if (result.error) {
    readiness.fail(`${label} failed to start`);
  }
  if (result.status !== 0) {
    readiness.fail(`${label} failed`);
  }
}

readiness.assertReallyMeReleasePackagePolicy({
  scriptPath: "scripts/check_release_readiness.mjs",
  version: "0.7.0",
});
readiness.runNodeCheck("scripts/check-release-readiness-policy-lock.mjs");
readiness.assertWorkflowActionsPinned();
readiness.assertNodeWorkflowJobsPinNode({ nodeVersion: "26" });
readiness.assertCargoFuzzWorkflowPolicy({
  version: "0.13.2",
  minimumInstallations: 1,
  requiredInstallSteps: [{ job: "build", name: "Install cargo-fuzz" }],
});
readiness.assertCargoWorkspacePolicy();
readiness.assertRepositoryShapePolicy({
  archetype: "protocol-engine",
  requiredLanes: ["crates", "contracts", "conformance", "docs", "scripts", ".github"],
  optionalLanes: ["vectors", "fuzz", "packages", "gen"],
  exceptions: [
    { path: "circuits", reason: "organization-specific" },
  ],
  crates: [
    { path: "crates/api", role: "domain" },
    { path: "crates/artifact-package", role: "support" },
    { path: "crates/artifacts", role: "storage" },
    { path: "crates/backend-bb", role: "provider" },
    { path: "crates/cli", role: "runtime" },
    { path: "crates/demo-fixture-generator", role: "support" },
    { path: "crates/noir-witness-core", role: "support" },
    { path: "crates/platform-ffi", role: "adapter" },
    { path: "crates/proto", role: "proto" },
    { path: "crates/proto-codec", role: "proto-codec" },
    { path: "crates/release-assembly", role: "support" },
    { path: "crates/release-process", role: "support" },
    { path: "crates/root-status-authority", role: "runtime" },
  ],
  subLanes: {
    gen: ["java", "kotlin"],
    packages: ["bbjs-provider", "kotlin", "swift"],
  },
  forbiddenPaths: ["bindings"],
  requireReleaseReadiness: true,
});
readiness.assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated"],
  baselinePath: null,
  productionTargetLines: 500,
  productionHardLines: 500,
  testTargetLines: 800,
  testHardLines: 800,
  moduleHardLines: 100,
  forbidWildcardImports: true,
  forbidInlineTests: true,
  forbidSubstantiveFacades: true,
  forbidPanickingProductionCode: true,
  forbidDynamicErrorSurfaces: true,
});
// Every mode checks platform source policy. Scoped modes verify that platform
// execution is delegated to the required CI jobs for the same source commit.
readiness.runNodeCheck("scripts/check-platform-size-contract.mjs");
runRepositoryCommand("platform size contract tests", "node", [
  "--test", "scripts/check-platform-size-contract.test.mjs",
]);
readiness.runNodeCheck("scripts/check-bbjs-provider-package.mjs");
runRepositoryCommand("bb.js provider package policy tests", "node", [
  "--test", "scripts/check-bbjs-provider-package.test.mjs",
]);
readiness.runNodeCheck("scripts/check-platform-facade-pins.mjs");
runRepositoryCommand("platform facade pin policy tests", "node", [
  "--test", "scripts/check-platform-facade-pins.test.mjs",
]);
runRepositoryCommand("bb.js provider tests", "node", [
  "--test", "packages/bbjs-provider/test/*.test.mjs",
]);
readiness.assertTypeScriptSourcePolicy({
  roots: ["packages/bbjs-provider/src"],
  tsconfigPaths: ["packages/bbjs-provider/tsconfig.json"],
  generatedPrefixes: [],
  baselinePath: null,
  productionTargetLines: 500,
  productionHardLines: 500,
  testTargetLines: 800,
  testHardLines: 800,
  facadeHardLines: 100,
  staticAnalysis: {
    files: [
      {
        path: "packages/bbjs-provider/tsconfig.json",
        required: [
          "\"strict\": true",
          "\"noImplicitAny\": true",
          "\"noUncheckedIndexedAccess\": true",
          "\"exactOptionalPropertyTypes\": true",
          "\"useUnknownInCatchVariables\": true",
          "\"noImplicitOverride\": true",
          "\"noFallthroughCasesInSwitch\": true",
          "\"noEmit\": true",
        ],
      },
      {
        path: "packages/bbjs-provider/package.json",
        required: [
          "\"type\": \"module\"",
          "\"types\": \"./src/index.d.ts\"",
          "\"test\": \"node --test test/*.test.mjs\"",
          "\"node\": \">=24\"",
        ],
      },
    ],
  },
  verification: [
    {
      roles: ["typecheck", "lint"],
      command: "node",
      args: ["scripts/check-bbjs-provider-package.mjs"],
    },
    {
      roles: ["test"],
      command: "node",
      args: ["--test", "packages/bbjs-provider/test/*.test.mjs"],
    },
  ],
});
if (existsSync(resolve(repoRoot, "packages/swift"))) {
  readiness.assertSwiftSourcePolicy({
    roots: ["packages/swift/Sources", "packages/swift/Tests", "packages/swift/Examples"],
    facadeFiles: ["packages/swift/Sources/ReallyMeZK/ReallyMeZK.swift"],
    generatedPrefixes: ["packages/swift/Sources/Generated/ReallyMeZkProtoGenerated"],
    baselinePath: null,
    productionTargetLines: 500,
    productionHardLines: 500,
    testTargetLines: 800,
    testHardLines: 800,
    facadeHardLines: 100,
    configuration: {
      files: [
        {
          path: "Package.swift",
          required: [
            "ReallyMeZKKit",
            "ReallyMeZKPlatformNative",
            "ReallyMeZKDemoBundle",
            "ReallyMeZKPlatformFFI",
            ".binaryTarget(",
            "ffiArtifactChecksum",
            "ffiArtifactVersion",
            "ffiArtifactLocalPathOverride",
            "static.reallyme.net/zk/swift/\\(ffiArtifactChecksum)",
            "checksum: ffiArtifactChecksum",
            "StrictConcurrency",
          ],
          forbidden: [],
        },
        {
          path: "packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo.xcodeproj/project.pbxproj",
          required: [
            "ReallyMeZKDemoBundle",
            "CodeSignOnCopy",
            "SWIFT_VERSION = 6.0;",
          ],
          forbidden: [
            "SWIFT_OBJC_BRIDGING_HEADER",
            "DEVELOPMENT_TEAM",
            "CODE_SIGN_IDENTITY",
            "PROVISIONING_PROFILE",
            "ReallyMeZKPlatformFFI.xcframework in Frameworks",
          ],
        },
      ],
    },
    verification: fullPlatformVerificationMode ? [
      {
        roles: ["format"],
        command: "packages/swift/scripts/check-format.sh",
        args: [],
      },
      {
        roles: ["lint"],
        command: "packages/swift/scripts/check-lint.sh",
        args: [],
      },
      {
        roles: ["build"],
        command: "swift",
        args: ["build", "-Xswiftc", "-warnings-as-errors"],
      },
      {
        roles: ["test"],
        command: "swift",
        args: ["test", "-Xswiftc", "-warnings-as-errors"],
      },
    ] : [{
      roles: ["format", "lint", "build", "test"],
      command: "node",
      args: ["scripts/check-platform-policy-delegation.mjs", "swift"],
    }],
  });
  assertSwiftDemoBundleProjectBoundary();
  if (fullPlatformVerificationMode) {
    runRepositoryCommand("Swift iOS demo build", "packages/swift/scripts/check-ios-demo-build.sh", []);
  }
}
if (existsSync(resolve(repoRoot, "packages/kotlin"))) {
  // The repository gate limits the typed exception's named base alias to its
  // superclass call; the shared policy still forbids generic error creation.
  readiness.runNodeCheck("scripts/check-kotlin-typed-errors.mjs");
  runRepositoryCommand("Kotlin typed-error policy tests", "node", [
    "--test", "scripts/check-kotlin-typed-errors.test.mjs",
  ]);
  readiness.assertKotlinSourcePolicy({
    roots: [
      "packages/kotlin/src",
      "packages/kotlin/proto-codec/src",
      "packages/kotlin/demo-shared/src",
      "packages/kotlin/demo/src",
      "packages/kotlin/demo-android/src",
    ],
    facadeFiles: ["packages/kotlin/src/main/kotlin/me/really/zk/ReallyMeZk.kt"],
    generatedPrefixes: ["gen/kotlin"],
    baselinePath: null,
    productionTargetLines: 500,
    productionHardLines: 500,
    testTargetLines: 800,
    testHardLines: 800,
    facadeHardLines: 100,
    configuration: {
      files: [
        {
          path: "packages/kotlin/settings.gradle.kts",
          required: [
            "include(\":android-native\")",
          ],
        },
        {
          path: "packages/kotlin/build.gradle.kts",
          required: [
            "explicitApi()",
            "allWarningsAsErrors = true",
            "com.android.library",
            "ktlintCheck",
            "detekt",
            "test",
          ],
        },
        {
          path: "packages/kotlin/android-native/build.gradle.kts",
          required: [
            "com.android.library",
            "maven-publish",
            "api(project(\":\"))",
            "jniLibs.directories.add",
            "checkAndroidJniFreshness",
            "checkAndroidJniSymbols",
            "assembleRelease",
            "singleVariant(\"release\")",
            "zk-android",
            "verifyPublishedAndroidAarNativeLibraries",
            "localReleaseArtifacts",
          ],
        },
        {
          path: "packages/kotlin/proto-codec/build.gradle.kts",
          required: [
            "explicitApi()",
            "allWarningsAsErrors = true",
            "ktlint",
            "detekt",
            "test",
          ],
        },
        {
          path: "packages/kotlin/demo-shared/build.gradle.kts",
          required: [
            "explicitApi()",
            "allWarningsAsErrors = true",
            "ktlintCheck",
            "detekt",
            "test",
          ],
        },
        {
          path: "packages/kotlin/demo-android/build.gradle.kts",
          required: [
            "com.android.application",
            "compileSdk = 37",
            "implementation(project(\":android-native\"))",
            "allWarningsAsErrors.set(true)",
            "-Xexplicit-api=strict",
            "testDebugUnitTest",
          ],
          forbidden: [
            "jniLibs.directories.add",
            "target/android-platform-jni",
          ],
        },
      ],
    },
    verification: fullPlatformVerificationMode ? [
      {
        roles: ["format"],
        command: "./packages/kotlin/gradlew",
        args: ["--project-dir", "packages/kotlin", "ktlintCheck"],
      },
      {
        roles: ["static-analysis"],
        command: "./packages/kotlin/gradlew",
        args: ["--project-dir", "packages/kotlin", "detekt"],
      },
      {
        roles: ["compile"],
        command: "./packages/kotlin/gradlew",
        args: [
          "--project-dir",
          "packages/kotlin",
          "compileKotlin",
          ":proto-generated:compileKotlin",
          ":proto-codec:compileKotlin",
          ":demo-shared:compileKotlin",
          ":android-native:assembleRelease",
          ":demo-android:compileDebugKotlin",
          ":demo-android:assembleDebug",
        ],
      },
      {
        roles: ["test"],
        command: "./packages/kotlin/gradlew",
        args: [
          "--project-dir",
          "packages/kotlin",
          "test",
          ":proto-codec:test",
          ":demo-shared:test",
          ":android-native:check",
          ":demo-android:testDebugUnitTest",
        ],
      },
    ] : [{
      roles: ["format", "static-analysis", "compile", "test"],
      command: "node",
      args: ["scripts/check-platform-policy-delegation.mjs", "kotlin"],
    }],
  });
}
readiness.runNodeCheck("scripts/harden-zk-generated.mjs", ["--check-idempotent"]);
readiness.runNodeCheck("scripts/check-proto-first-boundaries.mjs");
readiness.runNodeCheck("scripts/check-provider-manifest.mjs");
readiness.runNodeCheck("scripts/check-modern-circuit-source-lock.mjs");
runRepositoryCommand("modern circuit source lock tests", "node", [
  "--test", "scripts/check-modern-circuit-source-lock.test.mjs",
]);
readiness.runNodeCheck("scripts/check-demo-artifacts.mjs");
if (fullPlatformVerificationMode) {
  runRepositoryCommand("release artifact cache", "node", [
    "scripts/release-artifact-cache.mjs",
    "--check",
  ]);
}
if (fullPlatformVerificationMode) {
  runRepositoryCommand("Demo flow fixture freshness", "scripts/check-demo-flow-inputs.sh", []);
}
readiness.runNodeCheck("scripts/check-noir-security-profile.mjs");
if (fullPlatformVerificationMode) {
  runRepositoryCommand("Poseidon2 crypto contract", "scripts/check-poseidon2-crypto-contract.sh", []);
}
readiness.runNodeCheck("scripts/verify_release_attestation.test.mjs");
readiness.runNodeCheck("scripts/verify_sealed_release_candidate.test.mjs");
readiness.runNodeCheck("scripts/package-inventory-policy.test.mjs");
assertNoDocumentationSpdxHeaders();
readiness.runNodeCheck("scripts/check-spdx-headers.mjs");
readiness.assertSpdxHeaders({
  names: [],
  extensions: [
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".kts",
    ".mjs",
    ".proto",
    ".py",
    ".rs",
    ".sh",
    ".swift",
    ".toml",
    ".ts",
    ".vector",
    ".yaml",
    ".yml",
  ],
  exclusions: [
    { path: "circuits/vendor/poseidon-v0.2.0", reason: "vendored" },
    { path: "crates/proto/src/generated", reason: "generated" },
    { path: "gen/java/zk", reason: "generated" },
    { path: "gen/kotlin/zk", reason: "generated" },
    { path: "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated", reason: "generated" },
    { path: "scripts/release-readiness/core.mjs", reason: "vendored" },
  ],
  requireExclusionsMatched: true,
  requireExclusionReasons: true,
  copyright:
    "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
});
readiness.assertSpdxHeaders({
  names: [],
  extensions: [".nr"],
  exclusions: [
    { path: "circuits/vendor/poseidon-v0.2.0", reason: "vendored" },
  ],
  requireExclusionsMatched: true,
  requireExclusionReasons: true,
  copyright:
    "SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
});
readiness.assertProtoContract(
  "crates/proto/proto/reallyme/zk/v1/manifest.proto",
);
readiness.assertProtoContract(
  "crates/proto/proto/reallyme/zk/v1/zk_service.proto",
);

readiness.assertTextPolicy({
  files: [
    {
      path: "Cargo.toml",
      required: [
        '"crates/proto-codec"',
        'unsafe_code = "deny"',
        'unwrap_used = "deny"',
        'expect_used = "deny"',
        'panic = "deny"',
        'base64 = { version = "0.23.1"',
        'buffa = { version = "0.9.2"',
        'p256 = { version = "0.14.0"',
        'reallyme-codec = { version = "0.3.2"',
        'reallyme-ssi-proto = { version = "=0.6.1", default-features = false }',
        'rust-version = "1.99"',
        'sha2 = "0.11"',
      ],
      forbidden: [
        '"crates/conformance"',
        '"crates/proto/codec"',
        '"crates/proto/zk"',
        "connectrpc",
        'sha2 = "0.10"',
      ],
    },
    {
      path: "rust-toolchain.toml",
      required: [
        'channel = "1.99.0"',
        '"wasm32-unknown-unknown"',
      ],
      forbidden: ['channel = "1.98.1"'],
    },
    {
      path: "crates/backend-bb/Cargo.toml",
      required: [
        "publish = true",
        "wasm = []",
      ],
      forbidden: [
        "wasm-bindgen",
        "cdylib",
      ],
    },
    {
      path: "crates/platform-ffi/Cargo.toml",
      required: [
        'crate-type = ["rlib", "staticlib"]',
        "reallyme-zk-backend-bb =",
        "reallyme-zk-proto-codec =",
      ],
      forbidden: [
        "cdylib",
        "serde_json",
        "anyhow",
      ],
    },
    {
      path: "scripts/install_apple_barretenberg_static_archives.sh",
      required: [
        "barretenberg-static-arm64-darwin.tar.gz",
        "barretenberg-static-arm64-ios.tar.gz",
        "barretenberg-static-arm64-ios-sim.tar.gz",
        "310b2baaee0f8c8a96725d9cc246ffd41243ed8606965ad0c87f99428288d964",
        "c7350fb21963da64d59d1b94835dfcdf71a78ea05752ed56af7004e5fa7f671d",
        "5ca108540b0cf88731cb6e6c3017eb630efbcfa3091c234971b78f0fb012f494",
        "c554fc906e3d306946cb0620b2f5ee1d434fc0f7c02d9b2a56abd6b64b65ef87",
        "5f6fce5ef64354e0307a1adcde0e7ac7349ddc6164c43d75f1471b39ae1fdde3",
        "68ac9359b2a859a8e975e2db4c91e188280711b13b4bf70e632a96497520511b",
      ],
      forbidden: [],
    },
    {
      path: "scripts/build_swift_xcframework.sh",
      required: [
        "scripts/build_apple_platform_ffi_xcframework.sh",
        "scripts/check-apple-platform-ffi-freshness.sh",
        "scripts/install_apple_barretenberg_static_archives.sh",
        "ReallyMeZKPlatformFFI.xcframework.zip",
        "ReallyMeZKPlatformFFI.xcframework.checksum",
        "swift package compute-checksum",
      ],
      forbidden: [],
    },
    {
      path: "scripts/prepare_swift_binary_manifest.mjs",
      required: [
        "ffiArtifactChecksum",
        "ffiArtifactVersion",
        "ffiArtifactLocalPathOverride",
        "--local-artifact-path",
      ],
      forbidden: [],
    },
    {
      path: "scripts/verify_swift_release_artifact.mjs",
      required: [
        'execFileSync("swift", ["package", "compute-checksum"',
        "ReallyMeZKPlatformFFI.xcframework.zip",
        "static.reallyme.net/zk/swift",
        "reallyme_zk_platform_context_create",
        "reallyme_zk_platform_context_create_with_crs_files",
        "reallyme_zk_platform_dispatch",
        "reallyme_zk_platform_context_destroy",
        "reallyme_zk_platform_buffer_destroy",
        "reallyme_zk_platform_encode_failure_response",
      ],
      forbidden: [],
    },
    {
      path: "scripts/build_apple_platform_ffi_xcframework.sh",
      required: [
        "MACOS_BB_LIB_DIR",
        "IOS_BB_LIB_DIR",
        "IOS_SIM_BB_LIB_DIR",
        "ReallyMeZKPlatformFFI.xcframework",
        "reallyme_zk_platform_abi.h",
        "aarch64-apple-darwin",
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "mobile-release",
        "cargo_profile",
        "apple-platform-ffi-xcframework-v4",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "verify_archive_deployment_target",
        "check-platform-ffi-symbols.sh",
      ],
      forbidden: [
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/build_android_platform_ffi_static.sh",
      required: [
        "ANDROID_ARM64_BB_LIB_DIR",
        "aarch64-linux-android",
        "ANDROID_API_LEVEL",
        "reallyme_zk_platform_abi.h",
        "libreallyme_zk_platform_ffi.a",
        "ReallyMeZKPlatformFFI.build.tsv",
        "mobile-release",
        "cargo_profile",
        "android-platform-ffi-v1",
        "source_closure_sha256",
        "check-platform-ffi-symbols.sh",
      ],
      forbidden: [
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/build_android_platform_jni.sh",
      required: [
        "PLATFORM_FFI_DIR",
        "libreallyme_zk_platform_jni.so",
        "reallyme_zk_platform_jni.cc",
        "reallyme_zk_platform_jni.map",
        "libc++_shared.so",
        "ReallyMeZKPlatformJNI.build.tsv",
        "ReallyMeZKPlatformFFI.build.tsv",
        "platform_metadata_sha256",
        "check-platform-ffi-symbols.sh",
        "android-jni",
      ],
      forbidden: [
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/check-android-platform-jni-freshness.sh",
      required: [
        "android-platform-jni-v1",
        "android-platform-ffi-v1",
        "mobile-release",
        "android-platform-jni-source-closure.sh",
        "source_closure_sha256",
        "platform_archive_sha256",
        "platform_metadata_sha256",
        "platform_header_sha256",
        "jni_library_sha256",
        "libcxx_shared_sha256",
        "check-platform-ffi-symbols.sh",
        "android-jni",
      ],
      forbidden: [
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/android-platform-jni-source-closure.sh",
      required: [
        "Cargo.lock",
        "Cargo.toml",
        "crates/api",
        "crates/artifacts",
        "crates/backend-bb",
        "crates/platform-ffi",
        "crates/noir-witness-core",
        "crates/proto",
        "crates/proto-codec",
        "packages/kotlin/native/jni",
      ],
      forbidden: [
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/check-platform-ffi-symbols.sh",
      required: [
        "reallyme_zk_platform_context_create",
        "reallyme_zk_platform_context_create_with_crs_files",
        "reallyme_zk_platform_dispatch",
        "reallyme_zk_platform_context_destroy",
        "reallyme_zk_platform_buffer_destroy",
        "release_index_sha256_ptr",
        "reallyme_zk_platform_encode_failure_response",
        "private external _reallyme_bbapi_call",
        "GLOBAL[[:space:]]+HIDDEN",
        "android-jni",
        "Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeDispatch",
      ],
      forbidden: [
        "curl ",
        "git clone",
      ],
    },
    {
      path: "crates/proto-codec/Cargo.toml",
      required: [
        '"dep:reallyme-ssi-proto"',
        '"reallyme-ssi-proto/generated"',
        "reallyme-ssi-proto = { workspace = true, optional = true }",
      ],
      forbidden: [
        "crate-type",
        "staticlib",
        "reallyme-identity-common-proto",
        "../ssi/",
        "git =",
      ],
    },
    {
      path: "buf.gen.yaml",
      required: [
        "protoc-gen-buffa",
        "protoc-gen-buffa-packaging",
        "crates/proto/src/generated/buffa",
        "buf.build/apple/swift:v1.39.0",
        "buf.build/protocolbuffers/java:v35.1",
        "buf.build/protocolbuffers/kotlin:v35.1",
        "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated",
        "gen/java/zk",
        "gen/kotlin/zk",
      ],
      forbidden: [
        "protoc-gen-connect",
        "bufbuild/es",
      ],
    },
    {
      path: "crates/proto/proto/reallyme/zk/v1/manifest.proto",
      required: [
        "package reallyme.zk.v1;",
        "message ZkProviderOperationRequest",
        "message ZkProviderOperationResponse",
        "message ZkError",
        "enum ZkErrorReason",
        "enum ZkWitnessEncoding",
        "ZkWitnessEncoding encoding = 3;",
        "ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA = 1;",
        "ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA = 2;",
        'import "reallyme/zk/v1/capabilities.proto";',
      ],
      forbidden: [
        "service ZkProviderService",
        "enum ZkProofSystem",
        "ZkProofSystem proof_system",
        "[deprecated = true]",
        "reserved ",
        "ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_NON_ZK_NO_IPA",
      ],
    },
    {
      path: "crates/proto/proto/reallyme/zk/v1/zk_service.proto",
      required: [
        'import "reallyme/zk/v1/manifest.proto";',
        "service ZkProviderService",
        "rpc ZkProviderOperation(ZkProviderOperationRequest) returns (ZkProviderOperationResponse);",
      ],
      forbidden: ["connectrpc"],
    },
    {
      path: "crates/proto/Cargo.toml",
      required: [
        "publish = true",
        '"/proto/**/*.proto"',
        '"/src/**/*.rs"',
        '"/tests/**/*"',
      ],
      forbidden: ['"/tests/**/*.rs"'],
    },
    {
      path: "crates/artifact-package/Cargo.toml",
      required: ['reallyme-codec = { workspace = true, features = ["hex"] }'],
      forbidden: [],
    },
    {
      path: "crates/artifact-package/src/bin/check-release-index-attestation.rs",
      required: [
        "reallyme_codec::hex::lower_hex_to_bytes(value)",
        "<[u8; SHA256_BYTES]>::try_from(decoded)",
        "ATTESTED_NARGO_VERSION",
        "build_capability_registry",
      ],
      forbidden: ["fn hex_nibble", "HEX_RADIX"],
    },
    {
      path: "crates/release-assembly/src/bin/check-release-source-attestation.rs",
      required: [
        "validate_release_source_attestation",
        "ArtifactVersion::try_from_token",
      ],
      forbidden: [],
    },
    {
      path: "crates/release-assembly/src/source_attestation.rs",
      required: [
        "SealedRelease::load_candidate_and_check",
        "SealedArtifactPackage::load_and_check",
        "SourceTree::load",
        "noir_source_tree_sha256",
        "noir_source_sha256",
      ],
      forbidden: [],
    },
    {
      path: "scripts/harden-zk-generated.mjs",
      required: [
        'from "./proto-hardening/core.mjs"',
        "ZK_SCALAR_FIELD_CLASSIFICATIONS",
        "hardenGeneratedProto({",
        'binaryOnlyJsonMessages: ["ZkWitness"]',
        "--check-idempotent",
      ],
      forbidden: ["writeFileSync", "function hardenOneof"],
    },
    {
      path: "scripts/proto-hardening/core.mjs",
      required: [
        "export function hardenGeneratedProto",
        "parseProtoContracts",
        "messageReferences",
        "transitivelySensitiveMessages",
        "hardenSensitiveByteSerializers",
        "hardenUnknownFieldOwners",
        "ReallyMeZeroizingUnknownFields",
        "hardenBinaryOnlyJsonMessages",
        "__reallyme_reject_binary_only_bytes",
        "zeroizingSerializationHelper",
        "::reallyme_codec::base64::bytes_to_base64",
        "decoded.as_mut_slice().zeroize()",
        "deserialize_zeroizing_bytes",
        "hardenOneofs",
        "hardenViewOneofs",
      ],
      forbidden: [],
    },
    {
      path: "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.rs",
      required: [
        "fn __reallyme_zeroize_unknown_fields(",
        "impl ::core::ops::Drop for ReallyMeZeroizingUnknownFields",
        "pub __buffa_unknown_fields: ReallyMeZeroizingUnknownFields,",
        "#[serde(default, deny_unknown_fields)]",
        "impl ::core::ops::Drop for ZkWitness",
        'field("encoded", &"<redacted>")',
        "deserialize_zeroizing_bytes",
        "fn __reallyme_serialize_zeroizing_bytes",
        "fn __reallyme_deserialize_zeroizing_bytes",
        "::reallyme_codec::base64::bytes_to_base64",
        "decoded.as_mut_slice().zeroize()",
        'serialize_with = "__reallyme_serialize_zeroizing_bytes"',
        'serialize_with = "__reallyme_reject_binary_only_bytes"',
        "binary-only protobuf transport",
      ],
      forbidden: [
        '.field("encoded", &self.encoded)',
        "pub __buffa_unknown_fields: ::buffa::UnknownFields,",
        "::buffa::alloc::format!(",
      ],
    },
    {
      path: "crates/proto/tests/generated_tests.rs",
      required: ["fn witness_protojson_is_binary_only()"],
      forbidden: [],
    },
    {
      path: "crates/proto/tests/generated_tests/sensitive_bindings.rs",
      required: ["fn sensitive_borrowed_views_are_binary_only()"],
      forbidden: [],
    },
    {
      path: "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.__view.rs",
      required: [
        "DigestView(<redacted>)",
        "ZkPublicInputsView(<redacted>)",
        "NamedPublicInputView(<redacted>)",
        "ZkProofPackageView(<redacted>)",
        "ZkSessionBindingView(<redacted>)",
        "ZkWitnessView(<redacted>)",
        "JSON serialization is disabled for this binary-only view",
        "binary-only protobuf transport",
      ],
      forbidden: [
        "OwnedView",
        "DigestOwnedView",
        "ZkArtifactManifestOwnedView",
        "ZkPublicInputsOwnedView",
        "NamedPublicInputOwnedView",
        "ZkProofPackageOwnedView",
        "ZkClaimProofBundleStageProofPackageOwnedView",
        "ZkClaimProofBundleOwnedView",
        "ZkSessionBindingOwnedView",
        "ZkExpectedStageProofShapeOwnedView",
        "ZkExpectedClaimProofBundleProofShapeOwnedView",
        "ZkWitnessOwnedView",
        "ZkClaimProofBundleWitnessOwnedView",
        "ZkClaimProofBundleProveOperationOwnedView",
        "ZkClaimProofBundleVerifyOperationOwnedView",
        "ZkStageProveOperationOwnedView",
        "ZkStageVerifyOperationOwnedView",
        "ZkProviderOperationRequestOwnedView",
        "ZkProviderOperationResultOwnedView",
        "ZkProviderOperationResponseOwnedView",
        "ZkProvingVectorOwnedView",
        "ZkProvingVectorSetOwnedView",
        "ZkReleaseArtifactPinOwnedView",
        "ZkVerificationVectorOwnedView",
        "ZkVerificationVectorSetOwnedView",
        "ZkReleaseVerificationVectorPinOwnedView",
        "ZkReleaseIndexOwnedView",
      ],
    },
    {
      path: "crates/proto/src/generated/buffa/reallyme.zk.v1.mod.rs",
      required: ["ZkWitnessView"],
      forbidden: [
        "OwnedView",
        "DigestOwnedView",
        "ZkArtifactManifestOwnedView",
        "ZkPublicInputsOwnedView",
        "NamedPublicInputOwnedView",
        "ZkProofPackageOwnedView",
        "ZkClaimProofBundleStageProofPackageOwnedView",
        "ZkClaimProofBundleOwnedView",
        "ZkSessionBindingOwnedView",
        "ZkExpectedStageProofShapeOwnedView",
        "ZkExpectedClaimProofBundleProofShapeOwnedView",
        "ZkWitnessOwnedView",
        "ZkClaimProofBundleWitnessOwnedView",
        "ZkClaimProofBundleProveOperationOwnedView",
        "ZkClaimProofBundleVerifyOperationOwnedView",
        "ZkStageProveOperationOwnedView",
        "ZkStageVerifyOperationOwnedView",
        "ZkProviderOperationRequestOwnedView",
        "ZkProviderOperationResultOwnedView",
        "ZkProviderOperationResponseOwnedView",
        "ZkProvingVectorOwnedView",
        "ZkProvingVectorSetOwnedView",
        "ZkReleaseArtifactPinOwnedView",
        "ZkVerificationVectorOwnedView",
        "ZkVerificationVectorSetOwnedView",
        "ZkReleaseVerificationVectorPinOwnedView",
        "ZkReleaseIndexOwnedView",
      ],
    },
    {
      path: "crates/api/src/suite.rs",
      required: [
        "pub enum ZkProofSuite",
        "BarretenbergUltraHonkKeccakZkNoIpa",
        "pub const PRODUCTION",
      ],
      forbidden: ["Poseidon2NonZk", "pub enum ZkProofSystem"],
    },
    {
      path: "crates/api/src/bundle/tests.rs",
      required: [
        "fn standalone_credential_envelope_cannot_grant_claim_admission()",
        "fn bundle_rejects_diagnostic_envelope_root_chain_mismatch()",
        "ZkClaimProofBundleStage::CredentialEnvelope",
        "ZkPublicInputName::EnvelopeBinding",
        "ZkErrorReason::BindingMismatch",
      ],
      forbidden: [],
    },
    {
      path: "crates/cli/src/runner.rs",
      required: [
        "verify-stage (diagnostic only; never presentation admission)",
      ],
      forbidden: [],
    },
    {
      path: "crates/cli/src/stage_commands.rs",
      required: [
        "verify-stage: diagnostic-stage-proof-ok; not-presentation-admission",
      ],
      forbidden: [
        "verify-stage: ok",
        "verify-stage: verified",
      ],
    },
    {
      path: "packages/swift/Sources/ReallyMeZK/ReallyMeZKProvider.swift",
      required: [
        "func verifyDiagnosticStage(",
        "request: ReallyMeZKStageVerifyRequest",
        "proof: ProofHandle",
      ],
      forbidden: [
        "func verify(\n    request: ReallyMeZKStageVerifyRequest",
      ],
    },
    {
      path: "packages/kotlin/src/main/kotlin/me/really/zk/ReallyMeZkProvider.kt",
      required: [
        "public fun verifyDiagnosticStage(",
        "request: ZkStageVerifyRequest",
        "proof: ProofHandle",
      ],
      forbidden: [
        "public fun verify(\n        request: ZkStageVerifyRequest",
      ],
    },
    {
      path: "crates/proto-codec/src/lib.rs",
      required: ["mod domain;", "pub mod error;", "pub mod exchange;", "pub mod proof;"],
      forbidden: ["pub mod domain;"],
    },
    {
      path: "crates/proto-codec/src/exchange.rs",
      required: [
        "pub enum ZkProviderOperationKind",
        "pub fn decode_operation_request_kind",
        "decode_operation_request(request_bytes)",
        "let operation =",
        "pub fn validate_operation_exchange",
        "response.request_sha256() != Digest32::sha256(request_bytes)",
        "ZkProviderOperationOutcome::Failure",
        "ZkErrorReason::BackendFailure",
      ],
      forbidden: [
        "pub fn validate_operation_response_for_kind",
        "format!",
        "unwrap(",
        "expect(",
      ],
    },
    {
      path: "crates/proto-codec/tests/exchange_tests.rs",
      required: [
        "fn canonical_fixture_exchange_preserves_typed_provider_failure()",
        "fn success_result_must_match_the_request_operation()",
        "fn malformed_request_fails_before_response_validation()",
        "fn response_for_one_canonical_request_cannot_be_cross_paired()",
      ],
      forbidden: [],
    },
    {
      path: "crates/proto/tests/fixtures/protobuf/artifact-operation.pb.hex",
      required: ["2a0c0a0808011001180420011001"],
      forbidden: ["2a00"],
    },
    {
      path: "crates/proto/tests/fixtures/protojson/artifact-operation.json",
      required: [
        '"credentialHashAlgorithm":"ZK_CREDENTIAL_HASH_ALGORITHM_SHA256"',
        '"family":"ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1"',
        '"stage":"ZK_CIRCUIT_STAGE_CLAIM"',
        '"circuitRevision":1',
      ],
      forbidden: [],
    },
    {
      path: "crates/api/src/proof.rs",
      required: [
        "pub enum ZkWitnessEncoding",
        "NoirWitnessStackV1",
        "try_from_noir_witness_stack_v1",
        "try_from_noir_witness_stack_v1_zeroizing",
        "pub const fn encoding(&self) -> ZkWitnessEncoding",
      ],
      forbidden: ["try_from_exact_bytes", "try_from_exact_zeroizing_bytes"],
    },
    {
      path: "crates/proto-codec/src/operation.rs",
      required: [
        "MAX_ZK_PROTO_OPERATION_BYTES",
        ".with_unknown_field_limit(ZK_PROTO_UNKNOWN_FIELD_LIMIT)",
        "zk_proto_from_json",
        "fn encode_canonical_operation(",
        "Zeroizing<Vec<u8>>",
        ".try_encode_bounded(maximum, &mut *encoded)",
        "ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1",
        "try_from_noir_witness_stack_v1",
      ],
      forbidden: [
        "saturating_add",
        "Result<ZkProviderOperation, String>",
        "request.encode_to_vec()",
      ],
    },
    {
      path: "crates/proto-codec/tests/operation_tests.rs",
      required: ["DomainWitnessEncoding::NoirWitnessStackV1"],
      forbidden: [],
    },
    {
      path: "crates/proto-codec/tests/operation_tests/validation_failure_tests.rs",
      required: [
        "fn unspecified_witness_encoding_fails_closed()",
        "fn unknown_witness_encoding_fails_closed()",
      ],
      forbidden: [],
    },
    {
      path: "crates/proto-codec/src/result.rs",
      required: [
        "fn encode_canonical_response(",
        "Zeroizing<Vec<u8>>",
        ".try_encode_bounded(maximum, &mut *encoded)",
      ],
      forbidden: ["response.encode_to_vec()"],
    },
    {
      path: "crates/proto-codec/src/vector.rs",
      required: ["let mutated = Zeroizing::new(request.encode_to_vec())"],
      forbidden: ["let mut canonical = vector_set.encode_to_vec()"],
    },
    {
      path: "crates/proto-codec/src/vector/decoding.rs",
      required: ["let canonical = Zeroizing::new(vector_set.encode_to_vec())"],
      forbidden: ["let mut canonical = vector_set.encode_to_vec()"],
    },
    {
      path: "crates/proto-codec/src/verification_vector.rs",
      required: ["let mutated = Zeroizing::new(request.encode_to_vec())"],
      forbidden: ["let mut canonical = vector_set.encode_to_vec()"],
    },
    {
      path: "crates/proto-codec/src/verification_vector/decoding.rs",
      required: ["let canonical = Zeroizing::new(vector_set.encode_to_vec())"],
      forbidden: ["let mut canonical = vector_set.encode_to_vec()"],
    },
    {
      path: "crates/proto-codec/src/protojson.rs",
      required: [
        "MAX_ZK_PROTO_JSON_BYTES",
        "MAX_ZK_PROTO_MESSAGE_BYTES",
        "pub trait ZkProtoJson",
        "struct BoundedJsonWriter",
        "checked_add(input.len())",
        "try_encode_bounded",
        "Zeroizing<String>",
        "serde_json::from_slice",
        "enforce_operation_request_json_policy",
        "SecretOperationUnsupported",
        "advance_json_cursor",
        ".checked_add(1)",
      ],
      forbidden: [
        "Result<M, String>",
        "Vec::with_capacity(MAX_ZK_PROTO_JSON_BYTES)",
        "pb::ZkProvingVectorSet",
      ],
    },
    {
      path: "docs/platform-binding-contract.md",
      required: [
        "This repository provides first-party Swift and Kotlin provider packages",
        "packages/swift",
        "packages/kotlin",
        "tests/fixtures/protobuf",
        "tests/fixtures/protojson",
        "Connect",
        "reallyme_zk_platform_encode_failure_response",
        "reallyme_zk_platform_context_create",
        "reallyme_zk_platform_dispatch",
        "reallyme_zk_platform_context_destroy",
        "reallyme_zk_platform_buffer_destroy",
        "release-index SHA-256 digest",
        "descriptor-relative no-follow path traversal",
        "scripts/build_apple_platform_ffi_xcframework.sh",
        "scripts/build_android_platform_ffi_static.sh",
        "scripts/build_android_platform_jni.sh",
        "reallyme_zk_platform_jni.map",
        "Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeDispatch",
        "typed `ZkErrorReason` values",
        "canonical `NoirWitnessStackV1` encoding discriminator",
      ],
      forbidden: [
        "identity-sdk",
        "Platform bindings and packaging remain in `reallyme/identity`",
      ],
    },
    {
      path: "docs/provenance/toolchain-artifact-provenance.md",
      required: [
        "candidateMatchedPair.status = \"promoted\"",
        "modern-circuit-source-lock.tsv",
        "verify_sealed_release_candidate.mjs",
        "exact source revision and sealed artifacts",
        "Swift and Android presentation",
      ],
      forbidden: [
        "candidateMatchedPair.status = \"gate_pending\"",
      ],
    },
    {
      path: "scripts/publish-crates-in-order.mjs",
      required: [
        "validatePackageInventory",
        "PackageInventoryError",
        "unexpected-package-inventory-failure",
      ],
      forbidden: ["shell: true"],
    },
    {
      path: "scripts/check-proto-first-boundaries.mjs",
      required: [
        "requireExactDirectoryFiles",
        '"manifest.proto"',
        '"zk_service.proto"',
        '"malicious-duplicate-field.json"',
        '"backend-unavailable-response.pb.hex"',
      ],
      forbidden: [],
    },
    {
      path: "scripts/test-modern-soundness-regressions.sh",
      required: [
        "field-to-u128-zero-branch",
        "acir-five-distinct-witnesses",
        "mutate_witness_field",
        "run_bb_verify_rejects",
        "run_bb_prove_rejects",
        "mutate_proof_bytes",
        "Proof verification failed",
        "64323764613183177041862057485226039389",
        "53438638232309528389504892708671455233",
        "private-persona-negated-subject",
        "private persona x must differ from credential subject x",
        "private-claim-high-index-bits",
        "merkle root mismatch",
        "private-claim-index-out-of-range",
        "index exceeds path depth",
        "NARGO must point at the pinned modern nargo executable",
        "BB must point at the pinned modern bb executable",
      ],
      forbidden: [
        "field-to-u128-invalid",
        "grep -q RANGE",
      ],
    },
    {
      path: "scripts/soundness-regression-assertions.sh",
      required: [
        "Proof verification failed",
        "Failed to verify the generated proof!",
        "left proof artifacts after rejecting the witness",
        "MAX_PROOF_BYTES",
      ],
      forbidden: [],
    },
    {
      path: "scripts/test-modern-linked-promotion-gate.sh",
      required: [
        "REALLYME_CLI_RETAINED_PROVE_COMMAND",
        "REALLYME_CLI_RETAINED_PUBLIC_INPUTS",
        "REALLYME_CLI_RETAINED_SRS_COMMAND",
        "REALLYME_NATIVE_PROVE_THEN_VERIFY=1",
        "REALLYME_CLI_PROVE_VERIFY_RETAINED=1",
        "reallyme-zk-noir-witness-core",
        "circuit_boundary_contracts",
        "bounded_hash_tail_vectors",
        "poseidon2-bounded-fixture",
        "did not execute any tests",
      ],
      forbidden: ["return Ok(())"],
    },
    {
      path: "scripts/test-modern-linked-cli-cross-verify.sh",
      required: [
        "BB must point at the pinned official candidate bb executable",
        "BB_CRS_DIR must name a plain absolute CRS directory",
        "BB hash does not match circuits/toolchain-lock.json",
        "BB version does not match circuits/toolchain-lock.json",
        "CRS file identity does not match the toolchain lock",
        "REALLYME_ZK_ALL_CIRCUITS_V1_ROOT",
        "REALLYME_BN254_G1_PATH",
        "REALLYME_BN254_G2_PATH",
        "native_linked_cli_cross_verify",
        "test result: ok\\. 1 passed; 0 failed",
        "did not execute exactly one test",
        "linked-generated proof verified by isolated official bb",
      ],
      forbidden: [
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/test-modern-linked-all30-matrix.sh",
      required: [
        "native_linked_private_persona_composition",
        "linked_private_persona_same_fixture_compares_verified_session_links",
        "test result: ok\\. 1 passed; 0 failed",
        "did not execute exactly one test",
      ],
      forbidden: [
        "native_linked_private_persona_composition -- --ignored",
      ],
    },
    {
      path: "scripts/test-linked-private-persona-distinct-subject.sh",
      required: [
        "REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT",
        "linked_private_persona_distinct_hidden_subject_credentials_share_session_link",
        "test result: ok\\. 1 passed; 0 failed",
        "did not execute exactly one signed-vector proof test",
      ],
      forbidden: [
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "crates/demo-fixture-generator/src/generate-private-persona-distinct-fixtures.rs",
      required: [
        "mod generate_private_persona_distinct_fixtures;",
        "generate_private_persona_distinct_fixtures::run",
        "audit_message()",
      ],
      forbidden: [
        "unwrap(",
        "expect(",
        "panic!",
      ],
    },
    {
      path: "crates/demo-fixture-generator/src/generate_private_persona_distinct_fixtures.rs",
      required: [
        "validate_managed_output_tree",
        "first.issuer_public_key == second.issuer_public_key",
        "first.credential_binding != wrong.credential_binding",
        "REQUIRED_CIRCUIT_MARKERS",
        "CredentialMaterial::try_new(0)",
        "CredentialMaterial::try_new(1)",
      ],
      forbidden: [
        "unwrap(",
        "expect(",
        "panic!",
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "crates/demo-fixture-generator/src/generate_private_persona_distinct_fixtures/crypto.rs",
      required: [
        "ISSUER_A_SCALAR",
        "ISSUER_B_SCALAR",
        "SUBJECT_A_SCALAR",
        "SUBJECT_B_SCALAR",
        "WRONG_PERSONA_SCALAR",
        "BINDMRK1",
        "BINDSUB1",
        "LINK1",
        "normalize_s()",
        "material_label",
        "credential-a",
        "credential-b",
      ],
      forbidden: [
        "unwrap(",
        "expect(",
        "panic!",
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "crates/demo-fixture-generator/src/generate_private_persona_distinct_fixtures/crypto/transcript.rs",
      required: ["PERS2", "PSESB2", "ENVB1", "CREDB1"],
      forbidden: ["unwrap(", "expect(", "panic!"],
    },
    {
      path: "scripts/test-generated-private-persona-distinct-subject.sh",
      required: [
        "GENERATED_PRIVATE_PERSONA_FIXTURE_ROOT",
        "TARGET_ROOT",
        "pwd -P",
        "generate-private-persona-distinct-fixtures",
        "-- generate",
        "-- check",
        "REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT",
        "test-linked-private-persona-distinct-subject.sh",
      ],
      forbidden: [
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/prepare-modern-retained-proof-matrix.sh",
      required: [
        "REALLYME_RETAINED_RUN_LABEL",
        "modern-run-01",
        "verification_key",
        "claim_bundle_4",
        "output root must be empty",
      ],
      forbidden: [
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "crates/backend-bb/tests/native_linked_claim_bundle_capacity.rs",
      required: [
        "ZkCircuitStage::ClaimBundle4",
        "rows.len() != expected_count",
        "baseline_cumulative_process_rss_high_water_kib",
        "after_prove_cumulative_process_rss_high_water_kib",
        "ZkErrorReason::BindingMismatch",
        "flip_nonce(binding)",
        "wrong_binding",
      ],
      forbidden: [
        "REALLYME_NATIVE_LARGEST_CLAIM_PROOF_BUNDLE_CAPACITY",
        "return Ok(())",
        "unwrap(",
        "expect(",
        "panic!",
      ],
    },
    {
      path: "scripts/test-native-linked-claim-bundle-capacity.sh",
      required: [
        "REALLYME_CLAIM_BUNDLE_CAPACITY_SUMMARY",
        "native_linked_claim_bundle_capacity",
        "claim_bundle_4_capacity_is_measured_with_negative_binding_checks",
        "test result: ok\\. 1 passed; 0 failed",
        "header plus four claim_bundle_4 rows",
      ],
      forbidden: [
        "rm -rf",
        "curl ",
        "git clone",
      ],
    },
    {
      path: "scripts/check-noir-advisory-ancestry.sh",
      required: [
        "GHSA-cp84-xrj5-49vg",
        "field-to-u128-zero-branch",
        "fix_or_release_revision",
        "noir_1_0_0_descends_from_patched_release",
        "noir_1_0_0_descends_from_fix_commit",
      ],
      forbidden: ['"advisory\\tfix_commit\\tpatched_version"'],
    },
    {
      path: "docs/provenance/noir-1.0.0-security-fixes-v1.tsv",
      required: [
        "GHSA-cp84-xrj5-49vg",
        "GHSA-2v53-vfw3-w489",
        "GHSA-xw6r-48f5-gc77",
        "field-to-u128-zero-branch",
        "2026-09-30",
      ],
      forbidden: ["advisory\tfix_commit\tpatched_version"],
    },
    {
      path: "circuits/security-regressions/field-to-u128-zero-branch/src/main.nr",
      required: [
        "let x = inp as u128;",
        "if x == 0",
        "out = 2;",
      ],
      forbidden: ["false as Field"],
    },
    {
      path: "circuits/security-regressions/acir-five-distinct-witnesses/src/main.nr",
      required: [
        "a * b + c + d + e == 9",
        "five distinct witnesses must constrain",
      ],
      forbidden: ["to_be_bytes"],
    },
    {
      path: "scripts/package-inventory-policy.mjs",
      required: [
        "MAX_INVENTORY_BYTES",
        "MAX_INVENTORY_FILES",
        "FORBIDDEN_PACKAGE_ROOTS",
        "REQUIRED_PACKAGE_FILES",
        "tests/fixtures/protobuf/artifact-operation.pb.hex",
        "tests/fixtures/protojson/malicious-unknown-enum.json",
        "unexpected-package-schema",
        "unexpected-package-fixture",
      ],
      forbidden: ["throw new Error", "console."],
    },
    {
      path: "fuzz/fuzz_targets/protojson_contracts.rs",
      required: [
        "ZkProviderOperationRequest",
        "zk_proto_from_json",
        "zk_proto_to_json",
        "round_trip_if_admitted",
      ],
      forbidden: ["ZkProvingVectorSet", "unsafe"],
    },
    {
      path: "fuzz/README.md",
      required: ["`protojson_contracts`", "witness bytes must never be added"],
      forbidden: [],
    },
    {
      path: "contracts/CONTRACT.md",
      required: [
        "The versioned message schema is message-only",
        "the separate, transport-neutral `zk_service.proto` imports it",
        "Connect dependencies, generated Connect output",
        "Executable proving operations and witness-bearing values are binary-only",
        "Every witness carries the closed `ZkWitnessEncoding` discriminator",
        "Identity and claim fields must not be",
        "all generated views are borrowed-only",
        "recursively zeroizing wrapper",
      ],
      forbidden: ["The protobuf schema declares Connect services"],
    },
    {
      path: "crates/proto-codec/README.md",
      required: [
        "binary-only proving rule",
        "`ZkProvingVectorSet` is intentionally absent",
        "Unspecified or unknown witness encodings fail as malformed protobuf",
      ],
      forbidden: [],
    },
    {
      path: ".github/workflows/swift-package-preflight.yml",
      required: [
        "scripts/verify_required_ci.mjs",
        'REQUIRED_CI_WAIT_SECONDS: "0"',
        "components: llvm-tools-preview",
        "REALLYME_ZK_ARTIFACT_TRANSPORT: r2",
        "scripts/release-artifact-cache.mjs --hydrate --distribution-only --swift-only",
        "packages/swift/ReallyMeZKPlatformFFI.xcframework.build.tsv",
        "scripts/check-apple-platform-ffi-freshness.sh",
        "swift-xcframework-${{ inputs.version }}-${{ needs.verify-source-sha.outputs.release_sha }}",
        "scripts/prepare_swift_binary_manifest.mjs",
        "scripts/verify_swift_release_artifact.mjs",
        "scripts/verify_sdk_release_version.mjs",
        "--local-artifact-path build/native/apple-platform-ffi/ReallyMeZKPlatformFFI.xcframework",
        "swift test -Xswiftc -warnings-as-errors",
        "ref: 18a6d91d99837e80f92e41fe04effb0b043d754e",
      ],
      forbidden: ["scripts/build_swift_xcframework.sh"],
    },
    {
      path: ".github/workflows/swift-package-release.yml",
      required: [
        "scripts/verify_swift_release_preflight.mjs",
        "SWIFT_PREFLIGHT_RUN_ID: ${{ needs.verify-release-sha.outputs.preflight_run_id }}",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "scripts/verify_swift_release_artifact.mjs",
        "scripts/verify_sdk_release_version.mjs",
        "node scripts/publish_github_release.mjs --publish --swift",
        "group: github-release-${{ github.repository }}",
        "scripts/release-artifact-manifest.mjs",
        "build/swift/ReallyMeZKPlatformFFI.xcframework.build.tsv",
      ],
      forbidden: ["scripts/verify_release_attestation.mjs", "scripts/prepare_swift_binary_manifest.mjs", "gh release create"],
    },
    {
      path: "scripts/publish_github_release.mjs",
      required: [
        "reallyme-zk-v${version}",
        "release-tag-target-mismatch",
        "release-asset-conflict",
        "legacy-release-exists",
        "release-assets-missing-after-upload",
        "release-sha-is-not-current-main",
        "discoverReleases(root, request)",
        "release-inventory-limit-exceeded",
      ],
      forbidden: ["--clobber", "throw new Error", "git push"],
    },
    {
      path: ".github/workflows/rust-ci.yml",
      required: [
        "toolchain: 1.99.0",
        "public-crate-msrv:",
        "lane: [native, all-features, default]",
        "node scripts/run_bounded_nextest.mjs",
        "security-mutations:",
        "test -n \"$mutation_list\"",
        "env -u CARGO_TARGET_DIR cargo mutants --gitignore true",
        "cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check",
        "node scripts/check-public-crate-baselines.mjs",
        "toolchain: 1.99.0",
        "cargo +1.99.0 check --locked --all-features",
        "--exclude reallyme-zk-root-status-authority",
        "--package reallyme-zk-api",
        "--package reallyme-zk-artifacts",
        "--package reallyme-zk-proto",
        "scripts/test-modern-production-circuits.sh",
        "scripts/test-persona-credential-evidence-linked-proofs.py",
        "scripts/test-persona-credential-evidence-joined-circuits.py",
        "scripts/test-persona-credential-evidence-current-state-circuits.py",
        "scripts/check-poseidon2-crypto-contract.sh",
        "scripts/test-modern-soundness-regressions.sh",
        "scripts/test-modern-linked-all30-matrix.sh",
        "scripts/test-modern-linked-cli-cross-verify.sh",
        "ios-demo-resources/zk_demo",
        'node scripts/stage-demo-mobile-assets.mjs "${demo_fixture}"',
        'REALLYME_ZK_PLATFORM_DEMO_FIXTURES_REQUIRED: "1"',
        "--test demo_fixture_witness_tests",
        'grep -Fq "running 0 tests"',
        "demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider",
        "test demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider ... ok",
        "repository: reallyme/ssi",
        "ref: 77f5c5874403599e64c1bc79fe40ed54cfcf2e77",
        "repository: reallyme/openid4vci",
        "ref: 9ba35e61057dbbe1c56515c400636721469ba4b7",
        "repository: reallyme/openid4vp",
        "ref: 90d5a5a7349268aed2d2945b1f9f96b7fe9bd8db",
        "REALLYME_ZK_REQUIRED_OPEN_STACK_CHECKOUTS: ssi,openid4vci,openid4vp",
      ],
      forbidden: [
        "repository: reallyme/cose",
        "ba7676ec3402ac09cadf5ffac55bc7615180ff9e",
      ],
    },
    {
      path: ".github/workflows/crates-package-preflight.yml",
      required: [
        "toolchain: 1.99.0",
        '= "1.99.0"',
        "REQUIRED_CI_WRITE_GITHUB_OUTPUT",
        "scripts/run-gitleaks.sh",
        "scripts/audit_committed_lockfiles.sh",
        "ref: 18a6d91d99837e80f92e41fe04effb0b043d754e",
        "node .release-readiness/scripts/run-consumer-check.mjs",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "subject-path: reviewed-crates/*.crate",
      ],
      forbidden: ["toolchain: 1.98.1"],
    },
    {
      path: ".github/workflows/crates-release.yml",
      required: [
        "environment: crates-io",
        "toolchain: 1.99.0",
        '= "1.99.0"',
        "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}",
        "gh attestation verify",
        "REVIEWED_CRATE_DIRECTORY: reviewed-crates",
        "PUBLICATION_LEDGER_PATH:",
        "prepare-source-release:",
        "finalize:",
        "node scripts/publish_github_release.mjs --prepare",
        "node zk/scripts/publish_github_release.mjs --publish",
        "group: github-release-${{ github.repository }}",
      ],
      forbidden: [
        "environment: crates-release",
        "toolchain: 1.98.1",
        "id-token: write",
      ],
    },
    {
      path: ".github/workflows/protobuf-ci.yml",
      required: [
        "toolchain: 1.99.0",
        "buf format --diff --exit-code crates/proto/proto",
        "buf breaking --against",
        "scripts/check-proto-breaking.sh",
        "scripts/check-generated-protos.sh",
      ],
      forbidden: [],
    },
    {
      path: ".github/workflows/secret-scan.yml",
      required: ["fetch-depth: 0", "scripts/run-gitleaks.sh"],
      forbidden: [],
    },
    {
      path: ".github/workflows/repository-security.yml",
      required: ["private-vulnerability-reporting", "grep -qx true"],
      forbidden: [],
    },
    {
      path: ".github/workflows/sealed-release-package-attestation.yml",
      required: [
        "check-release-index-attestation",
        "check-release-source-attestation",
        "reallyme-zk-release-assembly",
        "id-token: write",
      ],
      forbidden: [],
    },
    {
      path: ".github/workflows/sealed-release-attestation.yml",
      required: [
        "github.workflow_ref == 'reallyme/zk/.github/workflows/sealed-release-package-attestation.yml@refs/heads/main'",
        "check-release-index-attestation",
        "check-release-source-attestation",
        "reallyme-zk-release-assembly",
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
      ],
      forbidden: [],
    },
    ...[
      "crates-package-preflight.yml",
      "crates-release.yml",
      "fuzz.yml",
      "protobuf-ci.yml",
          "repository-security.yml",
      "sealed-release-attestation.yml",
      "sealed-release-package-attestation.yml",
      "swift-package-preflight.yml",
      "swift-package-release.yml",
      "secret-scan.yml",
    ].map((workflow) => ({
      path: `.github/workflows/${workflow}`,
      required: [],
      forbidden: [
        "ba7676ec3402ac09cadf5ffac55bc7615180ff9e",
        "5c2da5e5d5795c2c895d0dca0819287ee7101207",
      ],
    })),
  ],
});

for (const sdkOwnedPath of [
  "crates/wasm",
  "crates/proto/src/generated/connect",
]) {
  if (existsSync(resolve(repoRoot, sdkOwnedPath))) {
    readiness.fail(`${sdkOwnedPath} is SDK-owned and must not be checked into ZK`);
  }
}

const classifiedScalars = new Set(
  ZK_SCALAR_FIELD_CLASSIFICATIONS.map(
    ({ field, kind, message }) => `${message}.${field}:${kind}`,
  ),
);
if (classifiedScalars.size !== ZK_SCALAR_FIELD_CLASSIFICATIONS.length) {
  readiness.fail("ZK scalar hardening classifications must not contain duplicates");
}

if (generatedFreshnessMode) {
  readiness.assertGeneratedArtifactsFresh({
    generatedPaths: [
      "crates/proto/src/generated/buffa",
      "gen/java/zk",
      "gen/kotlin/zk",
      "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated",
    ],
    commands: [
      ["buf", ["lint"]],
      ["scripts/generate-zk-platform-protos.sh", []],
    ],
  });
}

console.log("zk release readiness checks passed");
