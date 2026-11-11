#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import {
  validateSwiftDemoBundleProjectBoundarySource,
} from "./swift-demo-project-boundary.mjs";

test("scoped readiness modes enforce platform source policy through CI delegation", () => {
  const temporary = mkdtempSync(join(tmpdir(), "zk-readiness-mode-"));
  try {
    const core = join(temporary, "core.mjs");
    writeFileSync(core, `export const createReleaseReadinessContext = () => new Proxy({}, {
      get: (_target, key) => (...arguments_) => {
        if (key === "assertSwiftSourcePolicy" || key === "assertKotlinSourcePolicy") {
          const verification = arguments_[0]?.verification;
          if (verification?.length !== 1 ||
              verification[0]?.command !== "node" ||
              verification[0]?.args?.[0] !== "scripts/check-platform-policy-delegation.mjs") {
            throw new Error("platform-delegation-missing-in-scoped-mode");
          }
        }
      },
    });\n`);
    for (const mode of ["--policy-only", "--generated-freshness", "--rust-release-packages"]) {
      const result = spawnSync(process.execPath, ["scripts/check_release_readiness.mjs", mode], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          RELEASE_READINESS_CORE_URL: pathToFileURL(core).href,
          RELEASE_VERSION: "0.3.0",
        },
      });
      assert.equal(result.status, 0, `${mode}: ${result.stderr}`);
      assert.match(result.stdout, /zk release readiness checks passed/u);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("readiness keeps platform ffi as the only native staticlib package", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");
  const platformFfiBlock = source.match(
    /path: "crates\/platform-ffi\/Cargo\.toml",[\s\S]*?forbidden:/u,
  )?.[0] ?? "";
  const protoCodecBlock = source.match(
    /path: "crates\/proto-codec\/Cargo\.toml",[\s\S]*?forbidden:[\s\S]*?\],/u,
  )?.[0] ?? "";

  assert.match(platformFfiBlock, /crate-type = \["rlib", "staticlib"\]/u);
  assert.doesNotMatch(protoCodecBlock, /crate-type = \["rlib", "staticlib"\]/u);
  assert.match(protoCodecBlock, /"crate-type"/u);
  assert.match(protoCodecBlock, /"staticlib"/u);
});

test("readiness enforces reviewed policy lock before local policy receipts", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");

  assert.match(source, /assertReallyMeReleasePackagePolicy/u);
  assert.match(source, /scripts\/check-release-readiness-policy-lock\.mjs/u);
  assert.match(
    source,
    /assertReallyMeReleasePackagePolicy[\s\S]*check-release-readiness-policy-lock\.mjs/u,
  );
});

test("readiness preserves diagnostic-only stage verification boundary", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");

  assert.match(source, /verify-stage: diagnostic-stage-proof-ok; not-presentation-admission/u);
  assert.match(source, /func verifyDiagnosticStage\(/u);
  assert.match(source, /public fun verifyDiagnosticStage\(/u);
  assert.match(
    source,
    /fn bundle_rejects_diagnostic_envelope_root_chain_mismatch\(\)/u,
  );
  assert.match(source, /request: ReallyMeZKStageVerifyRequest/u);
  assert.match(source, /request: ZkStageVerifyRequest/u);
});

test("readiness preserves consumer native package boundaries", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");

  assert.match(source, /ReallyMeZKPlatformNative/u);
  assert.match(source, /ReallyMeZKDemoBundle/u);
  assert.match(source, /ReallyMeZKPlatformFFI/u);
  assert.match(source, /CodeSignOnCopy/u);
  assert.match(source, /assertSwiftDemoBundleProjectBoundary/u);
  assert.match(source, /validateSwiftDemoBundleProjectBoundarySource/u);
  assert.match(source, /CODE_SIGN_IDENTITY/u);
  assert.match(source, /PROVISIONING_PROFILE/u);
  assert.match(source, /\.binaryTarget\(/u);
  assert.match(source, /include\(\\":android-native\\"\)/u);
  assert.match(source, /maven-publish/u);
  assert.match(source, /zk-android/u);
  assert.match(source, /verifyPublishedAndroidAarNativeLibraries/u);
  assert.match(source, /localReleaseArtifacts/u);
  assert.match(source, /scripts\/release-artifact-cache\.mjs/u);
  assert.match(source, /implementation\(project\(\\":android-native\\"\)\)/u);
  assert.match(source, /:android-native:assembleRelease/u);
  assert.match(source, /:android-native:check/u);
  assert.match(source, /SWIFT_VERSION = 6\.0;/u);
  assert.match(source, /SWIFT_OBJC_BRIDGING_HEADER/u);
  assert.match(source, /ios-demo-resources\/zk_demo/u);
});

test("readiness preserves TypeScript provider source policy", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");
  const tsconfig = readFileSync("packages/bbjs-provider/tsconfig.json", "utf8");

  assert.match(source, /assertTypeScriptSourcePolicy/u);
  assert.match(source, /packages\/bbjs-provider\/src/u);
  assert.match(source, /packages\/bbjs-provider\/tsconfig\.json/u);
  assert.match(source, /scripts\/check-bbjs-provider-package\.mjs/u);
  assert.match(source, /scripts\/check-platform-facade-pins\.mjs/u);
  assert.match(source, /scripts\/check-platform-facade-pins\.test\.mjs/u);
  assert.match(source, /packages\/bbjs-provider\/test\/\*\.test\.mjs/u);

  for (const required of [
    "\"strict\": true",
    "\"noImplicitAny\": true",
    "\"noUncheckedIndexedAccess\": true",
    "\"exactOptionalPropertyTypes\": true",
    "\"useUnknownInCatchVariables\": true",
    "\"noImplicitOverride\": true",
    "\"noFallthroughCasesInSwitch\": true",
    "\"noEmit\": true",
  ]) {
    assert.match(tsconfig, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }
});

test("readiness preserves narrow native unsafe boundaries", () => {
  const platformLib = readFileSync("crates/platform-ffi/src/lib.rs", "utf8");
  const nativeBackend = readFileSync("crates/backend-bb/src/native_backend.rs", "utf8");

  assert.doesNotMatch(platformLib, /^\s*#!\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]/mu);
  assert.doesNotMatch(nativeBackend, /^\s*#!\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]/mu);
  assert.match(platformLib, /#\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]\s*\nmod ffi;/u);
  assert.match(
    platformLib,
    /#\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]\s*\nmod input;/u,
  );
  assert.match(nativeBackend, /#\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]\s*\ntype BbapiCall/u);
  assert.match(
    nativeBackend,
    /#\s*\[\s*allow\s*\(\s*unsafe_code\s*\)\s*\]\s*\nmod linked_bbapi/u,
  );
});

test("readiness preserves the promoted toolchain and current v1 provenance checks", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");

  assert.match(source, /candidateMatchedPair\.status =/u);
  assert.match(source, /promoted/u);
  assert.match(source, /modern-circuit-source-lock\.tsv/u);
  assert.match(source, /verify_sealed_release_candidate\.mjs/u);
  assert.match(source, /exact source revision and sealed artifacts/u);
});

test("readiness explicitly governs non-default ZK source SPDX extensions", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");

  for (const extension of [".nr", ".cc", ".h"]) {
    assert.match(
      source,
      new RegExp(`"${extension.replace(".", "\\.")}"`, "u"),
    );
  }
  assert.match(
    source,
    /SPDX-FileCopyrightText: Copyright \(c\) 2026 ReallyMe Technologies Limited/u,
  );
});

test("readiness preserves generated private persona composition gate", () => {
  const source = readFileSync("scripts/check_release_readiness.mjs", "utf8");

  assert.match(source, /generate-private-persona-distinct-fixtures/u);
  assert.match(source, /ISSUER_A_SCALAR/u);
  assert.match(source, /ISSUER_B_SCALAR/u);
  assert.match(source, /BINDSUB1/u);
  assert.match(source, /LINK1/u);
  assert.match(source, /normalize_s\(\)/u);
  assert.match(source, /validate_managed_output_tree/u);
  assert.match(source, /GENERATED_PRIVATE_PERSONA_FIXTURE_ROOT/u);
  assert.match(source, /test-linked-private-persona-distinct-subject\.sh/u);
});

test("swift demo project boundary rejects unsafe native bundle wiring", () => {
  const source = readFileSync(
    "packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo.xcodeproj/project.pbxproj",
    "utf8",
  );

  assert.equal(validateSwiftDemoBundleProjectBoundarySource(source), null);

  const withoutLocalPackageReference = source.replace(
    /relativePath = \.\.\/\.\.\/\.\.\/\.\.;/u,
    "relativePath = ../../missing;",
  );
  assert.match(
    validateSwiftDemoBundleProjectBoundarySource(withoutLocalPackageReference) ?? "",
    /does not link ReallyMeZKDemoBundle to the local package/u,
  );

  const withoutEmbedPhaseMembership = source.replace(
    /\n\s*[0-9A-F]+ \/\* ReallyMeZKDemoBundle in Embed Frameworks \*\/,/u,
    "",
  );
  assert.match(
    validateSwiftDemoBundleProjectBoundarySource(withoutEmbedPhaseMembership) ?? "",
    /does not embed ReallyMeZKDemoBundle in the app target/u,
  );

  const withoutCodeSignOnCopy = source.replace("CodeSignOnCopy, ", "");
  assert.match(
    validateSwiftDemoBundleProjectBoundarySource(withoutCodeSignOnCopy) ?? "",
    /does not embed and sign the ReallyMeZKDemoBundle product/u,
  );

  const withCheckedInTeam = `${source}\nDEVELOPMENT_TEAM = EXAMPLE123;\n`;
  assert.match(
    validateSwiftDemoBundleProjectBoundarySource(withCheckedInTeam) ?? "",
    /contains checked-in DEVELOPMENT_TEAM/u,
  );
});
