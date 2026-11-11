#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { extname, join, relative } from "node:path";
import { normalizeModernProgram } from "./normalize-modern-program.mjs";

const repositoryRoot = new URL("../", import.meta.url);
const demoAppPath = new URL(
  "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo",
  import.meta.url,
);
const demoResourcesPath = new URL(
  "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/Resources",
  import.meta.url,
);
const demoResourcesZkPath = new URL(
  "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/Resources/zk_demo",
  import.meta.url,
);
const demoProjectPath = new URL(
  "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo.xcodeproj/project.pbxproj",
  import.meta.url,
);
const stagingScriptPath = new URL("../scripts/stage-demo-mobile-assets.mjs", import.meta.url);
const pinnedReleaseIndexSources = [
  new URL(
    "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/DemoNativeContext.swift",
    import.meta.url,
  ),
  new URL(
    "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemoTests/ReallyMeZKDemoIntegrationTests.swift",
    import.meta.url,
  ),
  new URL(
    "../packages/kotlin/demo-android/src/main/kotlin/me/really/zk/demo/android/AndroidDemoAssetsInternal.kt",
    import.meta.url,
  ),
  new URL(
    "../packages/kotlin/demo-android/build.gradle.kts",
    import.meta.url,
  ),
  new URL(
    "../crates/platform-ffi/tests/support/demo_fixture_types.rs",
    import.meta.url,
  ),
  new URL(
    "../conformance/openid4vp-linked-wallet-verifier/src/common_credential_root_direct_post.rs",
    import.meta.url,
  ),
];
const stageRequestManifestPath = new URL(
  "../vectors/common-credential-root-stage-requests-v1.sha256.tsv",
  import.meta.url,
);
const circuitSourceLockPath = new URL("../circuits/modern-circuit-source-lock.tsv", import.meta.url);
const exactSourceTrustRootPath = new URL(
  "../crates/platform-ffi/src/context/exact_source/part_01.rs",
  import.meta.url,
);
const exactSourceIdentityPinsPath = new URL(
  "../crates/platform-ffi/src/context/exact_source/part_03.rs",
  import.meta.url,
);
const exactSourceIdentityDomain = Buffer.from("reallyme-zk-linked-all30-v1\n");
const productionProofSuiteName = "barretenberg_ultra_honk_keccak_zk_no_ipa";
const claimBundle4Circuits = [
  "sha256/families/credential_subject_claim_v1/claim_bundle_4",
  "sha256/families/private_persona_claim_v1/claim_bundle_4",
  "poseidon2/families/credential_subject_claim_v1/claim_bundle_4",
  "poseidon2/families/private_persona_claim_v1/claim_bundle_4",
];
const pinnedStageManifestSources = [
  new URL(
    "../packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/ReallyMeZKDemoCommonCredentialRootRunner.swift",
    import.meta.url,
  ),
  new URL(
    "../packages/kotlin/demo-android/src/main/kotlin/me/really/zk/demo/android/AndroidDemoCommonCredentialRootAssets.kt",
    import.meta.url,
  ),
];
const forbiddenExtensions = new Set([".acir", ".dat", ".vk"]);
const forbiddenBinaryExtensions = new Set([".a", ".framework", ".xcframework"]);

function fail(reason) {
  console.error(`demo artifact check failed: ${reason}`);
  process.exit(1);
}

function displayPath(path) {
  return relative(repositoryRoot.pathname, path);
}

function expectedReleaseIndexSha256() {
  const script = readFileSync(stagingScriptPath, "utf8");
  const match = script.match(/expectedReleaseIndexSha256\s*=\s*\n?\s*"([0-9a-f]{64})"/);
  if (!match) {
    fail("stage-demo-mobile-assets.mjs must define expectedReleaseIndexSha256");
  }
  return match[1];
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function checkPinnedReleaseIndexSha256() {
  const expected = expectedReleaseIndexSha256();
  for (const sourceUrl of pinnedReleaseIndexSources) {
    if (!existsSync(sourceUrl)) {
      fail(`pinned release-index source is missing: ${displayPath(sourceUrl.pathname)}`);
    }
    const source = readFileSync(sourceUrl, "utf8");
    if (!source.includes(expected)) {
      fail(
        `pinned release-index digest in ${displayPath(
          sourceUrl.pathname,
        )} must match ${expected}`,
      );
    }
  }
}

function checkPinnedStageManifestSha256() {
  if (!existsSync(stageRequestManifestPath)) {
    fail(
      `common-credential-root stage request manifest is missing: ${displayPath(
        stageRequestManifestPath.pathname,
      )}`,
    );
  }
  const expected = sha256Hex(readFileSync(stageRequestManifestPath));
  for (const sourceUrl of pinnedStageManifestSources) {
    if (!existsSync(sourceUrl)) {
      fail(`pinned stage-manifest source is missing: ${displayPath(sourceUrl.pathname)}`);
    }
    const source = readFileSync(sourceUrl, "utf8");
    if (!source.includes(expected)) {
      fail(
        `pinned common-credential-root stage manifest digest in ${displayPath(
          sourceUrl.pathname,
        )} must match ${expected}`,
      );
    }
  }
}

function hexFromRustByteArray(source) {
  const match = source.match(
    /TRUSTED_EXACT_SOURCE_LOCK_SHA256:\s*\[u8;\s*32\]\s*=\s*\[([\s\S]*?)\];/,
  );
  if (!match) {
    fail("diagnostic exact-source trust root must define TRUSTED_EXACT_SOURCE_LOCK_SHA256");
  }
  const values = Array.from(match[1].matchAll(/0x([0-9a-fA-F]{2})/g), (value) =>
    value[1].toLowerCase(),
  );
  if (values.length !== 32) {
    fail("diagnostic exact-source trust root must contain exactly 32 bytes");
  }
  return values.join("");
}

function currentCircuitSourceRows() {
  const lock = readFileSync(circuitSourceLockPath, "utf8").trimEnd().split("\n");
  if (lock.shift() !== "circuit\tpackage\tsource_closure_sha256") {
    fail("modern circuit source lock header changed");
  }
  const rows = new Map();
  for (const line of lock) {
    const fields = line.split("\t");
    if (fields.length !== 3 || !/^[0-9a-f]{64}$/.test(fields[2])) {
      fail("modern circuit source lock contains a malformed row");
    }
    rows.set(fields[0], { packageName: fields[1], sourceClosureSha256: fields[2] });
  }
  return rows;
}

function exactSourceIdentity(circuit, sourceClosureSha256, bytecodeSha256, verificationKeySha256) {
  const digest = createHash("sha256");
  digest.update(exactSourceIdentityDomain);
  digest.update(Buffer.from(circuit));
  digest.update("\n");
  digest.update(Buffer.from(productionProofSuiteName));
  digest.update("\n");
  digest.update(Buffer.from(sourceClosureSha256, "hex"));
  digest.update(Buffer.from(bytecodeSha256, "hex"));
  digest.update(Buffer.from(verificationKeySha256, "hex"));
  return digest.digest("hex");
}

function checkDiagnosticExactSourcePins() {
  const expectedLockSha256 = sha256Hex(readFileSync(circuitSourceLockPath));
  const trustRoot = readFileSync(exactSourceTrustRootPath, "utf8");
  if (hexFromRustByteArray(trustRoot) !== expectedLockSha256) {
    fail(`diagnostic exact-source lock pin must match ${expectedLockSha256}`);
  }

  const rows = currentCircuitSourceRows();
  const identityPins = readFileSync(exactSourceIdentityPinsPath, "utf8");
  for (const circuit of claimBundle4Circuits) {
    const row = rows.get(circuit);
    if (!row) {
      fail(`modern circuit source lock is missing ${circuit}`);
    }
    const targetRoot = join(repositoryRoot.pathname, "circuits", circuit, "target");
    const bytecodePath = join(targetRoot, `${row.packageName}.json`);
    const verificationKeyPath = join(targetRoot, "modern-run-01", "vk");
    if (!existsSync(bytecodePath) || !existsSync(verificationKeyPath)) {
      continue;
    }
    const normalizedProgram = normalizeModernProgram(readFileSync(bytecodePath));
    if (normalizedProgram === null) {
      fail(`diagnostic program normalization failed for ${circuit}`);
    }
    const identity = exactSourceIdentity(
      circuit,
      row.sourceClosureSha256,
      sha256Hex(normalizedProgram),
      sha256Hex(readFileSync(verificationKeyPath)),
    );
    if (!identityPins.includes(identity)) {
      fail(`diagnostic exact-source identity pin for ${circuit} must match ${identity}`);
    }
  }
}

function walkResources(path, found) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    if (entry.isSymbolicLink()) {
      found.push(child);
      continue;
    }
    if (entry.isDirectory()) {
      walkResources(child, found);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (forbiddenExtensions.has(extname(entry.name))) {
      found.push(child);
    }
  }
}

function walkSampleApp(path, found) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    const extension = extname(entry.name);
    if (entry.isSymbolicLink() || forbiddenBinaryExtensions.has(extension)) {
      found.push(child);
      continue;
    }
    if (entry.isDirectory()) {
      walkSampleApp(child, found);
    }
  }
}

checkPinnedReleaseIndexSha256();
checkPinnedStageManifestSha256();
checkDiagnosticExactSourcePins();

if (existsSync(demoResourcesPath)) {
  const stat = statSync(demoResourcesPath);
  if (!stat.isDirectory()) {
    fail("sample app Resources path must be a directory");
  }
  const forbidden = [];
  walkResources(demoResourcesPath.pathname, forbidden);
  if (forbidden.length > 0) {
    const display = forbidden
      .map(displayPath)
      .sort()
      .join(", ");
    fail(`legacy proving artifacts or symlinks are bundled in Resources: ${display}`);
  }
}

if (existsSync(demoResourcesZkPath)) {
  fail("sample app Resources/zk_demo must not be present; use build/native/ios-demo-resources/zk_demo");
}

if (existsSync(demoProjectPath)) {
  const project = readFileSync(demoProjectPath, "utf8");
  const explicitStagedResources =
    project.match(/isa = PBXBuildFile; fileRef = [^;]+\/\* zk_demo \*\/; \};/g) ?? [];
  if (explicitStagedResources.length !== 1) {
    fail("Xcode project must have exactly one explicit staged zk_demo resource producer");
  }
  if (!project.includes("Resources/zk_demo,")) {
    fail("Xcode synchronized app folder must exclude Resources/zk_demo from target membership");
  }
}

if (existsSync(demoAppPath)) {
  const forbidden = [];
  walkSampleApp(demoAppPath.pathname, forbidden);
  if (forbidden.length > 0) {
    const display = forbidden.map(displayPath).sort().join(", ");
    fail(`framework, archive, or symlink is present in the sample app: ${display}`);
  }
}

console.log("demo artifact check passed");
