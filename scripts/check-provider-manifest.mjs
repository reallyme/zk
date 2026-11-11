#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";

const manifestPath = new URL("../provider_manifest.json", import.meta.url);
const policyPath = new URL("../PROVIDER_POLICY.md", import.meta.url);

function fail(reason) {
  console.error(`provider manifest check failed: ${reason}`);
  process.exit(1);
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readManifest() {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    fail("manifest is not valid JSON");
  }
  if (!isRecord(parsed)) {
    fail("manifest root must be an object");
  }
  return parsed;
}

function requireExactKeys(record, expected, label) {
  if (!isRecord(record)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(record).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    fail(`${label} keys do not match the reviewed schema`);
  }
}

function requireLane(lanes, laneName, status, provider, fallback) {
  const lane = lanes[laneName];
  requireExactKeys(lane, ["fallback", "provider", "status"], `lane ${laneName}`);
  if (lane.status !== status || lane.provider !== provider || lane.fallback !== fallback) {
    fail(`lane ${laneName} does not match the reviewed provider route`);
  }
}

const manifest = readManifest();
requireExactKeys(
  manifest,
  [
    "fallbackBehaviors",
    "lanes",
    "mobileDependencies",
    "productionProofSuite",
    "schemaVersion",
    "spdxFileCopyrightText",
    "spdxLicenseIdentifier",
  ],
  "manifest",
);
if (manifest.schemaVersion !== 1) {
  fail("schemaVersion must remain 1");
}
if (manifest.spdxLicenseIdentifier !== "MIT OR Apache-2.0") {
  fail("provider manifest license must match repository dual-license policy");
}
if (manifest.productionProofSuite !== "barretenberg_ultra_honk_keccak_zk_no_ipa") {
  fail("production proof suite drifted");
}
if (
  !Array.isArray(manifest.fallbackBehaviors) ||
  manifest.fallbackBehaviors.length !== 2 ||
  manifest.fallbackBehaviors[0] !== "explicit_provider_required" ||
  manifest.fallbackBehaviors[1] !== "typed_unsupported_provider"
) {
  fail("fallback behavior set drifted");
}

const lanes = manifest.lanes;
requireExactKeys(
  lanes,
  ["kotlin_android", "kotlin_jvm", "rust_native", "swift", "typescript_wasm"],
  "lanes",
);
requireLane(
  lanes,
  "rust_native",
  "first_party_candidate_gate_pending",
  "linked Barretenberg backend implemented here and injected at application boundary",
  "explicit_provider_required",
);
requireLane(
  lanes,
  "swift",
  "first_party_package_in_progress",
  "packages/swift modern linked provider pending full gate",
  "typed_unsupported_provider",
);
requireLane(lanes, "kotlin_jvm", "contract_only", "none", "explicit_provider_required");
requireLane(
  lanes,
  "kotlin_android",
  "first_party_package_in_progress",
  "packages/kotlin modern linked provider pending full gate",
  "explicit_provider_required",
);
requireLane(
  lanes,
  "typescript_wasm",
  "blocked_modern_provider_migration",
  "reallyme/identity modern Barretenberg provider required",
  "typed_unsupported_provider",
);

const mobile = manifest.mobileDependencies;
requireExactKeys(
  mobile,
  ["androidProofBackend", "appleProofBackend", "cryptoUtilities", "witnessGeneration"],
  "mobileDependencies",
);
requireExactKeys(
  mobile.appleProofBackend,
  ["repository", "requiredContract", "status"],
  "mobileDependencies.appleProofBackend",
);
const requiredAppleContract = [
  "official_matched_noir_barretenberg_pair_pending_gate",
  "ultra_honk",
  "keccak_transcript",
  "zero_knowledge_enabled",
  "ipa_accumulation_disabled",
  "separate_public_inputs",
  "narrow_typed_native_abi",
  "bounded_owned_buffers",
  "crs_hash_pinning",
  "zeroized_witness_copies",
  "ios_27_minimum",
  "retained_proof_verification",
  "self_verified_generated_proofs",
];
if (
  mobile.appleProofBackend.repository !== "packages/swift" ||
  mobile.appleProofBackend.status !== "in_progress" ||
  !Array.isArray(mobile.appleProofBackend.requiredContract) ||
  mobile.appleProofBackend.requiredContract.length !== requiredAppleContract.length ||
  mobile.appleProofBackend.requiredContract.some(
    (value, index) => value !== requiredAppleContract[index],
  )
) {
  fail("Apple backend admission contract drifted");
}
requireExactKeys(
  mobile.cryptoUtilities,
  ["contract", "repository", "status"],
  "mobileDependencies.cryptoUtilities",
);
if (
  mobile.cryptoUtilities.repository !== "reallyme/crypto" ||
  mobile.cryptoUtilities.status !== "compatible" ||
  mobile.cryptoUtilities.contract !==
    "platform utilities only; not circuit Poseidon2 or the proof backend"
) {
  fail("platform crypto utility ownership drifted");
}
requireExactKeys(
  mobile.witnessGeneration,
  ["contract", "repository", "revision", "status"],
  "mobileDependencies.witnessGeneration",
);
if (
  mobile.witnessGeneration.repository !== "reallyme/zk" ||
  mobile.witnessGeneration.revision !== "pending-modern-toolchain-gate" ||
  mobile.witnessGeneration.status !== "in_progress" ||
  mobile.witnessGeneration.contract !== "repository-owned typed inputs and NoirWitnessStackV1 output only"
) {
  fail("witness-generation ownership drifted");
}
requireExactKeys(
  mobile.androidProofBackend,
  ["repository", "requiredContract", "status"],
  "mobileDependencies.androidProofBackend",
);
const requiredAndroidContract = [
  "official_matched_noir_barretenberg_pair_pending_gate",
  "ultra_honk",
  "keccak_transcript",
  "zero_knowledge_enabled",
  "ipa_accumulation_disabled",
  "separate_public_inputs",
  "narrow_typed_jni_abi",
  "typed_status_codes",
  "bounded_owned_buffers",
  "zeroized_witness_copies",
  "deterministic_aars",
  "retained_proof_verification",
];
if (
  mobile.androidProofBackend.repository !== "packages/kotlin" ||
  mobile.androidProofBackend.status !== "in_progress" ||
  !Array.isArray(mobile.androidProofBackend.requiredContract) ||
  mobile.androidProofBackend.requiredContract.length !== requiredAndroidContract.length ||
  mobile.androidProofBackend.requiredContract.some(
    (value, index) => value !== requiredAndroidContract[index],
  )
) {
  fail("Android backend admission contract drifted");
}

const policy = readFileSync(policyPath, "utf8");
for (const requiredText of [
  "Applications must explicitly select a provider",
  "Uses the exact `barretenberg_ultra_honk_keccak_zk_no_ipa` proof suite",
  "Verifiers requiring credential revocation status must reject the four-stage",
  "Passes all retained positive and negative conformance tests",
  "If a provider is unavailable or incompatible, the operation must fail",
  "First-party Swift and Kotlin provider packages",
  "Witness material must be held in a short-lived, zeroizing owner",
  "Incorrect transaction-data bindings",
]) {
  if (!policy.includes(requiredText)) {
    fail("provider policy documentation is incomplete");
  }
}

console.log("provider manifest checks passed");
