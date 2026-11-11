#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeModernProgram } from "./normalize-modern-program.mjs";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");
const identityDomain = Buffer.from("reallyme-zk-linked-all30-v1\n");
const proofSuite = Buffer.from("barretenberg_ultra_honk_keccak_zk_no_ipa\n");
const sourceLockPath = join(root, "circuits/modern-circuit-source-lock.tsv");
const exactArtifactManifest = join(root, "vectors/common-credential-root-artifact-identities-v1.tsv");
const stageRequestRoot = join(root, "vectors/common-credential-root-stage-requests-v1");
const stageRequestManifest = join(root, "vectors/common-credential-root-stage-requests-v1.sha256.tsv");
const mobileFixtureRoot = join(root, "vectors/common-credential-root-mobile-fixtures-v1");
const mobileFixtureConsumers = Object.freeze([
  join(root, "scripts/stage-demo-mobile-assets.mjs"),
  join(root, "packages/kotlin/demo-android/src/main/kotlin/me/really/zk/demo/android/AndroidDemoCommonCredentialRootAssets.kt"),
  join(root, "packages/swift/Examples/ReallyMeZKDemo/ReallyMeZKDemo/ReallyMeZKDemoCommonCredentialRootRunner.swift"),
]);
const MAX_TEXT_MANIFEST_BYTES = 256 * 1024;
const MAX_PROGRAM_JSON_BYTES = 16 * 1024 * 1024;
const MAX_VERIFICATION_KEY_BYTES = 16 * 1024 * 1024;
const MAX_PROOF_BYTES = 16 * 1024 * 1024;
const MAX_PUBLIC_INPUT_BYTES = 1024 * 1024;
const MAX_REQUEST_VECTOR_BYTES = 2 * 1024 * 1024;

const exactArtifacts = Object.freeze([
  ["sha256", "root_attestation", "credential_common_credential_root_v1_attestation_sha256", "attestation-proof"],
  ["sha256", "root_status", "credential_common_credential_root_v1_status_sha256", "status-proof"],
  ["sha256", "lineage", "credential_common_credential_root_v1_lineage_sha256", "lineage-proof"],
  ["sha256", "issuer_credential_status", "credential_common_credential_root_v1_issuer_credential_status_sha256", "issuer-status-proof"],
  ["sha256", "private_persona_claim", "common_credential_root_v1_sha256_private_persona_claim", "proof"],
  ["sha256", "public_persona_claim", "common_credential_root_v1_sha256_public_persona_claim", "proof"],
  ["sha256", "public_session", "credential_common_credential_root_v1_public_session_sha256", "common-credential-root-session-proof"],
  ["poseidon2", "root_attestation", "credential_common_credential_root_v1_attestation_poseidon2", "attestation-proof"],
  ["poseidon2", "root_status", "credential_common_credential_root_v1_status_poseidon2", "status-proof"],
  ["poseidon2", "lineage", "credential_common_credential_root_v1_lineage_poseidon2", "lineage-proof"],
  ["poseidon2", "issuer_credential_status", "credential_common_credential_root_v1_issuer_credential_status_poseidon2", "issuer-status-proof"],
  ["poseidon2", "private_persona_claim", "common_credential_root_v1_poseidon2_private_persona_claim", "proof"],
  ["poseidon2", "public_persona_claim", "common_credential_root_v1_poseidon2_public_persona_claim", "proof"],
  ["poseidon2", "public_session", "credential_common_credential_root_v1_public_session_poseidon2", "common-credential-root-session-proof"],
]);

const expectedMobileFixtures = new Map([
  ["common-credential-root-sha256-private.pb", "8eff0e80317c7eda620a35f5beb4b63b7dd5162a2cf2ab8fad3be4d74e18c8d4"],
  ["common-credential-root-sha256-public.pb", "77b4a74aedadfb0df3c8c4a8b3fb2d8253b32d29f3b298d938c5a342f426931a"],
  ["common-credential-root-poseidon2-private.pb", "0ca57395f3a6d5124433ba932e93bed467dc56be2764b3c5a6b2c2513d547b2a"],
  ["common-credential-root-poseidon2-public.pb", "4bdd5f4fdc2cbcd71b54ecbc543ca7b3d84efe729aa444b01fcf018376f99a2c"],
]);

function fail(reason) {
  console.error(`common-credential-root CI artifact check failed: ${reason}`);
  process.exit(2);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readPlainFile(path, maximumBytes) {
  if (!existsSync(path)) {
    fail(`missing file ${path}`);
  }
  const metadata = lstatSync(path);
  if (!metadata.isFile()) {
    fail(`refusing non-regular file ${path}`);
  }
  if (metadata.size > maximumBytes) {
    fail(`refusing oversized file ${path}`);
  }
  return readFileSync(path);
}

function readDirectoryNames(path) {
  if (!existsSync(path)) {
    fail(`missing directory ${path}`);
  }
  const metadata = lstatSync(path);
  if (!metadata.isDirectory()) {
    fail(`refusing non-directory ${path}`);
  }
  return readdirSync(path);
}

function readSourceDigests() {
  const lines = readPlainFile(sourceLockPath, MAX_TEXT_MANIFEST_BYTES)
    .toString("utf8")
    .trimEnd()
    .split("\n");
  if (lines.shift() !== "circuit\tpackage\tsource_closure_sha256") {
    fail("source lock header changed");
  }
  const digests = new Map();
  for (const line of lines) {
    const [sourcePath, , digest] = line.split("\t");
    if (sourcePath === undefined || digest === undefined || !/^[a-f0-9]{64}$/u.test(digest)) {
      fail("source lock row is malformed");
    }
    digests.set(sourcePath, digest);
  }
  return digests;
}

function readExactArtifactManifest() {
  const lines = readPlainFile(exactArtifactManifest, MAX_TEXT_MANIFEST_BYTES)
    .toString("utf8")
    .trimEnd()
    .split("\n");
  if (lines.shift() !== "circuit\tartifact_identity_sha256") {
    fail("exact artifact identity manifest header changed");
  }
  const identities = new Map();
  for (const line of lines) {
    const [sourcePath, identity] = line.split("\t");
    if (sourcePath === undefined || identity === undefined || !/^[a-f0-9]{64}$/u.test(identity)) {
      fail("exact artifact identity manifest row is malformed");
    }
    if (identities.has(sourcePath)) {
      fail(`duplicate artifact identity row for ${sourcePath}`);
    }
    identities.set(sourcePath, identity);
  }
  return identities;
}

function computeExactArtifactIdentities() {
  const sourceDigests = readSourceDigests();
  const seen = new Set();
  const identities = new Map();
  for (const [lane, stage, packageName, proofDirectory] of exactArtifacts) {
    const sourcePath = `${lane}/families/common_credential_root_v1/${stage}`;
    const sourceDigest = sourceDigests.get(sourcePath);
    if (sourceDigest === undefined) {
      fail(`missing source digest for ${sourcePath}`);
    }
    if (seen.has(sourcePath)) {
      fail(`duplicate source path ${sourcePath}`);
    }
    seen.add(sourcePath);
    const targetRoot = join(root, "circuits", sourcePath, "target");
    const program = normalizeModernProgram(
      readPlainFile(join(targetRoot, `${packageName}.json`), MAX_PROGRAM_JSON_BYTES),
    );
    if (program === null) {
      fail(`could not normalize compiled program for ${sourcePath}`);
    }
    const verificationKey = readPlainFile(
      join(targetRoot, proofDirectory, "vk"),
      MAX_VERIFICATION_KEY_BYTES,
    );
    const proof = readPlainFile(join(targetRoot, proofDirectory, "proof"), MAX_PROOF_BYTES);
    const publicInputs = readPlainFile(
      join(targetRoot, proofDirectory, "public_inputs"),
      MAX_PUBLIC_INPUT_BYTES,
    );
    if (program.length === 0 || verificationKey.length === 0 || proof.length === 0 || publicInputs.length === 0) {
      fail(`empty proof artifact for ${sourcePath}`);
    }
    const identity = sha256(Buffer.concat([
      identityDomain,
      Buffer.from(`${sourcePath}\n`),
      proofSuite,
      Buffer.from(sourceDigest, "hex"),
      createHash("sha256").update(program).digest(),
      createHash("sha256").update(verificationKey).digest(),
    ]));
    identities.set(sourcePath, identity);
  }
  if (seen.size !== exactArtifacts.length) {
    fail("common-credential-root exact artifact matrix is incomplete");
  }
  return identities;
}

function writeExactArtifactManifest() {
  const identities = computeExactArtifactIdentities();
  const rows = [...identities.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([sourcePath, identity]) => `${sourcePath}\t${identity}\n`)
    .join("");
  process.stdout.write(`circuit\tartifact_identity_sha256\n${rows}`);
}

function checkExactArtifacts() {
  const expected = readExactArtifactManifest();
  const actual = computeExactArtifactIdentities();
  if (actual.size !== expected.size) {
    fail("exact artifact identity manifest has the wrong row count");
  }
  for (const [sourcePath, identity] of actual) {
    if (expected.get(sourcePath) !== identity) {
      fail(`artifact identity mismatch for ${sourcePath}`);
    }
  }
  for (const sourcePath of expected.keys()) {
    if (!actual.has(sourcePath)) {
      fail(`artifact identity manifest contains unknown source ${sourcePath}`);
    }
  }
}

function expectedStageRequestNames() {
  const names = new Set();
  for (const lane of ["poseidon2", "sha256"]) {
    for (const mode of ["private", "public"]) {
      for (let slot = 0; slot < 9; slot += 1) {
        names.add(`${lane}-${mode}-${slot}.pb`);
      }
    }
  }
  return names;
}

function checkStageRequests() {
  const lines = readPlainFile(stageRequestManifest, MAX_TEXT_MANIFEST_BYTES)
    .toString("utf8")
    .trimEnd()
    .split("\n");
  if (lines.shift() !== "filename\tsha256") {
    fail("stage request manifest header changed");
  }
  const expectedNames = expectedStageRequestNames();
  for (const line of lines) {
    const [name, expectedDigest] = line.split("\t");
    if (!expectedNames.delete(name) || !/^[a-f0-9]{64}$/u.test(expectedDigest)) {
      fail("stage request manifest row is malformed or unexpected");
    }
    const bytes = readPlainFile(join(stageRequestRoot, name), MAX_REQUEST_VECTOR_BYTES);
    if (sha256(bytes) !== expectedDigest) {
      fail(`stage request digest mismatch for ${name}`);
    }
  }
  if (expectedNames.size !== 0) {
    fail("stage request manifest is missing rows");
  }
  const actualNames = new Set(
    readDirectoryNames(stageRequestRoot).filter((name) => name.endsWith(".pb")),
  );
  if (actualNames.size !== 36) {
    fail("stage request directory has an unexpected file count");
  }
}

function checkMobileFixtures() {
  const identities = readExactArtifactManifest();
  const consumerSources = mobileFixtureConsumers.map((path) =>
    readPlainFile(path, MAX_TEXT_MANIFEST_BYTES).toString("utf8"),
  );
  const actualNames = new Set(
    readDirectoryNames(mobileFixtureRoot).filter((name) => name.endsWith(".pb")),
  );
  if (actualNames.size !== expectedMobileFixtures.size) {
    fail("mobile fixture directory has an unexpected file count");
  }
  for (const [name, expectedDigest] of expectedMobileFixtures) {
    actualNames.delete(name);
    for (const source of consumerSources) {
      const nameOffset = source.indexOf(name.replace(/\.pb$/u, ""));
      if (nameOffset < 0 || !source.slice(nameOffset, nameOffset + 240).includes(expectedDigest)) {
        fail(`mobile consumer fixture pin is stale for ${name}`);
      }
    }
    const bytes = readPlainFile(join(mobileFixtureRoot, name), MAX_REQUEST_VECTOR_BYTES);
    if (sha256(bytes) !== expectedDigest) {
      fail(`mobile fixture digest mismatch for ${name}`);
    }
    // A fixture can match its own digest while carrying a proof for an older
    // verification key. Check the exact issuer-status pins admitted by this build.
    const lane = name.startsWith("common-credential-root-sha256-") ? "sha256" : "poseidon2";
    const sourcePath = `${lane}/families/common_credential_root_v1/issuer_credential_status`;
    const identity = identities.get(sourcePath);
    if (identity === undefined) {
      fail(`missing issuer-status identity for ${lane}`);
    }
    const operation = oneMessageField(bytes, 9);
    const presentation = oneMessageField(operation, 1);
    const proofs = protobufFields(presentation).filter(([field]) => field === 5);
    if (proofs.length !== 9) {
      fail(`mobile fixture has an unexpected proof count for ${name}`);
    }
    for (const [index, expectedSlot] of [[7, 8], [8, 9]]) {
      const proof = proofs[index][1];
      const slot = oneVarintField(proof, 2);
      const actualIdentity = oneMessageField(oneMessageField(proof, 7), 1);
      if (slot !== expectedSlot || actualIdentity.toString("hex") !== identity) {
        fail(`mobile fixture has a stale issuer-status artifact for ${name}`);
      }
    }
  }
  if (actualNames.size !== 0) {
    fail("mobile fixture directory has unexpected files");
  }
}

function readVarint(bytes, initialOffset) {
  let value = 0;
  let multiplier = 1;
  for (let offset = initialOffset; offset < bytes.length && offset < initialOffset + 10; offset += 1) {
    const byte = bytes[offset];
    value += (byte & 0x7f) * multiplier;
    if (!Number.isSafeInteger(value)) {
      fail("mobile fixture protobuf integer exceeds the safe range");
    }
    if ((byte & 0x80) === 0) {
      return [value, offset + 1];
    }
    multiplier *= 128;
  }
  fail("mobile fixture has an invalid protobuf varint");
}

function protobufFields(bytes) {
  const fields = [];
  let offset = 0;
  while (offset < bytes.length) {
    const [tag, afterTag] = readVarint(bytes, offset);
    const field = Math.floor(tag / 8);
    const wire = tag % 8;
    if (field === 0) {
      fail("mobile fixture has an invalid protobuf field number");
    }
    if (wire === 0) {
      const [value, afterValue] = readVarint(bytes, afterTag);
      fields.push([field, value]);
      offset = afterValue;
    } else if (wire === 2) {
      const [length, afterLength] = readVarint(bytes, afterTag);
      const end = afterLength + length;
      if (!Number.isSafeInteger(end) || end > bytes.length) {
        fail("mobile fixture has an invalid protobuf field length");
      }
      fields.push([field, bytes.subarray(afterLength, end)]);
      offset = end;
    } else if (wire === 1 || wire === 5) {
      offset = afterTag + (wire === 1 ? 8 : 4);
      if (offset > bytes.length) {
        fail("mobile fixture has a truncated protobuf field");
      }
    } else {
      fail("mobile fixture has an unsupported protobuf wire type");
    }
  }
  return fields;
}

function oneField(bytes, number, type) {
  const matches = protobufFields(bytes).filter(([field]) => field === number);
  if (matches.length !== 1 || typeof matches[0][1] !== type) {
    fail("mobile fixture has a missing or duplicate protobuf field");
  }
  return matches[0][1];
}

function oneMessageField(bytes, number) {
  return oneField(bytes, number, "object");
}

function oneVarintField(bytes, number) {
  return oneField(bytes, number, "number");
}

const mode = process.argv[2] ?? "all";
switch (mode) {
  case "all":
    checkExactArtifacts();
    checkStageRequests();
    checkMobileFixtures();
    break;
  case "exact-artifacts":
    checkExactArtifacts();
    break;
  case "write-exact-artifacts":
    writeExactArtifactManifest();
    break;
  case "stage-requests":
    checkStageRequests();
    break;
  case "mobile-fixtures":
    checkMobileFixtures();
    break;
  default:
    fail("usage: check-common-credential-root-ci-artifacts.mjs [all|exact-artifacts|write-exact-artifacts|stage-requests|mobile-fixtures]");
}
if (mode !== "write-exact-artifacts") {
  console.log(`common-credential-root CI artifact ${mode} check ok`);
}
