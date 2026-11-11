#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import {
  copyFileSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { localPath } from "./release-artifact-manifest.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const localArtifactRoot = resolve(
  process.env.REALLYME_ZK_LOCAL_ARTIFACT_ROOT ??
    join(root, "build/native"),
);
const generatedArtifactRoot = resolve(localArtifactRoot, "mobile-demo-artifacts-persona-credential-evidence-v1-candidate");
const publicCircuitArchivePath = localPath("mobile-circuit-artifacts-persona-credential-evidence-v1.tar");
const defaultCrsRoot = process.env.REALLYME_ZK_DEMO_CRS_DIR ?? `${process.env.HOME}/.bb-crs`;
const expectedReleaseIndexSha256 =
  "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7";
const expectedPublicCircuitArchiveSha256 =
  "74990876329b137dc0bc073360423d64d08b8f0a50872639c4ed0dbfcffe89a9";
const expectedG1PrefixSha256 =
  "0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5";
const expectedG2Sha256 =
  "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f";
const expectedCommonCredentialRootSourceLockSha256 =
  "ca4d51a94243c36af605a90429ff6605984d6158a724c290189e57d55d2e129a";
const commonCredentialRootIdentityDomain = Buffer.from("reallyme-zk-linked-all30-v1\n");
const commonCredentialRootSuite = Buffer.from("barretenberg_ultra_honk_keccak_zk_no_ipa\n");
const commonCredentialRootCircuits = [
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
];
const commonCredentialRootFixtures = new Map([
  ["common-credential-root-sha256-private.pb", "8eff0e80317c7eda620a35f5beb4b63b7dd5162a2cf2ab8fad3be4d74e18c8d4"],
  ["common-credential-root-sha256-public.pb", "77b4a74aedadfb0df3c8c4a8b3fb2d8253b32d29f3b298d938c5a342f426931a"],
  ["common-credential-root-poseidon2-private.pb", "0ca57395f3a6d5124433ba932e93bed467dc56be2764b3c5a6b2c2513d547b2a"],
  ["common-credential-root-poseidon2-public.pb", "4bdd5f4fdc2cbcd71b54ecbc543ca7b3d84efe729aa444b01fcf018376f99a2c"],
]);
const commonCredentialRootStageRequestManifest = "vectors/common-credential-root-stage-requests-v1.sha256.tsv";
const commonCredentialRootStageRequestDirectory = "vectors/common-credential-root-stage-requests-v1";
const personaCredentialEvidenceRequestDirectory =
  "vectors/persona-credential-evidence-mobile-requests-v1";
const commonCredentialRootStageCount = 9;
const proverG1PrefixBytes = 67_108_928;
const g2Bytes = 128;
const allowedTargets = new Set([
  resolve(localArtifactRoot, "ios-demo-resources/zk_demo"),
  resolve(root, "packages/kotlin/demo-android/build/generated/reallyme-zk-demo-assets/zk_demo"),
]);

function fail(reason) {
  console.error(`demo mobile asset staging failed: ${reason}`);
  process.exit(1);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function copyPrefix(source, target, byteCount) {
  const fd = openSync(source, "r");
  try {
    const buffer = Buffer.alloc(byteCount);
    let totalRead = 0;
    while (totalRead < byteCount) {
      const bytesRead = readSync(
        fd,
        buffer,
        totalRead,
        byteCount - totalRead,
        totalRead,
      );
      if (bytesRead === 0) {
        break;
      }
      totalRead += bytesRead;
    }
    if (totalRead !== byteCount) {
      fail(`CRS prefix ${source} is shorter than ${byteCount} bytes`);
    }
    if (sha256(buffer) !== expectedG1PrefixSha256) {
      fail("CRS G1 prover prefix digest does not match the reviewed pin");
    }
    writeFileSync(target, buffer, { mode: 0o644 });
    buffer.fill(0);
  } finally {
    closeSync(fd);
  }
}

function copyExact(source, target, byteCount, expectedDigest) {
  const bytes = readFileSync(source);
  if (bytes.byteLength !== byteCount) {
    fail(`${source} has ${bytes.byteLength} bytes, expected ${byteCount}`);
  }
  if (sha256(bytes) !== expectedDigest) {
    fail(`${source} digest does not match the reviewed pin`);
  }
  writeFileSync(target, bytes, { mode: 0o644 });
}

function copyPublicArtifacts(sourceRoot, targetRoot) {
  for (const entry of readdirSync(sourceRoot, { withFileTypes: true })) {
    const source = join(sourceRoot, entry.name);
    const target = join(targetRoot, entry.name);
    if (source.includes("/vectors/") || source.includes("/verification-vectors/")) {
      continue;
    }
    if (entry.isSymbolicLink()) {
      fail("public circuit artifact source must not contain symbolic links");
    }
    if (entry.isDirectory()) {
      mkdirSync(target, { recursive: true });
      copyPublicArtifacts(source, target);
      continue;
    }
    if (entry.isFile()) {
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(source, target);
    }
  }
}

function maybeUnpackPublicCircuitArtifacts() {
  const indexPath = join(generatedArtifactRoot, "v1/v1/index.pb");
  if (existsSync(indexPath)) {
    return;
  }
  if (existsSync(generatedArtifactRoot)) {
    fail(
      "generated public circuit artifact directory exists but is missing the release index",
    );
  }
  if (!existsSync(publicCircuitArchivePath)) {
    fail(`missing generated release index at ${indexPath}`);
  }
  const archiveBytes = readFileSync(publicCircuitArchivePath);
  if (sha256(archiveBytes) !== expectedPublicCircuitArchiveSha256) {
    fail("public circuit artifact archive digest does not match the reviewed pin");
  }
  verifyPublicCircuitArchiveListing(publicCircuitArchivePath);
  mkdirSync(generatedArtifactRoot, { recursive: true });
  const result = spawnSync(
    "tar",
    ["-xf", publicCircuitArchivePath, "-C", generatedArtifactRoot],
    {
      cwd: root,
      stdio: "inherit",
    },
  );
  if (result.error !== undefined) {
    fail("tar failed to start while unpacking public circuit artifacts");
  }
  if (result.status !== 0) {
    fail("tar failed while unpacking public circuit artifacts");
  }
  verifyNoVectorFiles(generatedArtifactRoot);
}

function verifyPublicCircuitArchiveListing(archivePath) {
  const result = spawnSync("tar", ["-tf", archivePath], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.error !== undefined) {
    fail("tar failed to start while listing public circuit artifacts");
  }
  if (result.status !== 0) {
    fail("tar failed while listing public circuit artifacts");
  }
  const entries = result.stdout.trimEnd().split("\n");
  if (entries.length === 0) {
    fail("public circuit artifact archive is empty");
  }
  for (const entry of entries) {
    if (
      entry.startsWith("/") ||
      entry.includes("../") ||
      (!entry.startsWith("common-credential-root-v1/") &&
       !entry.startsWith("persona-credential-evidence-v1/") &&
       !entry.startsWith("v1/")) ||
      entry.includes("/vectors/") ||
      entry.includes("/vectors/proving-spec/")
    ) {
      fail("public circuit artifact archive contains an unexpected path");
    }
  }
}

function verifyNoVectorFiles(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const child = join(directory, entry.name);
    if (
      entry.isFile() &&
      (child.includes("/vectors/") || child.includes("/verification-vectors/"))
    ) {
      fail("public circuit artifacts must not contain vector files");
    }
    if (entry.isDirectory()) {
      verifyNoVectorFiles(child);
    }
  }
}

function verifyPublicRuntimeArtifacts() {
  // The archive digest authenticates distribution bytes. Runtime validation
  // checks every manifest, program and key without requiring the private
  // proof-bearing vectors that are deliberately absent from this distribution.
  const result = spawnSync(
    "cargo",
    ["run", "--quiet", "--locked", "--offline", "-p", "reallyme-zk-artifact-package",
      "--bin", "check-mobile-runtime", "--", generatedArtifactRoot, "v1"],
    { cwd: root, stdio: "inherit" },
  );
  if (result.error !== undefined || result.status !== 0) {
    fail("public circuit artifacts failed runtime integrity validation");
  }
}

function readCommonCredentialRootIdentityPins() {
  const manifest = readFileSync(
    join(root, "vectors/common-credential-root-artifact-identities-v1.tsv"), "utf8",
  ).trimEnd().split("\n");
  if (manifest.shift() !== "circuit\tartifact_identity_sha256" ||
      manifest.length !== commonCredentialRootCircuits.length) {
    fail("common-credential-root artifact identity manifest is incomplete");
  }
  const identities = new Map();
  for (const line of manifest) {
    const fields = line.split("\t");
    if (fields.length !== 2 || !/^[a-f0-9]{64}$/u.test(fields[1]) ||
        identities.has(fields[0])) {
      fail("common-credential-root artifact identity manifest is malformed");
    }
    identities.set(fields[0], fields[1]);
  }
  return identities;
}

function commonCredentialRootSourceLockSha256(lockBytes) {
  const lines = lockBytes.toString("utf8").trimEnd().split("\n");
  const header = lines.shift();
  if (header !== "circuit\tpackage\tsource_closure_sha256") {
    fail("common-credential-root source lock header changed");
  }
  const rows = new Map();
  for (const line of lines) {
    const [sourcePath, packageName, digest] = line.split("\t");
    if (
      sourcePath === undefined ||
      packageName === undefined ||
      digest === undefined ||
      !/^[a-f0-9]{64}$/u.test(digest)
    ) {
      fail("invalid common-credential-root source lock entry");
    }
    if (rows.has(sourcePath)) {
      fail("duplicate common-credential-root source lock entry");
    }
    rows.set(sourcePath, line);
  }
  const pinnedLines = ["circuit\tpackage\tsource_closure_sha256"];
  for (const [lane, stage] of commonCredentialRootCircuits) {
    const sourceName = `${lane}/families/common_credential_root_v1/${stage}`;
    const line = rows.get(sourceName);
    if (line === undefined) {
      fail(`missing source closure for ${sourceName}`);
    }
    pinnedLines.push(line);
  }
  return sha256(Buffer.from(`${pinnedLines.join("\n")}\n`, "utf8"));
}

function verifyCommonCredentialRootArtifacts(targetArtifactRoot) {
  const expectedIdentities = readCommonCredentialRootIdentityPins();
  const sourceLockPath = join(root, "circuits/modern-circuit-source-lock.tsv");
  const lockBytes = readFileSync(sourceLockPath);
  if (commonCredentialRootSourceLockSha256(lockBytes) !== expectedCommonCredentialRootSourceLockSha256) {
    fail("common-credential-root source lock does not match the reviewed pin");
  }
  const sourceDigests = new Map();
  for (const line of lockBytes.toString("utf8").trimEnd().split("\n").slice(1)) {
    const [sourcePath, , digest] = line.split("\t");
    if (sourcePath === undefined || digest === undefined || !/^[a-f0-9]{64}$/.test(digest)) {
      fail("invalid common-credential-root source lock entry");
    }
    sourceDigests.set(sourcePath, digest);
  }
  const packageRoot = join(targetArtifactRoot, "common-credential-root-v1");
  const packagedLock = readFileSync(join(packageRoot, "modern-circuit-source-lock.tsv"));
  if (commonCredentialRootSourceLockSha256(packagedLock) !== expectedCommonCredentialRootSourceLockSha256) {
    fail("sealed common-credential-root source lock does not match the reviewed pin");
  }
  for (const [lane, stage] of commonCredentialRootCircuits) {
    const sourceName = `${lane}/families/common_credential_root_v1/${stage}`;
    const expectedIdentity = expectedIdentities.get(sourceName);
    if (expectedIdentity === undefined) {
      fail(`missing common-credential-root artifact identity for ${sourceName}`);
    }
    const sourceDigest = sourceDigests.get(sourceName);
    if (sourceDigest === undefined) {
      fail(`missing source closure for ${sourceName}`);
    }
    const targetDirectory = join(packageRoot, lane, stage);
    const program = readFileSync(join(targetDirectory, "program.json"));
    const verificationKey = readFileSync(join(targetDirectory, "verification-key.bin"));
    const identity = sha256(Buffer.concat([
      commonCredentialRootIdentityDomain,
      Buffer.from(`${sourceName}\n`),
      commonCredentialRootSuite,
      Buffer.from(sourceDigest, "hex"),
      createHash("sha256").update(program).digest(),
      createHash("sha256").update(verificationKey).digest(),
    ]));
    if (identity !== expectedIdentity) {
      fail(`common-credential-root artifact identity mismatch for ${sourceName}`);
    }
  }
  if (expectedIdentities.size !== commonCredentialRootCircuits.length) {
    fail("common-credential-root artifact identity manifest has unexpected entries");
  }
}

function stageCommonCredentialRootStageRequests(targetRoot) {
  const lines = readFileSync(join(root, commonCredentialRootStageRequestManifest), "utf8")
    .trimEnd()
    .split("\n");
  if (lines.shift() !== "filename\tsha256" || lines.length !== 36) {
    fail("common-credential-root stage request manifest has an invalid header or row count");
  }
  const expectedNames = new Set();
  for (const lane of ["sha256", "poseidon2"]) {
    for (const mode of ["private", "public"]) {
      for (let slot = 0; slot < commonCredentialRootStageCount; slot += 1) {
        expectedNames.add(`${lane}-${mode}-${slot}.pb`);
      }
    }
  }
  const targetDirectory = join(targetRoot, "common-credential-root-stage-requests-v1");
  mkdirSync(targetDirectory, { recursive: true });
  copyFileSync(join(root, commonCredentialRootStageRequestManifest), join(targetDirectory, "sha256.tsv"));
  for (const line of lines) {
    const fields = line.split("\t");
    if (fields.length !== 2) {
      fail("common-credential-root stage request manifest row is malformed");
    }
    const [name, expectedDigest] = fields;
    if (!expectedNames.delete(name) || !/^[a-f0-9]{64}$/.test(expectedDigest)) {
      fail("common-credential-root stage request manifest contains an unexpected entry");
    }
    const bytes = readFileSync(join(root, commonCredentialRootStageRequestDirectory, name));
    try {
      if (sha256(bytes) !== expectedDigest) {
        fail(`common-credential-root stage request digest mismatch for ${name}`);
      }
      writeFileSync(join(targetDirectory, name), bytes, { mode: 0o644 });
    } finally {
      bytes.fill(0);
    }
  }
  if (expectedNames.size !== 0) {
    fail("common-credential-root stage request manifest is incomplete");
  }
}

function stagePreparedRequests(targetRoot) {
  const sourceRoot = join(root, personaCredentialEvidenceRequestDirectory);
  const lines = readFileSync(join(sourceRoot, "sha256.tsv"), "utf8")
    .trimEnd()
    .split("\n");
  if (lines.shift() !== "filename\tsha256" || lines.length !== 20) {
    fail("prepared sample request manifest has an invalid header or row count");
  }
  const expectedNames = new Set();
  for (const lane of ["sha256", "poseidon2"]) {
    for (const persona of ["public", "private"]) {
      for (const part of ["issuer", "root", "validity", "claim", "status"]) {
        expectedNames.add(`${lane}-${persona}-${part}.pb`);
      }
    }
  }
  const targetDirectory = join(
    targetRoot,
    "persona-credential-evidence-mobile-requests-v1",
  );
  mkdirSync(targetDirectory, { recursive: true });
  for (const line of lines) {
    const fields = line.split("\t");
    if (fields.length !== 2) {
      fail("prepared sample request manifest row is malformed");
    }
    const [name, expectedDigest] = fields;
    if (!expectedNames.delete(name) || !/^[a-f0-9]{64}$/.test(expectedDigest)) {
      fail("prepared sample request manifest contains an unexpected entry");
    }
    const bytes = readFileSync(join(sourceRoot, name));
    try {
      if (sha256(bytes) !== expectedDigest) {
        fail(`prepared sample request digest mismatch for ${name}`);
      }
      writeFileSync(join(targetDirectory, name), bytes, { mode: 0o644 });
    } finally {
      bytes.fill(0);
    }
  }
  if (expectedNames.size !== 0) {
    fail("prepared sample request manifest is incomplete");
  }
  copyFileSync(join(sourceRoot, "sha256.tsv"), join(targetDirectory, "sha256.tsv"));
}

function stage(targetRoot) {
  if (!allowedTargets.has(targetRoot)) {
    fail(`refusing to stage into unapproved target ${targetRoot}`);
  }
  if (existsSync(targetRoot) && lstatSync(targetRoot).isSymbolicLink()) {
    fail(`refusing to replace symbolic link target ${targetRoot}`);
  }
  maybeUnpackPublicCircuitArtifacts();
  const indexPath = join(generatedArtifactRoot, "v1/v1/index.pb");
  if (!existsSync(indexPath)) {
    fail(`missing generated release index at ${indexPath}`);
  }
  const indexBytes = readFileSync(indexPath);
  if (sha256(indexBytes) !== expectedReleaseIndexSha256) {
    fail("generated release index digest does not match the reviewed pin");
  }
  verifyPublicRuntimeArtifacts();

  const g1Path = resolve(defaultCrsRoot, "bn254_g1.dat");
  const g2Path = resolve(defaultCrsRoot, "bn254_g2.dat");
  if (!existsSync(g1Path) || !existsSync(g2Path)) {
    fail(`missing CRS files under ${defaultCrsRoot}`);
  }
  if (statSync(g1Path).size < proverG1PrefixBytes) {
    fail("CRS G1 file is smaller than the reviewed prover prefix");
  }

  rmSync(targetRoot, { force: true, recursive: true });
  mkdirSync(join(targetRoot, "artifacts"), { recursive: true });
  mkdirSync(join(targetRoot, "crs"), { recursive: true });
  copyPublicArtifacts(generatedArtifactRoot, join(targetRoot, "artifacts"));
  verifyNoVectorFiles(join(targetRoot, "artifacts"));
  verifyCommonCredentialRootArtifacts(join(targetRoot, "artifacts"));
  for (const [name, expectedDigest] of commonCredentialRootFixtures) {
    const source = join(root, "vectors/common-credential-root-mobile-fixtures-v1", name);
    if (!existsSync(source)) {
      fail(`missing common-credential-root verification fixture ${name}`);
    }
    const bytes = readFileSync(source);
    if (sha256(bytes) !== expectedDigest) {
      fail(`common-credential-root verification fixture digest mismatch for ${name}`);
    }
    writeFileSync(join(targetRoot, name), bytes, { mode: 0o644 });
  }
  stageCommonCredentialRootStageRequests(targetRoot);
  stagePreparedRequests(targetRoot);
  copyFileSync(indexPath, join(targetRoot, "release-index.pb"));
  writeFileSync(join(targetRoot, "release-index.sha256"), `${expectedReleaseIndexSha256}\n`);
  copyPrefix(g1Path, join(targetRoot, "crs/bn254_g1.prover"), proverG1PrefixBytes);
  copyExact(g2Path, join(targetRoot, "crs/bn254_g2"), g2Bytes, expectedG2Sha256);
}

if (process.argv[2] !== undefined && process.argv.length === 3) {
  stage(resolve(root, process.argv[2]));
} else {
  fail("expected one demo target directory");
}
