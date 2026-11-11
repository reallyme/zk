#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Stage the exact common-credential-root programs proven by the pinned circuit gate.
// The release sealer independently validates every staged byte before admission.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeModernProgram } from "./normalize-modern-program.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactRoot = resolve(process.env.REALLYME_ZK_LOCAL_ARTIFACT_ROOT ??
  join(root, "release-artifacts/modern-v1-bb-6.0.0"));
const candidate = resolve(process.argv[2] ?? "");
const approvedCandidate = join(artifactRoot, "mobile-demo-artifacts-persona-credential-evidence-v1-candidate");
const sourceLock = join(root, "circuits/modern-circuit-source-lock.tsv");
const identityManifest = join(root, "vectors/common-credential-root-artifact-identities-v1.tsv");
const stages = [
  ["root_attestation", "credential_common_credential_root_v1_attestation", "attestation-proof"],
  ["root_status", "credential_common_credential_root_v1_status", "status-proof"],
  ["lineage", "credential_common_credential_root_v1_lineage", "lineage-proof"],
  ["issuer_credential_status", "credential_common_credential_root_v1_issuer_credential_status", "issuer-status-proof"],
  ["private_persona_claim", "common_credential_root_v1", "proof"],
  ["public_persona_claim", "common_credential_root_v1", "proof"],
  ["public_session", "credential_common_credential_root_v1_public_session", "common-credential-root-session-proof"],
];
const lanes = ["sha256", "poseidon2"];
const identityDomain = Buffer.from("reallyme-zk-linked-all30-v1\n");
const proofSuite = Buffer.from("barretenberg_ultra_honk_keccak_zk_no_ipa\n");
const maximumProgramBytes = 16 * 1024 * 1024;
const maximumKeyBytes = 16 * 1024 * 1024;

function fail(reason) {
  console.error(`common-credential-root candidate preparation failed: ${reason}`);
  process.exit(2);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function plainFile(path, maximumBytes) {
  if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
    fail("a required compiled artifact is not a regular file");
  }
  const size = statSync(path).size;
  if (size === 0 || size > maximumBytes) {
    fail("a compiled artifact violates its size bound");
  }
  return readFileSync(path);
}

function identityRows() {
  const lines = plainFile(identityManifest, 256 * 1024).toString("ascii").trimEnd().split("\n");
  if (lines.shift() !== "circuit\tartifact_identity_sha256" || lines.length !== lanes.length * stages.length) {
    fail("exact artifact identity manifest has an invalid shape");
  }
  const identities = new Map();
  for (const line of lines) {
    const fields = line.split("\t");
    if (fields.length !== 2 || !/^[a-f0-9]{64}$/u.test(fields[1]) || identities.has(fields[0])) {
      fail("exact artifact identity manifest has an invalid row");
    }
    identities.set(fields[0], fields[1]);
  }
  return identities;
}

function sourceRows(bytes) {
  const lines = bytes.toString("ascii").trimEnd().split("\n");
  if (lines.shift() !== "circuit\tpackage\tsource_closure_sha256") {
    fail("source lock header is invalid");
  }
  const sources = new Map();
  for (const line of lines) {
    const fields = line.split("\t");
    if (fields.length !== 3 || !/^[a-f0-9]{64}$/u.test(fields[2]) || sources.has(fields[0])) {
      fail("source lock row is invalid");
    }
    sources.set(fields[0], { packageName: fields[1], digest: fields[2] });
  }
  return sources;
}

if (process.argv.length !== 3 || candidate !== approvedCandidate ||
    !existsSync(candidate) || !lstatSync(candidate).isDirectory() || lstatSync(candidate).isSymbolicLink() ||
    !existsSync(join(candidate, "v1/v1/index.pb")) || existsSync(join(candidate, "common-credential-root-v1"))) {
  fail("expected the approved baseline candidate without staged common-credential-root artifacts");
}
const expectedSourceLock = process.env.REALLYME_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_SHA256;
const sourceBytes = plainFile(sourceLock, 256 * 1024);
if (!/^[a-f0-9]{64}$/u.test(expectedSourceLock ?? "") || digest(sourceBytes) !== expectedSourceLock) {
  fail("source lock differs from the separately reviewed digest");
}
for (const mode of ["exact-artifacts", "stage-requests"]) {
  const check = spawnSync(
    "node",
    [join(root, "scripts/check-common-credential-root-ci-artifacts.mjs"), mode],
    { cwd: root, stdio: "inherit" },
  );
  if (check.error !== undefined || check.status !== 0) {
    fail("the exact common-credential-root proof artifacts or vectors did not pass their gate");
  }
}

const sources = sourceRows(sourceBytes);
const identities = identityRows();
const temporary = mkdtempSync(join(artifactRoot, ".common-credential-root-artifacts-"));
try {
  const staged = join(temporary, "common-credential-root-v1");
  mkdirSync(staged);
  copyFileSync(sourceLock, join(staged, "modern-circuit-source-lock.tsv"));
  for (const lane of lanes) {
    for (const [stage, packageStem, proofDirectory] of stages) {
      const sourcePath = `${lane}/families/common_credential_root_v1/${stage}`;
      const source = sources.get(sourcePath);
      const expectedIdentity = identities.get(sourcePath);
      if (source === undefined || expectedIdentity === undefined) {
        fail("common-credential-root circuit is missing from the reviewed manifests");
      }
      const folder = join(root, "circuits", sourcePath, "target");
      const packageName = packageStem === "common_credential_root_v1"
        ? `common_credential_root_v1_${lane}_${stage}` : `${packageStem}_${lane}`;
      if (source.packageName !== packageName) {
        fail("compiled package name differs from the source lock");
      }
      const program = normalizeModernProgram(plainFile(join(folder, `${packageName}.json`), maximumProgramBytes));
      if (program === null) {
        fail("compiled program cannot be normalized");
      }
      const key = plainFile(join(folder, proofDirectory, "vk"), maximumKeyBytes);
      const actualIdentity = digest(Buffer.concat([
        identityDomain,
        Buffer.from(`${sourcePath}\n`),
        proofSuite,
        Buffer.from(source.digest, "hex"),
        Buffer.from(digest(program), "hex"),
        Buffer.from(digest(key), "hex"),
      ]));
      if (actualIdentity !== expectedIdentity) {
        fail("compiled program and key differ from the proven artifact identity");
      }
      const target = join(staged, lane, stage);
      mkdirSync(target, { recursive: true });
      writeFileSync(join(target, "program.json"), program, { flag: "wx", mode: 0o644 });
      writeFileSync(join(target, "verification-key.bin"), key, { flag: "wx", mode: 0o644 });
      identities.delete(sourcePath);
    }
  }
  if (identities.size !== 0) {
    fail("exact artifact manifest contains an unregistered circuit");
  }
  renameSync(staged, join(candidate, "common-credential-root-v1"));
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
