#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(scriptPath, "..", "..");
const defaultCircuitsRoot = join(repoRoot, "circuits");
const defaultLockPath = join(defaultCircuitsRoot, "modern-circuit-source-lock.tsv");

export class ModernSourceLockError extends Error {
  constructor(code) {
    super(code);
    this.name = "ModernSourceLockError";
    this.code = code;
  }
}

export const COMMON_CREDENTIAL_ROOT_SOURCE_PATHS = Object.freeze([
  "poseidon2/families/common_credential_root_v1/issuer_credential_status",
  "poseidon2/families/common_credential_root_v1/lineage",
  "poseidon2/families/common_credential_root_v1/private_persona_claim",
  "poseidon2/families/common_credential_root_v1/public_persona_claim",
  "poseidon2/families/common_credential_root_v1/public_session",
  "poseidon2/families/common_credential_root_v1/root_attestation",
  "poseidon2/families/common_credential_root_v1/root_status",
  "sha256/families/common_credential_root_v1/issuer_credential_status",
  "sha256/families/common_credential_root_v1/lineage",
  "sha256/families/common_credential_root_v1/private_persona_claim",
  "sha256/families/common_credential_root_v1/public_persona_claim",
  "sha256/families/common_credential_root_v1/public_session",
  "sha256/families/common_credential_root_v1/root_attestation",
  "sha256/families/common_credential_root_v1/root_status",
]);

export const PERSONA_CREDENTIAL_EVIDENCE_SOURCE_PATHS = Object.freeze([
  "poseidon2/families/persona_credential_evidence_v1/claim_root",
  "poseidon2/families/persona_credential_evidence_v1/current_state",
  "poseidon2/families/persona_credential_evidence_v1/issuer_envelope",
  "poseidon2/families/persona_credential_evidence_v1/private_claim",
  "poseidon2/families/persona_credential_evidence_v1/public_claim",
  "poseidon2/families/persona_credential_evidence_v1/signed_validity",
  "sha256/families/persona_credential_evidence_v1/claim_root",
  "sha256/families/persona_credential_evidence_v1/current_state",
  "sha256/families/persona_credential_evidence_v1/issuer_envelope",
  "sha256/families/persona_credential_evidence_v1/private_claim",
  "sha256/families/persona_credential_evidence_v1/public_claim",
  "sha256/families/persona_credential_evidence_v1/signed_validity",
]);

const HEADER = "circuit\tpackage\tsource_closure_sha256";
const EXPECTED_CIRCUIT_COUNT = 46;
const EXPECTED_CREDENTIAL_CIRCUIT_COUNT = 20;
const DIGEST_HEX = /^[0-9a-f]{64}$/u;

export function readRegistryPaths({ root = repoRoot } = {}) {
  const result = spawnSync("cargo", ["run", "--quiet", "-p", "reallyme-zk-cli", "--", "circuits", "--paths"], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    throw new ModernSourceLockError("REGISTRY_COMMAND_FAILED");
  }
  const lines = result.stdout.trimEnd().split("\n");
  if (lines[0] !== "circuit_path") {
    throw new ModernSourceLockError("REGISTRY_HEADER_CHANGED");
  }
  return lines.slice(1).sort();
}

export function readSourceLock(lockPath = defaultLockPath) {
  const lines = readFileSync(lockPath, "utf8").trimEnd().split("\n");
  if (lines[0] !== HEADER) {
    throw new ModernSourceLockError("SOURCE_LOCK_HEADER_CHANGED");
  }
  const rows = new Map();
  for (const line of lines.slice(1)) {
    const fields = line.split("\t");
    if (fields.length !== 3 || fields[0] === "" || fields[1] === "" || !DIGEST_HEX.test(fields[2])) {
      throw new ModernSourceLockError("SOURCE_LOCK_ROW_MALFORMED");
    }
    if (rows.has(fields[0])) {
      throw new ModernSourceLockError("SOURCE_LOCK_DUPLICATE_ROW");
    }
    rows.set(fields[0], {
      packageName: fields[1],
      sourceClosureSha256: fields[2],
    });
  }
  return rows;
}

export function validateModernCircuitSourceLock({
  circuitsRoot = defaultCircuitsRoot,
  lockPath = defaultLockPath,
  registryPaths = readRegistryPaths(),
} = {}) {
  const rows = readSourceLock(lockPath);
  const registry = [...registryPaths].sort();
  if (registry.length !== EXPECTED_CIRCUIT_COUNT || rows.size !== EXPECTED_CIRCUIT_COUNT) {
    throw new ModernSourceLockError("SOURCE_LOCK_COUNT_MISMATCH");
  }

  const commonCredentialRootRows = registry.filter((sourcePath) => sourcePath.includes("/common_credential_root_v1/"));
  if (!sameStringSet(commonCredentialRootRows, COMMON_CREDENTIAL_ROOT_SOURCE_PATHS)) {
    throw new ModernSourceLockError("COMMON_CREDENTIAL_ROOT_SOURCE_SET_MISMATCH");
  }
  const preparedRows = registry.filter((sourcePath) => sourcePath.includes("/persona_credential_evidence_v1/"));
  if (!sameStringSet(preparedRows, PERSONA_CREDENTIAL_EVIDENCE_SOURCE_PATHS)) {
    throw new ModernSourceLockError("PERSONA_CREDENTIAL_EVIDENCE_SOURCE_SET_MISMATCH");
  }
  if (registry.length - commonCredentialRootRows.length - preparedRows.length !== EXPECTED_CREDENTIAL_CIRCUIT_COUNT) {
    throw new ModernSourceLockError("CREDENTIAL_SOURCE_COUNT_CHANGED");
  }

  for (const sourcePath of registry) {
    const row = rows.get(sourcePath);
    if (row === undefined) {
      throw new ModernSourceLockError("SOURCE_LOCK_MISSING_ROW");
    }
    const manifestPath = join(circuitsRoot, sourcePath, "Nargo.toml");
    if (!existsSync(manifestPath)) {
      throw new ModernSourceLockError("SOURCE_DIRECTORY_MISSING");
    }
    const packageName = readNargoPackageName(manifestPath);
    if (row.packageName !== packageName) {
      throw new ModernSourceLockError("SOURCE_LOCK_PACKAGE_MISMATCH");
    }
    const digest = sourceClosureSha256(circuitsRoot, sourcePath);
    if (row.sourceClosureSha256 !== digest) {
      throw new ModernSourceLockError("SOURCE_LOCK_STALE_DIGEST");
    }
  }

  for (const sourcePath of rows.keys()) {
    if (!registry.includes(sourcePath)) {
      throw new ModernSourceLockError("SOURCE_LOCK_UNKNOWN_ROW");
    }
  }
}

function sameStringSet(left, right) {
  return left.length === right.length && left.every((value) => right.includes(value));
}

function readNargoPackageName(manifestPath) {
  const manifest = readFileSync(manifestPath, "utf8");
  const match = /^name\s*=\s*"([^"]+)"\s*$/mu.exec(manifest);
  if (match === null) {
    throw new ModernSourceLockError("SOURCE_MANIFEST_PACKAGE_MISSING");
  }
  return match[1];
}

function sourceClosureSha256(circuitsRoot, circuitPath) {
  const fileHashLines = sourceFiles(circuitsRoot, circuitPath)
    .map((sourcePath) => `${sourcePath}\t${sha256File(join(circuitsRoot, sourcePath))}\n`)
    .join("");
  return createHash("sha256").update(fileHashLines).digest("hex");
}

function sourceFiles(circuitsRoot, circuitPath) {
  const files = [...sourceFilesUnder(join(circuitsRoot, circuitPath), circuitsRoot)];
  const vendorRoot = join(circuitsRoot, "vendor");
  if (existsSync(vendorRoot)) {
    files.push(...sourceFilesUnder(vendorRoot, circuitsRoot));
  }
  return files.sort();
}

function sourceFilesUnder(root, circuitsRoot) {
  const files = [];
  visitSourceTree(root, circuitsRoot, files);
  return files;
}

function visitSourceTree(root, circuitsRoot, files) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const absolutePath = join(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "target") {
        visitSourceTree(absolutePath, circuitsRoot, files);
      }
      continue;
    }
    if (!entry.isFile() || (entry.name !== "Nargo.toml" && !entry.name.endsWith(".nr"))) {
      continue;
    }
    const relativePath = relative(circuitsRoot, absolutePath).split(sep).join("/");
    files.push(relativePath);
  }
}

function sha256File(path) {
  if (!statSync(path).isFile()) {
    throw new ModernSourceLockError("SOURCE_FILE_MISSING");
  }
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    validateModernCircuitSourceLock();
    console.log("modern circuit source lock ok");
  } catch (error) {
    if (error instanceof ModernSourceLockError) {
      console.error(`modern circuit source lock failed: ${error.code}`);
      process.exit(2);
    }
    throw error;
  }
}
