#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Compile the twelve exact prepared source circuits into a separately sealed
// local candidate. The Rust sealer authenticates every output before the
// candidate index can admit it; this script never edits a published pack.

import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readSync,
  openSync,
  closeSync,
  renameSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeModernProgram } from "./normalize-modern-program.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const lock = JSON.parse(readFileSync(join(root, "circuits/toolchain-lock.json"), "utf8"));
const pair = lock.candidateMatchedPair;
const candidate = resolve(process.argv[2] ?? "");
const artifactRoot = resolve(process.env.REALLYME_ZK_LOCAL_ARTIFACT_ROOT ??
  join(root, "build/native"));
const expectedCandidate = join(
  artifactRoot, "mobile-demo-artifacts-persona-credential-evidence-v1-candidate",
);
const nargo = requiredEnvironmentPath("NARGO");
const bb = requiredEnvironmentPath("BB");
const crs = resolve(process.env.BB_CRS_DIR ?? join(process.env.HOME ?? "", ".bb-crs"));
const sourceLock = join(root, "circuits/modern-circuit-source-lock.tsv");
const expectedSourceLock = process.env.REALLYME_PREPARED_SOURCE_LOCK_SHA256;
const stages = ["issuer_envelope", "claim_root", "signed_validity", "public_claim", "private_claim", "current_state"];
const lanes = ["sha256", "poseidon2"];
const maximumProgramBytes = 32 * 1024 * 1024;
const maximumKeyBytes = 32 * 1024 * 1024;

function fail(reason) {
  throw new Error(`prepared candidate preparation failed: ${reason}`);
}

function requiredEnvironmentPath(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    fail("required toolchain path is not configured");
  }
  return resolve(value);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readBounded(path, limit) {
  if (!statSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
    fail("artifact is not a regular file");
  }
  const size = statSync(path).size;
  if (size === 0 || size > limit) {
    fail("artifact exceeds its bounded file size");
  }
  return readFileSync(path);
}

function run(executable, args, cwd) {
  const result = spawnSync(executable, args, { cwd, stdio: "inherit" });
  if (result.error !== undefined || result.status !== 0) {
    fail("pinned compiler or key generator failed");
  }
}

function verifyPinnedExecutable(path, expected) {
  if (!/^[a-f0-9]{64}$/u.test(expected) ||
      digest(readBounded(realpathSync(path), 128 * 1024 * 1024)) !== expected) {
    fail("toolchain executable does not match its reviewed digest");
  }
}

function platformIdentity() {
  if (process.platform === "darwin" && process.arch === "arm64") {
    return pair.localBinaryIdentities.darwinArm64;
  }
  if (process.platform === "linux" && process.arch === "x64") {
    return pair.localBinaryIdentities.linuxX86_64;
  }
  fail("no reviewed toolchain identity exists for this build host");
}

function verifyPinnedCrs() {
  const pin = pair.barretenberg.crsIdentities.bn254FullProver1048577Points;
  const g1 = join(crs, "bn254_g1.dat");
  const g2 = join(crs, "bn254_g2.dat");
  if (!statSync(g1).isFile() || lstatSync(g1).isSymbolicLink() ||
      statSync(g1).size < pin.g1SourceBytes ||
      digest(readBounded(g2, pin.g2Bytes)) !== pin.g2Sha256) {
    fail("CRS source does not match the reviewed profile");
  }
  // The local CRS may contain more powers than this release uses. Authenticate
  // the exact reviewed source prefix and the smaller prover prefix.
  const chunk = Buffer.alloc(1024 * 1024);
  const sourceDigest = createHash("sha256");
  const proverDigest = createHash("sha256");
  const descriptor = openSync(g1, "r");
  try {
    let offset = 0;
    while (offset < pin.g1SourceBytes) {
      const length = Math.min(chunk.length, pin.g1SourceBytes - offset);
      const count = readSync(descriptor, chunk, 0, length, offset);
      if (count === 0) fail("CRS G1 prefix is truncated");
      sourceDigest.update(chunk.subarray(0, count));
      if (offset < pin.g1PrefixBytes) {
        const proverLength = Math.min(count, pin.g1PrefixBytes - offset);
        proverDigest.update(chunk.subarray(0, proverLength));
      }
      offset += count;
    }
    if (sourceDigest.digest("hex") !== pin.g1SourceSha256 ||
        proverDigest.digest("hex") !== pin.g1PrefixSha256) {
      fail("CRS G1 prefix digest mismatch");
    }
  } finally {
    chunk.fill(0);
    closeSync(descriptor);
  }
}

if (process.argv.length !== 3 || candidate !== expectedCandidate ||
    !existsSync(candidate) || lstatSync(candidate).isSymbolicLink() ||
    !statSync(candidate).isDirectory()) {
  fail("expected the approved existing local candidate directory");
}
if (!/^[a-f0-9]{64}$/u.test(expectedSourceLock ?? "") ||
    digest(readBounded(sourceLock, 64 * 1024)) !== expectedSourceLock) {
  fail("source lock does not match the separately reviewed digest");
}
const binaryIdentity = platformIdentity();
verifyPinnedExecutable(nargo, binaryIdentity.nargoExecutableSha256);
verifyPinnedExecutable(bb, binaryIdentity.barretenbergExecutableSha256);
verifyPinnedCrs();

const targetRoot = join(candidate, "persona-credential-evidence-v1");
if (existsSync(targetRoot)) fail("prepared candidate artifacts already exist");
const temporary = mkdtempSync(join(dirname(candidate), ".prepared-artifacts-"));
try {
  const staged = join(temporary, "persona-credential-evidence-v1");
  mkdirSync(staged);
  copyFileSync(sourceLock, join(staged, "modern-circuit-source-lock.tsv"));
  for (const lane of lanes) {
    for (const stage of stages) {
      const folder = join(root, "circuits", lane, "families/persona_credential_evidence_v1", stage);
      const packageName = `credential_persona_credential_evidence_v1_${stage}_${lane}`;
      run(nargo, ["compile", "--force"], folder);
      const sourceProgram = join(folder, "target", `${packageName}.json`);
      const normalized = normalizeModernProgram(readBounded(sourceProgram, maximumProgramBytes));
      if (normalized === null) fail("compiled program normalization failed");
      const target = join(staged, lane, stage);
      mkdirSync(target, { recursive: true });
      const program = join(target, "program.json");
      writeFileSync(program, normalized, { flag: "wx", mode: 0o644 });
      const keyDirectory = join(temporary, "keys", lane, stage);
      mkdirSync(keyDirectory, { recursive: true });
      run(bb, ["write_vk", "-t", "evm", "-c", crs, "-b", program, "-o", keyDirectory], root);
      const key = readBounded(join(keyDirectory, "vk"), maximumKeyBytes);
      writeFileSync(join(target, "verification-key.bin"), key, { flag: "wx", mode: 0o644 });
      if (digest(readBounded(program, maximumProgramBytes)) !== digest(normalized)) {
        fail("staged program changed after normalization");
      }
    }
  }
  // A rename into the approved candidate makes the six-stage set visible at
  // once. The Rust sealer still checks every path and digest before admission.
  renameSync(staged, targetRoot);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
