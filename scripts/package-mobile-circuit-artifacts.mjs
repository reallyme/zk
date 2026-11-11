#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactRoot = resolve(
  process.env.REALLYME_ZK_LOCAL_ARTIFACT_ROOT ??
    join(repositoryRoot, "release-artifacts/modern-v1-bb-6.0.0"),
);
const sourceRoot = join(artifactRoot, "mobile-demo-artifacts-persona-credential-evidence-v1-candidate");
const archivePath = join(artifactRoot, "mobile-circuit-artifacts-persona-credential-evidence-v1.tar");
const digestPath = `${archivePath}.sha256`;

if (process.argv.length !== 2) {
  fail("this command does not accept arguments");
}
if (!existsSync(sourceRoot) || !statSync(sourceRoot).isDirectory()) {
  fail("sealed mobile artifact source directory is missing");
}
if (existsSync(archivePath)) {
  fail("mobile circuit artifact archive already exists");
}

const paths = [];
walk(sourceRoot, "", paths);
paths.sort();
const counts = new Map();
for (const path of paths) {
  const name = path.split("/").at(-1);
  counts.set(name, (counts.get(name) ?? 0) + 1);
  if (!isAllowed(path)) {
    fail(`unexpected artifact path ${path}`);
  }
  if (name === "program.json") {
    checkPortableProgramPaths(join(sourceRoot, path));
  }
}
for (const [name, count] of [
  ["index.pb", 1],
  ["modern-circuit-source-lock.tsv", 2],
  ["manifest.pb", 16],
  ["program.json", 42],
  ["verification-key.bin", 42],
]) {
  if (counts.get(name) !== count) {
    fail(`expected ${count} ${name} files`);
  }
}
if (paths.length !== 103) {
  fail("runtime artifact set must contain exactly 103 files");
}

const stagingRoot = mkdtempSync(join(artifactRoot, ".mobile-circuit-package-"));
const temporaryArchive = `${archivePath}.partial`;
try {
  for (const path of paths) {
    const target = join(stagingRoot, path);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(sourceRoot, path), target);
    chmodSync(target, 0o644);
    utimesSync(target, 0, 0);
  }
  const result = spawnSync(
    "tar",
    [
      "-cf", temporaryArchive,
      "--format=ustar",
      "--uid", "0",
      "--gid", "0",
      "--uname", "root",
      "--gname", "root",
      "-C", stagingRoot,
      ...paths,
    ],
    {
      cwd: repositoryRoot,
      env: { ...process.env, COPYFILE_DISABLE: "1" },
      stdio: "inherit",
    },
  );
  if (result.error !== undefined || result.status !== 0) {
    fail("could not create mobile circuit artifact archive");
  }
  renameSync(temporaryArchive, archivePath);
  const digest = createHash("sha256").update(readFileSync(archivePath)).digest("hex");
  writeFileSync(digestPath, `${digest}  ${relative(artifactRoot, archivePath)}\n`);
  console.log(`${archivePath}\t${digest}`);
} finally {
  rmSync(stagingRoot, { recursive: true, force: true });
  rmSync(temporaryArchive, { force: true });
}

function walk(root, prefix, output) {
  for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
    const path = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name !== "vectors" && entry.name !== "verification-vectors") {
        walk(root, path, output);
      }
    } else if (entry.isFile() && !lstatSync(join(root, path)).isSymbolicLink()) {
      output.push(path);
    } else {
      fail(`unsupported artifact entry ${path}`);
    }
  }
}

function isAllowed(path) {
  if (path === "v1/v1/index.pb" ||
      path === "common-credential-root-v1/modern-circuit-source-lock.tsv" ||
      path === "persona-credential-evidence-v1/modern-circuit-source-lock.tsv") {
    return true;
  }
  if (/^common-credential-root-v1\/(sha256|poseidon2)\/(root_attestation|root_status|lineage|issuer_credential_status|private_persona_claim|public_persona_claim|public_session)\/(program\.json|verification-key\.bin)$/u.test(path)) {
    return true;
  }
  if (/^persona-credential-evidence-v1\/(sha256|poseidon2)\/(issuer_envelope|claim_root|signed_validity|public_claim|private_claim|current_state)\/(program\.json|verification-key\.bin)$/u.test(path)) {
    return true;
  }
  return /^v1\/(sha256|poseidon2)\/(credential_subject_claim_v1|private_persona_claim_v1)\/(claim|credential_envelope|credential_root|session)\/[a-f0-9]{64}\/(manifest\.pb|program\.json|verification-key\.bin)$/u.test(path);
}

function checkPortableProgramPaths(path) {
  let program;
  try {
    program = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail("compiled program is not valid JSON");
  }
  if (program === null || typeof program !== "object" ||
      program.file_map === null || typeof program.file_map !== "object" ||
      Array.isArray(program.file_map)) {
    fail("compiled program has no valid source file map");
  }
  for (const entry of Object.values(program.file_map)) {
    if (entry === null || typeof entry !== "object" ||
        typeof entry.path !== "string" || entry.path.length === 0 ||
        entry.path.startsWith("/") || entry.path.startsWith("\\") ||
        /^[a-zA-Z]:[\\/]/u.test(entry.path) ||
        entry.path.split(/[\\/]/u).includes("..")) {
      fail("compiled program contains a nonportable source path");
    }
  }
}

function fail(reason) {
  console.error(`mobile circuit artifact package failed: ${reason}`);
  process.exit(1);
}
