// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = "packages/bbjs-provider";
const BBJS_PACKAGE = "@aztec-foundation/bb.js";
const BBJS_VERSION = "6.0.0";
const REQUIRED_FILES = Object.freeze([
  "LICENSE-APACHE",
  "LICENSE-MIT",
  "README.md",
  "src/index.d.ts",
  "src/index.mjs",
]);

export class BbjsProviderPackagePolicyError extends Error {
  constructor(code) {
    super(code);
    this.name = "BbjsProviderPackagePolicyError";
    this.code = code;
  }
}

export function validateBbjsProviderPackagePolicy(sources) {
  const packageJson = parsePackageJson(sources.packageJson);
  requireEqual(packageJson.name, "@reallyme/zk-bbjs-provider", "PACKAGE_NAME_CHANGED");
  requireEqual(packageJson.version, "0.1.0", "PACKAGE_VERSION_CHANGED");
  requireEqual(packageJson.private, false, "PACKAGE_VISIBILITY_CHANGED");
  requireEqual(packageJson.type, "module", "PACKAGE_TYPE_CHANGED");
  requireEqual(packageJson.license, "MIT OR Apache-2.0", "PACKAGE_LICENSE_CHANGED");
  requireEqual(packageJson.main, "./src/index.mjs", "PACKAGE_MAIN_CHANGED");
  requireEqual(packageJson.types, "./src/index.d.ts", "PACKAGE_TYPES_CHANGED");
  requireEqual(packageJson.sideEffects, false, "PACKAGE_SIDEEFFECTS_CHANGED");
  requireEqual(packageJson.engines?.node, ">=24", "PACKAGE_NODE_ENGINE_CHANGED");
  requireEqual(packageJson.peerDependencies?.[BBJS_PACKAGE], BBJS_VERSION, "BBJS_PEER_VERSION_CHANGED");
  requireEqual(
    packageJson.peerDependenciesMeta?.[BBJS_PACKAGE]?.optional,
    true,
    "BBJS_PEER_OPTIONALITY_CHANGED",
  );
  requireEqual(
    packageJson.exports?.["."]?.import,
    "./src/index.mjs",
    "PACKAGE_EXPORT_IMPORT_CHANGED",
  );
  requireEqual(
    packageJson.exports?.["."]?.types,
    "./src/index.d.ts",
    "PACKAGE_EXPORT_TYPES_CHANGED",
  );
  requireArrayEqual(packageJson.files, REQUIRED_FILES, "PACKAGE_FILES_CHANGED");
  requireEqual(packageJson.scripts?.test, "node --test test/*.test.mjs", "PACKAGE_TEST_CHANGED");

  requireIncludes(sources.runtime, `const DEFAULT_BBJS_PACKAGE = "${BBJS_PACKAGE}";`, "BBJS_DEFAULT_CHANGED");
  requireIncludes(sources.runtime, "await import(specifier)", "BBJS_DYNAMIC_IMPORT_REMOVED");
  requireIncludes(
    sources.runtime,
    "export async function createReallyMeZkBbjsVerifier",
    "VERIFIER_FACADE_REMOVED",
  );
  requireIncludes(
    sources.runtime,
    "export async function verifyReallyMeZkBbjsProof",
    "ONE_SHOT_VERIFY_REMOVED",
  );
  requireIncludes(
    sources.declarations,
    "export declare function createReallyMeZkBbjsVerifier",
    "VERIFIER_DECLARATION_REMOVED",
  );
  requireIncludes(
    sources.declarations,
    "export declare function verifyReallyMeZkBbjsProof",
    "ONE_SHOT_VERIFY_DECLARATION_REMOVED",
  );
  requireIncludes(
    sources.readme,
    "createReallyMeZkBbjsVerifier()",
    "README_VERIFIER_FACADE_REMOVED",
  );
  requireIncludes(
    sources.readme,
    "verifyReallyMeZkBbjsProof()",
    "README_ONE_SHOT_VERIFY_REMOVED",
  );
  rejectPattern(sources.runtime, /from\s+["']@aztec(?:-foundation)?\/bb\.js["']/u, "STATIC_BBJS_IMPORT_FORBIDDEN");
  rejectPattern(sources.runtime, /require\(\s*["']@aztec(?:-foundation)?\/bb\.js["']\s*\)/u, "STATIC_BBJS_REQUIRE_FORBIDDEN");
  requireIncludes(sources.runtime, "KNOWN_ERROR_REASONS", "UNTYPED_LOADER_REASON_GUARD_REMOVED");
  requireIncludes(sources.runtime, "compressedWitness.fill(0)", "WITNESS_ZEROIZATION_REMOVED");
  requireIncludes(sources.runtime, "witnessForBackend.fill(0)", "BACKEND_WITNESS_ZEROIZATION_REMOVED");

  requireIncludes(sources.declarations, "InvalidLimit: \"invalid_limit\"", "DECLARATION_ERROR_REASON_CHANGED");
  requireIncludes(sources.readme, `${BBJS_PACKAGE}@${BBJS_VERSION}`, "README_PIN_CHANGED");
  requireIncludes(sources.readme, "does not create a second circuit registry", "README_REGISTRY_BOUNDARY_CHANGED");
}

export function readBbjsProviderPackageSources(repoRoot) {
  return Object.freeze({
    declarations: readFileSync(new URL(`${PACKAGE_ROOT}/src/index.d.ts`, repoRoot), "utf8"),
    packageJson: readFileSync(new URL(`${PACKAGE_ROOT}/package.json`, repoRoot), "utf8"),
    readme: readFileSync(new URL(`${PACKAGE_ROOT}/README.md`, repoRoot), "utf8"),
    runtime: readFileSync(new URL(`${PACKAGE_ROOT}/src/index.mjs`, repoRoot), "utf8"),
  });
}

function parsePackageJson(source) {
  try {
    return JSON.parse(source);
  } catch {
    throw new BbjsProviderPackagePolicyError("PACKAGE_JSON_INVALID");
  }
}

function requireEqual(actual, expected, code) {
  if (actual !== expected) {
    throw new BbjsProviderPackagePolicyError(code);
  }
}

function requireArrayEqual(actual, expected, code) {
  if (
    !Array.isArray(actual) ||
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    throw new BbjsProviderPackagePolicyError(code);
  }
}

function requireIncludes(source, needle, code) {
  if (!source.includes(needle)) {
    throw new BbjsProviderPackagePolicyError(code);
  }
}

function rejectPattern(source, pattern, code) {
  if (pattern.test(source)) {
    throw new BbjsProviderPackagePolicyError(code);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const repoRoot = new URL("../", import.meta.url);
  try {
    validateBbjsProviderPackagePolicy(readBbjsProviderPackageSources(repoRoot));
    process.stdout.write("bb.js provider package policy passed\n");
  } catch (error) {
    if (error instanceof BbjsProviderPackagePolicyError) {
      process.stderr.write(`bb.js provider package policy failed: ${error.code}\n`);
      process.exitCode = 1;
    } else {
      throw error;
    }
  }
}
