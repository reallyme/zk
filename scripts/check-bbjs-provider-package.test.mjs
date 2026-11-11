// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  BbjsProviderPackagePolicyError,
  readBbjsProviderPackageSources,
  validateBbjsProviderPackagePolicy,
} from "./check-bbjs-provider-package.mjs";

const sources = readBbjsProviderPackageSources(new URL("../", import.meta.url));

test("pins the reviewed bb.js provider package boundary", () => {
  assert.doesNotThrow(() => validateBbjsProviderPackagePolicy(sources));
});

test("rejects unreviewed bb.js peer version drift", () => {
  const changed = {
    ...sources,
    packageJson: sources.packageJson.replace('"6.0.0"', '"^6.0.0"'),
  };
  assert.throws(
    () => validateBbjsProviderPackagePolicy(changed),
    (error) =>
      error instanceof BbjsProviderPackagePolicyError &&
      error.code === "BBJS_PEER_VERSION_CHANGED",
  );
});

test("rejects package contents that omit license files", () => {
  const packageJson = JSON.parse(sources.packageJson);
  packageJson.files = packageJson.files.filter((path) => path !== "LICENSE-MIT");
  const changed = {
    ...sources,
    packageJson: JSON.stringify(packageJson),
  };
  assert.throws(
    () => validateBbjsProviderPackagePolicy(changed),
    (error) =>
      error instanceof BbjsProviderPackagePolicyError &&
      error.code === "PACKAGE_FILES_CHANGED",
  );
});

test("rejects static bb.js imports that would bundle the runtime", () => {
  const changed = {
    ...sources,
    runtime: `${sources.runtime}\nimport { UltraHonkBackend } from "@aztec-foundation/bb.js";\n`,
  };
  assert.throws(
    () => validateBbjsProviderPackagePolicy(changed),
    (error) =>
      error instanceof BbjsProviderPackagePolicyError &&
      error.code === "STATIC_BBJS_IMPORT_FORBIDDEN",
  );
});

test("rejects removal of the verifier SDK facade", () => {
  const changed = {
    ...sources,
    runtime: sources.runtime.replace(
      "export async function createReallyMeZkBbjsVerifier",
      "async function removedVerifierFacade",
    ),
  };
  assert.throws(
    () => validateBbjsProviderPackagePolicy(changed),
    (error) =>
      error instanceof BbjsProviderPackagePolicyError &&
      error.code === "VERIFIER_FACADE_REMOVED",
  );
});

test("rejects removal of the one-shot verification helper", () => {
  const changed = {
    ...sources,
    runtime: sources.runtime.replace(
      "export async function verifyReallyMeZkBbjsProof",
      "async function removedOneShotVerifier",
    ),
  };
  assert.throws(
    () => validateBbjsProviderPackagePolicy(changed),
    (error) =>
      error instanceof BbjsProviderPackagePolicyError &&
      error.code === "ONE_SHOT_VERIFY_REMOVED",
  );
});

test("rejects documentation that drops the circuit registry boundary", () => {
  const changed = {
    ...sources,
    readme: sources.readme.replace("does not create a second circuit registry", ""),
  };
  assert.throws(
    () => validateBbjsProviderPackagePolicy(changed),
    (error) =>
      error instanceof BbjsProviderPackagePolicyError &&
      error.code === "README_REGISTRY_BOUNDARY_CHANGED",
  );
});
