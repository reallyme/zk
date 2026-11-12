#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { PUBLIC_CRATES } from "./public-crates.mjs";

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const REQUEST_TIMEOUT_MILLISECONDS = 30_000;
const SEMVER_CHECK_TIMEOUT_MILLISECONDS = 600_000;
const CRATES_IO_API_ROOT = "https://crates.io/api/v1/crates";
const RELEASE_VERSION_PATTERN = /^(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)$/u;
export { PUBLIC_CRATES } from "./public-crates.mjs";

export class PublicCrateBaselineError extends Error {
  constructor(code) {
    super(code);
    this.name = "PublicCrateBaselineError";
    this.code = code;
  }
}

export function publicManifestVersions({ readManifest = (path) => readFileSync(path, "utf8") } = {}) {
  return PUBLIC_CRATES.map((crate) => {
    let source;
    try { source = readManifest(crate.manifest); } catch {
      throw new PublicCrateBaselineError("public-manifest-unavailable");
    }
    if (typeof source !== "string" || Buffer.byteLength(source, "utf8") > 65_536) {
      throw new PublicCrateBaselineError("invalid-public-manifest");
    }
    const versions = [...source.matchAll(/^version\s*=\s*"([^"]+)"\s*$/gmu)];
    if (versions.length !== 1 || !RELEASE_VERSION_PATTERN.test(versions[0][1])) {
      throw new PublicCrateBaselineError("invalid-public-manifest-version");
    }
    return versions[0][1];
  });
}

export function plannedPublicReleaseVersion(options = {}) {
  const versions = publicManifestVersions(options);
  if (versions.every((version) => version === versions[0])) return versions[0];
  // Adding providers must not rename or recreate the existing SDK release.
  const bootstrap = versions.every((version, index) => version === (index < 3 ? "0.3.0" : "0.3.1"));
  if (bootstrap) return "0.3.0";
  throw new PublicCrateBaselineError("public-manifest-version-mismatch");
}

function parseReleaseVersion(version) {
  if (!RELEASE_VERSION_PATTERN.test(version)) {
    throw new PublicCrateBaselineError("invalid-release-version");
  }
  const parts = version.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.some((part) => !Number.isSafeInteger(part))) {
    throw new PublicCrateBaselineError("invalid-release-version");
  }
  return Object.freeze({ major: parts[0], minor: parts[1], patch: parts[2] });
}

function compareReleaseVersions(left, right) {
  for (const field of ["major", "minor", "patch"]) {
    if (left[field] !== right[field]) {
      return left[field] < right[field] ? -1 : 1;
    }
  }
  return 0;
}

function latestPublishedVersion(payload) {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new PublicCrateBaselineError("invalid-registry-response");
  }
  const versions = payload.versions;
  if (!Array.isArray(versions)) {
    throw new PublicCrateBaselineError("invalid-registry-response");
  }

  let latest = null;
  for (const candidate of versions) {
    if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
      throw new PublicCrateBaselineError("invalid-registry-response");
    }
    if (typeof candidate.num !== "string" || typeof candidate.yanked !== "boolean") {
      throw new PublicCrateBaselineError("invalid-registry-response");
    }
    if (candidate.yanked || !RELEASE_VERSION_PATTERN.test(candidate.num)) {
      continue;
    }
    const parsed = parseReleaseVersion(candidate.num);
    if (latest === null || compareReleaseVersions(parsed, latest.parsed) > 0) {
      latest = Object.freeze({ version: candidate.num, parsed });
    }
  }
  if (latest === null) {
    throw new PublicCrateBaselineError("registry-has-no-stable-baseline");
  }
  return latest;
}

async function registryBaseline(packageName, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(`${CRATES_IO_API_ROOT}/${encodeURIComponent(packageName)}`, {
      headers: { "User-Agent": "reallyme-zk-release-preflight" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLISECONDS),
    });
  } catch {
    throw new PublicCrateBaselineError("registry-request-failed");
  }
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new PublicCrateBaselineError("registry-request-failed");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new PublicCrateBaselineError("invalid-registry-response");
  }
  return latestPublishedVersion(payload);
}

function runSemverCheck(crate, baselineVersion) {
  const result = spawnSync(
    "cargo",
    [
      "semver-checks",
      "--manifest-path",
      crate.manifest,
      "--baseline-version",
      baselineVersion,
      "--all-features",
    ],
    {
      stdio: "inherit",
      timeout: SEMVER_CHECK_TIMEOUT_MILLISECONDS,
      killSignal: "SIGTERM",
    },
  );
  if (result.error !== undefined || result.status !== 0) {
    throw new PublicCrateBaselineError("semver-check-failed");
  }
}

export async function checkPublicCrateBaselines({
  releaseVersion,
  fetchImpl = fetch,
  semverCheck = runSemverCheck,
  manifestVersions,
} = {}) {
  const versions = manifestVersions ?? PUBLIC_CRATES.map(() => releaseVersion);
  if (!Array.isArray(versions) || versions.length !== PUBLIC_CRATES.length) {
    throw new PublicCrateBaselineError("public-manifest-version-mismatch");
  }
  const results = [];
  for (const [index, crate] of PUBLIC_CRATES.entries()) {
    const requested = parseReleaseVersion(versions[index] ?? "");
    const baseline = await registryBaseline(crate.name, fetchImpl);
    if (baseline === null) {
      if (crate.firstVersion === null) {
        throw new PublicCrateBaselineError("published-baseline-missing");
      }
      if (compareReleaseVersions(requested, parseReleaseVersion(crate.firstVersion)) !== 0) {
        throw new PublicCrateBaselineError("first-publication-version-mismatch");
      }
      results.push(Object.freeze({ name: crate.name, status: "first-publication" }));
      continue;
    }

    const ordering = compareReleaseVersions(requested, baseline.parsed);
    if (ordering < 0) {
      throw new PublicCrateBaselineError("release-version-regression");
    }
    if (ordering === 0) {
      // A prior job may have published only part of this lockstep wave. The
      // publisher separately downloads that exact version and requires its
      // archive digest to match before it resumes dependent publication.
      results.push(Object.freeze({ name: crate.name, status: "same-version-recovery" }));
      continue;
    }

    semverCheck(crate, baseline.version);
    results.push(
      Object.freeze({
        name: crate.name,
        status: "checked",
        baselineVersion: baseline.version,
      }),
    );
  }
  return Object.freeze(results);
}

async function main() {
  try {
    const results = await checkPublicCrateBaselines({
      releaseVersion: process.env.RELEASE_VERSION,
      manifestVersions: process.env.RELEASE_VERSION === undefined ? publicManifestVersions() : undefined,
    });
    for (const result of results) {
      if (result.status === "checked") {
        console.log(`${result.name}: API checked against ${result.baselineVersion}`);
      } else {
        console.log(`${result.name}: ${result.status}`);
      }
    }
  } catch (error) {
    const code =
      error instanceof PublicCrateBaselineError
        ? error.code
        : "unexpected-public-crate-baseline-failure";
    console.error(`public crate baseline check failed: ${code}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
