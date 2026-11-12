#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  checkPublicCrateBaselines,
  publicManifestVersions,
  plannedPublicReleaseVersion,
  PublicCrateBaselineError,
} from "./check-public-crate-baselines.mjs";

function response(status, versions = []) {
  return Object.freeze({
    status,
    ok: status >= 200 && status < 300,
    async json() {
      return { versions };
    },
  });
}

test("a registry 404 is the only first-publication response", async () => {
  const calls = [];
  const results = await checkPublicCrateBaselines({
    manifestVersions: ["0.3.0", "0.3.0", "0.3.0", "0.3.1", "0.3.1"],
    fetchImpl: async (url) => url.endsWith("/reallyme-zk-api")
      ? response(200, [{ num: "0.2.1", yanked: false }]) : response(404),
    semverCheck: (crate, version) => calls.push([crate.name, version]),
  });
  assert.deepEqual(
    results.map(({ status }) => status),
    ["checked", ...new Array(4).fill("first-publication")],
  );
  assert.deepEqual(calls, [["reallyme-zk-api", "0.2.1"]]);
});

test("first publication is limited to the authorized 0.3.0 wave", async () => {
  await assert.rejects(
    checkPublicCrateBaselines({
      releaseVersion: "0.2.0",
      fetchImpl: async (url) => url.endsWith("/reallyme-zk-api")
        ? response(200, [{ num: "0.2.0", yanked: false }]) : response(404),
      semverCheck: () => assert.fail("same-version recovery needs no API check"),
    }),
    (error) =>
      error instanceof PublicCrateBaselineError &&
      error.code === "first-publication-version-mismatch",
  );
});

test("the already published API must have a registry baseline", async () => {
  await assert.rejects(
    checkPublicCrateBaselines({
      releaseVersion: "0.3.0",
      fetchImpl: async () => response(404),
      semverCheck: () => assert.fail("missing API baseline must fail before compatibility checks"),
    }),
    (error) => error instanceof PublicCrateBaselineError && error.code === "published-baseline-missing",
  );
});

test("registry transport failure is not treated as first publication", async () => {
  await assert.rejects(
    checkPublicCrateBaselines({
      releaseVersion: "0.1.0",
      fetchImpl: async () => {
        throw new TypeError("simulated transport failure");
      },
    }),
    (error) =>
      error instanceof PublicCrateBaselineError && error.code === "registry-request-failed",
  );
});

test("non-404 registry failure is release-blocking", async () => {
  await assert.rejects(
    checkPublicCrateBaselines({
      releaseVersion: "0.1.0",
      fetchImpl: async () => response(503),
    }),
    (error) =>
      error instanceof PublicCrateBaselineError && error.code === "registry-request-failed",
  );
});

test("every version advance uses the latest non-yanked exact baseline", async () => {
  const calls = [];
  const results = await checkPublicCrateBaselines({
    releaseVersion: "0.2.0",
    fetchImpl: async () =>
      response(200, [
        { num: "0.1.0", yanked: false },
        { num: "0.1.1", yanked: true },
      ]),
    semverCheck: (crate, baselineVersion) => calls.push([crate.name, baselineVersion]),
  });
  assert.equal(calls.length, 5);
  assert.ok(calls.every(([, baselineVersion]) => baselineVersion === "0.1.0"));
  assert.ok(results.every(({ status }) => status === "checked"));
});

test("version regression fails before API compatibility execution", async () => {
  await assert.rejects(
    checkPublicCrateBaselines({
      releaseVersion: "0.1.0",
      fetchImpl: async () => response(200, [{ num: "0.2.0", yanked: false }]),
      semverCheck: () => assert.fail("regressions cannot reach API checks"),
    }),
    (error) =>
      error instanceof PublicCrateBaselineError && error.code === "release-version-regression",
  );
});

test("same-version partial-wave recovery defers to archive identity checking", async () => {
  const results = await checkPublicCrateBaselines({
    releaseVersion: "0.2.0",
    fetchImpl: async () => response(200, [{ num: "0.2.0", yanked: false }]),
    semverCheck: () => assert.fail("same version is not a new API baseline"),
  });
  assert.ok(results.every(({ status }) => status === "same-version-recovery"));
});


test("ordinary CI derives a single lockstep version from all public manifests", () => {
  const seen = [];
  assert.equal(plannedPublicReleaseVersion({ readManifest: (path) => {
    seen.push(path);
    return '[package]\nversion = "0.3.0"\n';
  } }), "0.3.0");
  assert.equal(seen.length, 5);
});

test("public manifest drift and malformed versions fail before registry access", () => {
  for (const source of ['[package]\nversion = "latest"\n', '[package]\n', 'x'.repeat(65_537)]) {
    assert.throws(() => plannedPublicReleaseVersion({ readManifest: () => source }), PublicCrateBaselineError);
  }
  assert.throws(() => plannedPublicReleaseVersion({ readManifest: (path) =>
    `[package]\nversion = "${path.includes("artifacts") ? "0.2.1" : "0.3.0"}"\n`,
  }), (error) => error instanceof PublicCrateBaselineError && error.code === "public-manifest-version-mismatch");
  assert.throws(() => plannedPublicReleaseVersion({ readManifest: () => { throw new TypeError("unavailable"); } }),
    (error) => error instanceof PublicCrateBaselineError && error.code === "public-manifest-unavailable");
});


test("provider bootstrap keeps the existing release version without accepting arbitrary version drift", () => {
  const readManifest = (path) => `[package]\nversion = "${["crates/api/", "crates/artifacts/", "crates/proto/"].some((prefix) => path.startsWith(prefix)) ? "0.3.0" : "0.3.1"}"\n`;
  assert.equal(plannedPublicReleaseVersion({ readManifest }), "0.3.0");
  assert.deepEqual(publicManifestVersions({ readManifest }), ["0.3.0", "0.3.0", "0.3.0", "0.3.1", "0.3.1"]);
});
