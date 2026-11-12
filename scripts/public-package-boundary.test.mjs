// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { PUBLIC_CRATE_NAMES } from "./public-crates.mjs";
import { PublicPackageBoundaryError, validatePublicPackageBoundary } from "./public-package-boundary.mjs";

const privateNames = ["reallyme-zk-noir-witness-core", "reallyme-zk-platform-ffi"];
const fixture = (name, kind, optional = false) => [
  { name: "reallyme-zk-backend-bb", dependencies: [{ name, source: null, path: "../implementation", kind, optional, req: "*" }] },
  ...privateNames.map((privateName) => ({ name: privateName, dependencies: [] })),
];

test("unpublished implementations cannot enter public runtime or build features", () => {
  for (const name of privateNames) {
    for (const kind of [null, "build"]) {
      for (const optional of [false, true]) {
        assert.throws(() => validatePublicPackageBoundary(fixture(name, kind, optional)),
          { name: "PublicPackageBoundaryError", code: "unpublished-runtime-dependency" });
      }
    }
    validatePublicPackageBoundary(fixture(name, "dev"));
  }
  assert.throws(() => validatePublicPackageBoundary(null), PublicPackageBoundaryError);
  for (const malformed of [[null], [{ name: "reallyme-zk-api", dependencies: [null] }],
    [{ name: "reallyme-zk-api", dependencies: [{ name: "x", kind: "unexpected", source: null }] }]]) {
    assert.throws(() => validatePublicPackageBoundary(malformed), PublicPackageBoundaryError);
  }
  const versionedPrivate = fixture("reallyme-zk-noir-witness-core", "dev");
  versionedPrivate[0].dependencies[0].req = "^0.1.0";
  assert.throws(() => validatePublicPackageBoundary(versionedPrivate),
    { name: "PublicPackageBoundaryError", code: "private-development-dependency-must-be-omitted" });
  assert.throws(() => validatePublicPackageBoundary([{ name: "reallyme-zk-api", dependencies: [
    { name: "unpublished-upstream", kind: null, source: "git+https://example.invalid/source" },
  ] }]), { name: "PublicPackageBoundaryError", code: "git-runtime-dependency" });
});

test("real package metadata keeps implementation crates private and native-only", () => {
  const result = spawnSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const metadata = JSON.parse(result.stdout);
  validatePublicPackageBoundary(metadata.packages);
  const publicNames = metadata.packages.filter((pkg) => pkg.publish === null || pkg.publish.length > 0).map((pkg) => pkg.name);
  assert.deepEqual(publicNames.sort(), [...PUBLIC_CRATE_NAMES].sort());
  for (const name of privateNames) {
    const pkg = metadata.packages.find((candidate) => candidate.name === name);
    assert.ok(pkg);
    assert.deepEqual(pkg.publish, []);
  }
  const ffi = metadata.packages.find((pkg) => pkg.name === "reallyme-zk-platform-ffi");
  assert.deepEqual(ffi.features.default, []);
  for (const name of ["reallyme-zk-backend-bb", "reallyme-zk-noir-witness-core"]) {
    assert.equal(ffi.dependencies.find((dependency) => dependency.name === name).optional, true);
    assert.ok(ffi.features.native.includes(`dep:${name}`));
  }
});

test("packaged native admission carries the canonical toolchain lock", () => {
  assert.deepEqual(readFileSync("crates/backend-bb/toolchain-lock.json"), readFileSync("circuits/toolchain-lock.json"));
  for (const name of ["build.rs", "native/reallyme_bbapi_shim.h", "native/reallyme_bbapi_shim.cc", "toolchain-lock.json"]) {
    assert.ok(readFileSync("crates/backend-bb/Cargo.toml", "utf8").includes(`"/${name}"`) || name.startsWith("native/"));
  }
});
