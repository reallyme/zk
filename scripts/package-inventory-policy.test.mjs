#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  PackageInventoryError,
  validatePackageInventory,
} from "./package-inventory-policy.mjs";

const canonicalProtoInventory = [
  "Cargo.toml",
  "LICENSE-MIT",
  "LICENSE-APACHE",
  "proto/reallyme/zk/v1/capabilities.proto",
  "proto/reallyme/zk/v1/manifest.proto",
  "proto/reallyme/zk/v1/zk_service.proto",
  "tests/fixtures/protobuf/artifact-operation.pb.hex",
  "tests/fixtures/protobuf/backend-unavailable-response.pb.hex",
  "tests/fixtures/protojson/artifact-operation.json",
  "tests/fixtures/protojson/backend-unavailable-response.json",
  "tests/fixtures/protojson/malicious-duplicate-field.json",
  "tests/fixtures/protojson/malicious-unknown-enum.json",
].join("\n");

const hasCode = (code) => (error) =>
  error instanceof PackageInventoryError && error.code === code;

test("canonical proto schemas and fixtures are admitted", () => {
  const files = validatePackageInventory("reallyme-zk-proto", canonicalProtoInventory);
  assert.equal(files.length, 12);
  assert.ok(Object.isFrozen(files));
});

test("repository-only codec and native test harnesses cannot enter public archives", () => {
  for (const packageName of ["reallyme-zk-proto-codec", "reallyme-zk-backend-bb"]) {
    assert.throws(
      () => validatePackageInventory(packageName, "Cargo.toml\nLICENSE-MIT\nLICENSE-APACHE\ntests/bindings.rs"),
      hasCode("repository-only-tests-in-package"),
    );
  }
});

test("every public crate carries both declared license texts", () => {
  for (const packageName of ["reallyme-zk-api", "reallyme-zk-artifacts", "reallyme-zk-proto", "reallyme-zk-proto-codec", "reallyme-zk-backend-bb"]) {
    assert.throws(
      () => validatePackageInventory(packageName, "Cargo.toml\nLICENSE-MIT"),
      hasCode("required-package-license-missing"),
    );
    assert.throws(
      () => validatePackageInventory(packageName, "Cargo.toml\nLICENSE-APACHE"),
      hasCode("required-package-license-missing"),
    );
  }
});

test("duplicate, traversal, and forbidden paths fail closed", () => {
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "Cargo.toml\nCargo.toml"),
    hasCode("duplicate-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "../Cargo.toml"),
    hasCode("invalid-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "packages/ts/package.json"),
    hasCode("forbidden-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "target"),
    hasCode("forbidden-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", ".git/config"),
    hasCode("forbidden-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", " Cargo.toml"),
    hasCode("invalid-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "Cargo.toml\n\nsrc/lib.rs"),
    hasCode("invalid-package-inventory-path"),
  );
});

test("missing fixtures, extra schemas, and extra fixtures fail closed", () => {
  assert.throws(
    () => validatePackageInventory(
      "reallyme-zk-proto",
      canonicalProtoInventory.replace("tests/fixtures/protojson/malicious-unknown-enum.json", ""),
    ),
    hasCode("required-package-file-missing"),
  );
  assert.throws(
    () => validatePackageInventory(
      "reallyme-zk-proto",
      `${canonicalProtoInventory}\nproto/reallyme/zk/v1/parallel.proto`,
    ),
    hasCode("unexpected-package-schema"),
  );
  assert.throws(
    () => validatePackageInventory(
      "reallyme-zk-proto",
      `${canonicalProtoInventory}\ntests/fixtures/protojson/unreviewed.json`,
    ),
    hasCode("unexpected-package-fixture"),
  );
});

test("the imported capability schema must ship in the public archive", () => {
  assert.throws(
    () => validatePackageInventory(
      "reallyme-zk-proto",
      canonicalProtoInventory.split("\n")
        .filter((path) => path !== "proto/reallyme/zk/v1/capabilities.proto").join("\n"),
    ),
    hasCode("required-package-file-missing"),
  );
});

test("invalid types, paths, counts, and oversized inventories fail closed", () => {
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", null),
    hasCode("invalid-package-inventory-input"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "a".repeat(1_048_577)),
    hasCode("invalid-package-inventory-input"),
  );
  assert.throws(
    () => validatePackageInventory("reallyme-zk-api", "a".repeat(513)),
    hasCode("invalid-package-inventory-path"),
  );
  assert.throws(
    () => validatePackageInventory(
      "reallyme-zk-api",
      Array.from({ length: 4_097 }, (_, index) => `src/${index}.rs`).join("\n"),
    ),
    hasCode("invalid-package-inventory-count"),
  );
});
