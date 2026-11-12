// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { PUBLIC_CRATE_NAMES } from "./public-crates.mjs";

import { Buffer } from "node:buffer";

const MAX_INVENTORY_BYTES = 1_048_576;
const MAX_INVENTORY_FILES = 4_096;
const MAX_PACKAGE_PATH_BYTES = 512;
const MAX_PACKAGE_NAME_BYTES = 128;
const PACKAGE_PATH_PATTERN = /^[A-Za-z0-9._/-]+$/u;
const FORBIDDEN_PACKAGE_ROOTS = Object.freeze([".git", "gen", "packages", "target"]);
const PUBLIC_PACKAGES = new Set(PUBLIC_CRATE_NAMES);
// These suites use repository fixtures or unpublished native implementations.
export const REPOSITORY_TEST_PACKAGES = Object.freeze([
  "reallyme-zk-proto-codec", "reallyme-zk-backend-bb",
]);
const REQUIRED_PACKAGE_FILES = new Map([
  ["reallyme-zk-backend-bb", Object.freeze([
    "build.rs", "toolchain-lock.json", "native/reallyme_bbapi_shim.cc", "native/reallyme_bbapi_shim.h",
  ])],
  [
    "reallyme-zk-proto",
    Object.freeze([
      "proto/reallyme/zk/v1/capabilities.proto",
      "proto/reallyme/zk/v1/manifest.proto",
      "proto/reallyme/zk/v1/zk_service.proto",
      "tests/fixtures/protobuf/artifact-operation.pb.hex",
      "tests/fixtures/protobuf/backend-unavailable-response.pb.hex",
      "tests/fixtures/protojson/artifact-operation.json",
      "tests/fixtures/protojson/backend-unavailable-response.json",
      "tests/fixtures/protojson/malicious-duplicate-field.json",
      "tests/fixtures/protojson/malicious-unknown-enum.json",
    ]),
  ],
]);

/** Stable, privacy-safe package inventory rejection. */
export class PackageInventoryError extends Error {
  constructor(code) {
    super(code);
    this.name = "PackageInventoryError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new PackageInventoryError(code);
};

export const validatePackageInventory = (packageName, output) => {
  if (
    typeof packageName !== "string" ||
    packageName.length === 0 ||
    Buffer.byteLength(packageName, "utf8") > MAX_PACKAGE_NAME_BYTES ||
    typeof output !== "string" ||
    output.length === 0 ||
    Buffer.byteLength(output, "utf8") > MAX_INVENTORY_BYTES
  ) {
    fail("invalid-package-inventory-input");
  }

  const inventoryBody = output.endsWith("\n") ? output.slice(0, -1) : output;
  const files = inventoryBody
    .split("\n")
    .map((path) => (path.endsWith("\r") ? path.slice(0, -1) : path));
  if (files.length === 0 || files.length > MAX_INVENTORY_FILES) {
    fail("invalid-package-inventory-count");
  }
  const uniqueFiles = new Set(files);
  if (uniqueFiles.size !== files.length) {
    fail("duplicate-package-inventory-path");
  }

  for (const path of files) {
    const components = path.split("/");
    if (
      Buffer.byteLength(path, "utf8") > MAX_PACKAGE_PATH_BYTES ||
      !PACKAGE_PATH_PATTERN.test(path) ||
      path.startsWith("/") ||
      path.includes("//") ||
      path.includes("\\") ||
      components.some((component) => component === "" || component === "." || component === "..")
    ) {
      fail("invalid-package-inventory-path");
    }
    if (FORBIDDEN_PACKAGE_ROOTS.includes(components[0])) {
      fail("forbidden-package-inventory-path");
    }
  }

  const requiredFiles = REQUIRED_PACKAGE_FILES.get(packageName) ?? [];
  if (REPOSITORY_TEST_PACKAGES.includes(packageName) && files.some((path) => path.startsWith("tests/"))) {
    fail("repository-only-tests-in-package");
  }
  if (
    PUBLIC_PACKAGES.has(packageName) &&
    (!uniqueFiles.has("LICENSE-MIT") || !uniqueFiles.has("LICENSE-APACHE"))
  ) {
    fail("required-package-license-missing");
  }
  for (const requiredFile of requiredFiles) {
    if (!uniqueFiles.has(requiredFile)) {
      fail("required-package-file-missing");
    }
  }

  if (packageName === "reallyme-zk-proto") {
    const protoFiles = files.filter((path) => path.endsWith(".proto"));
    const requiredProtoFiles = requiredFiles.filter((path) => path.endsWith(".proto"));
    if (
      protoFiles.length !== requiredProtoFiles.length ||
      requiredProtoFiles.some((path) => !protoFiles.includes(path))
    ) {
      fail("unexpected-package-schema");
    }

    const fixtureFiles = files.filter((path) => path.startsWith("tests/fixtures/"));
    const requiredFixtureFiles = requiredFiles.filter((path) =>
      path.startsWith("tests/fixtures/"),
    );
    if (
      fixtureFiles.length !== requiredFixtureFiles.length ||
      requiredFixtureFiles.some((path) => !fixtureFiles.includes(path))
    ) {
      fail("unexpected-package-fixture");
    }
  }

  return Object.freeze([...files]);
};
