#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { hardenGeneratedProto } from "./proto-hardening/core.mjs";
import { ZK_SCALAR_FIELD_CLASSIFICATIONS } from "./proto-hardening/zk-scalar-policy.mjs";

const supportedArguments = new Set(["--check-idempotent"]);
const suppliedArguments = new Set();

function fail(message) {
  console.error(`generated ZK proto hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const generatedRoot = resolve(root, "crates/proto/src/generated/buffa");
const generatedStem = "reallyme.zk.v1.manifest";

hardenGeneratedProto({
  binaryOnlyJsonMessages: ["ZkWitness"],
  checkIdempotent: suppliedArguments.has("--check-idempotent"),
  failurePrefix: "generated ZK proto hardening failed",
  protoPath: resolve(
    root,
    "crates/proto/proto/reallyme/zk/v1/manifest.proto",
  ),
  generatedPath: resolve(generatedRoot, `${generatedStem}.rs`),
  modulePath: resolve(generatedRoot, "reallyme.zk.v1.mod.rs"),
  oneofPath: resolve(generatedRoot, `${generatedStem}.__oneof.rs`),
  viewPath: resolve(generatedRoot, `${generatedStem}.__view.rs`),
  viewOneofPath: resolve(generatedRoot, `${generatedStem}.__view_oneof.rs`),
  scalarFieldClassifications: ZK_SCALAR_FIELD_CLASSIFICATIONS,
});

// Capability metadata carries no scalar secrets, but its unknown-field owner
// follows the same deterministic cleanup policy as the rest of the protocol.
hardenGeneratedProto({
  // Both files are included in one generated package module; manifest owns
  // the shared cleanup helpers so their type and function definitions are unique.
  sharedHelpersInModule: true,
  binaryOnlyJsonMessages: [],
  checkIdempotent: suppliedArguments.has("--check-idempotent"),
  failurePrefix: "generated ZK capability hardening failed",
  protoPath: resolve(root, "crates/proto/proto/reallyme/zk/v1/capabilities.proto"),
  generatedPath: resolve(generatedRoot, "reallyme.zk.v1.capabilities.rs"),
  modulePath: resolve(generatedRoot, "reallyme.zk.v1.mod.rs"),
  oneofPath: resolve(generatedRoot, "reallyme.zk.v1.capabilities.__oneof.rs"),
  viewPath: resolve(generatedRoot, "reallyme.zk.v1.capabilities.__view.rs"),
  viewOneofPath: resolve(generatedRoot, "reallyme.zk.v1.capabilities.__view_oneof.rs"),
  scalarFieldClassifications: [],
});
