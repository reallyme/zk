// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PlatformSizeContractError,
  readPlatformSizeSources,
  validatePlatformSizeContract,
} from "./check-platform-size-contract.mjs";

const sources = readPlatformSizeSources(new URL("../", import.meta.url));

test("pins the reviewed Rust, Swift, Kotlin, and JNI size relationship", () => {
  assert.doesNotThrow(() => validatePlatformSizeContract(sources));
});

test("rejects a mobile witness cap widened independently of Rust", () => {
  const changed = {
    ...sources,
    swift: sources.swift.replace("public static let maximum = 4 * 1_024 * 1_024", "public static let maximum = 8 * 1_024 * 1_024"),
  };
  assert.throws(
    () => validatePlatformSizeContract(changed),
    (error) => error instanceof PlatformSizeContractError && error.code === "SWIFT_WITNESS_LIMIT_CHANGED",
  );
});

test("rejects a JNI envelope widened independently of the codec", () => {
  const changed = {
    ...sources,
    jni: sources.jni.replace("(256 * 1024 * 4) +", "(512 * 1024 * 4) +"),
  };
  assert.throws(
    () => validatePlatformSizeContract(changed),
    (error) => error instanceof PlatformSizeContractError && error.code === "JNI_OPERATION_LIMIT_CHANGED",
  );
});
