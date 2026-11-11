// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { firstGenericKotlinError } from "./check-kotlin-typed-errors.mjs";

const providerPath = "packages/kotlin/src/main/kotlin/me/really/zk/ReallyMeZkProvider.kt";

test("permits only the reviewed typed provider exception superclass", () => {
  const source = `private typealias ZkProviderExceptionBase = Exception
public class ReallyMeZkProviderException(
    public val reason: ZkProviderFailureReason,
  ) : ZkProviderExceptionBase("fixed, non-sensitive message")`;
  assert.equal(firstGenericKotlinError(source, providerPath), null);
  assert.equal(firstGenericKotlinError(source, "packages/kotlin/src/main/kotlin/Other.kt"), 1);
});

test("rejects generic thrown and assigned exceptions", () => {
  const alias = "private typealias ZkProviderExceptionBase = Exception\n";
  assert.equal(firstGenericKotlinError(`${alias}fun fail() { throw Exception(\"secret\") }`, providerPath), 2);
  assert.equal(firstGenericKotlinError(`${alias}val failure = RuntimeException(\"secret\")`, providerPath), 2);
  assert.equal(firstGenericKotlinError(`${alias}class Other : ZkProviderExceptionBase()`, providerPath), 2);
  assert.equal(firstGenericKotlinError("class Other : Exception()", "packages/kotlin/src/main/kotlin/Other.kt"), 1);
  assert.equal(firstGenericKotlinError("typealias HiddenError = Exception", "packages/kotlin/src/main/kotlin/Other.kt"), 1);
  assert.equal(firstGenericKotlinError("import kotlin.Exception as HiddenError", "packages/kotlin/src/main/kotlin/Other.kt"), 1);
});

test("ignores comments and quoted text, including nested comments", () => {
  const source = `// throw Exception("ignored")
/* outer /* throw RuntimeException() */ still ignored */
val text = "Exception(ignored)"
val raw = """IllegalStateException(ignored)"""
fun safe() = Unit`;
  assert.equal(firstGenericKotlinError(source, "packages/kotlin/src/main/kotlin/Other.kt"), null);
});
