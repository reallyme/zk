// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const sourcePaths = Object.freeze({
  rustApi: "crates/api/src/proof.rs",
  rustOperation: "crates/proto-codec/src/operation.rs",
  swift: "packages/swift/Sources/ReallyMeZK/Core/ZKModels.swift",
  kotlin: "packages/kotlin/src/main/kotlin/me/really/zk/ReallyMeZkProvider.kt",
  kotlinBridge: "packages/kotlin/src/main/kotlin/me/really/zk/ReallyMeZkNativeBridge.kt",
  jni: "packages/kotlin/native/jni/reallyme_zk_platform_jni.cc",
});

export class PlatformSizeContractError extends Error {
  constructor(code) {
    super(code);
    this.name = "PlatformSizeContractError";
    this.code = code;
  }
}

function canonicalExpression(expression) {
  return expression.replace(/[\s_]/gu, "");
}

function requireDeclaration(source, pattern, expected, code) {
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1 || canonicalExpression(matches[0][1]) !== expected) {
    throw new PlatformSizeContractError(code);
  }
}

export function validatePlatformSizeContract(sources) {
  requireDeclaration(
    sources.rustApi,
    /pub const MAX_PROOF_BYTES: usize = ([^;]+);/gu,
    "256*1024",
    "RUST_PROOF_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.rustApi,
    /pub const MAX_WITNESS_BYTES: usize = ([^;]+);/gu,
    "4*1024*1024",
    "RUST_WITNESS_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.rustOperation,
    /const ZK_CLAIM_PROOF_BUNDLE_STAGE_COUNT: usize = ([^;]+);/gu,
    "4",
    "RUST_STAGE_COUNT_CHANGED",
  );
  requireDeclaration(
    sources.rustOperation,
    /const ZK_PROTO_ENVELOPE_OVERHEAD_BYTES: usize = ([^;]+);/gu,
    "3*1024*1024",
    "RUST_ENVELOPE_OVERHEAD_CHANGED",
  );
  requireDeclaration(
    sources.rustOperation,
    /pub const MAX_ZK_PROTO_OPERATION_BYTES: usize = ([^;]+);/gu,
    "(MAXPROOFBYTES*ZKCLAIMPROOFBUNDLESTAGECOUNT)+(MAXWITNESSBYTES*ZKCLAIMPROOFBUNDLESTAGECOUNT)+ZKPROTOENVELOPEOVERHEADBYTES",
    "RUST_OPERATION_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.swift,
    /public struct ZKWitnessByteCount:[\s\S]*?public static let maximum = ([^\r\n]+)/gu,
    "4*1024*1024",
    "SWIFT_WITNESS_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.kotlin,
    /private const val MAX_WITNESS_BYTES = ([^\r\n]+)/gu,
    "4*1024*1024",
    "KOTLIN_WITNESS_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.kotlinBridge,
    /private const val MAX_PROVIDER_OPERATION_RESPONSE_BYTES = ([^\r\n]+)/gu,
    "4*1024*1024",
    "KOTLIN_RESPONSE_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.jni,
    /constexpr jsize kReallyMeMaxNativeOutputBytes = ([^;]+);/gu,
    "4*1024*1024",
    "JNI_OUTPUT_LIMIT_CHANGED",
  );
  requireDeclaration(
    sources.jni,
    /constexpr jsize kReallyMeMaxProviderOperationBytes\s*=\s*([^;]+);/gu,
    "(256*1024*4)+(4*1024*1024*4)+(3*1024*1024)",
    "JNI_OPERATION_LIMIT_CHANGED",
  );
}

export function readPlatformSizeSources(repoRoot) {
  return Object.fromEntries(
    Object.entries(sourcePaths).map(([key, path]) => [key, readFileSync(new URL(path, repoRoot), "utf8")]),
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const repoRoot = new URL("../", import.meta.url);
  try {
    validatePlatformSizeContract(readPlatformSizeSources(repoRoot));
    process.stdout.write("platform size contract passed\n");
  } catch (error) {
    if (error instanceof PlatformSizeContractError) {
      process.stderr.write(`platform size contract failed: ${error.code}\n`);
      process.exitCode = 1;
    } else {
      throw error;
    }
  }
}
