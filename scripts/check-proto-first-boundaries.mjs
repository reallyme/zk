#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

function read(path) {
  return readFileSync(resolve(repoRoot, path), "utf8");
}

function requireText(path, needle) {
  if (!read(path).includes(needle)) {
    failures.push(`${path}: missing required proto-first marker ${JSON.stringify(needle)}`);
  }
}

function rejectText(path, needle) {
  if (read(path).includes(needle)) {
    failures.push(`${path}: forbidden proto-first boundary text ${JSON.stringify(needle)}`);
  }
}

function cargoDependencies(path) {
  const manifest = read(path);
  const start = manifest.indexOf("[dependencies]\n");
  if (start === -1) {
    failures.push(`${path}: missing production dependency section`);
    return "";
  }
  const body = manifest.slice(start + "[dependencies]\n".length);
  const nextSection = body.search(/^\[/mu);
  return nextSection === -1 ? body : body.slice(0, nextSection);
}

function requireExactDirectoryFiles(directory, expectedFiles) {
  const absolute = resolve(repoRoot, directory);
  const entries = readdirSync(absolute, { withFileTypes: true });
  const actualFiles = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
  const unexpectedEntry = entries.some((entry) => !entry.isFile());
  const expected = [...expectedFiles].sort();
  if (
    unexpectedEntry ||
    actualFiles.length !== expected.length ||
    expected.some((file, index) => actualFiles[index] !== file)
  ) {
    failures.push(`${directory}: directory inventory differs from the reviewed contract`);
  }
}

function requireExactDirectoryEntries(directory, expectedEntries) {
  const absolute = resolve(repoRoot, directory);
  const actual = readdirSync(absolute)
    .filter((entry) => entry !== ".DS_Store")
    .sort();
  const expected = [...expectedEntries].sort();
  if (
    actual.length !== expected.length ||
    expected.some((entry, index) => actual[index] !== entry)
  ) {
    failures.push(`${directory}: directory layout differs from the reviewed architecture`);
  }
}

function rustFiles(directory) {
  const absolute = resolve(repoRoot, directory);
  const files = [];
  for (const entry of readdirSync(absolute)) {
    const path = resolve(absolute, entry);
    const metadata = statSync(path);
    if (metadata.isDirectory()) {
      files.push(...rustFiles(`${directory}/${entry}`));
    } else if (entry.endsWith(".rs")) {
      files.push(`${directory}/${entry}`);
    }
  }
  return files;
}

function productionRustSource(path) {
  const source = read(path);
  const testModule = source.indexOf("#[cfg(test)]");
  return testModule === -1 ? source : source.slice(0, testModule);
}

function rejectDirectJsonCalls(paths, allowlist) {
  for (const path of paths) {
    if (allowlist.has(path)) {
      continue;
    }
    const source = productionRustSource(path);
    for (const needle of ["serde_json::from_", "serde_json::to_", "serde_json::json!"]) {
      if (source.includes(needle)) {
        failures.push(`${path}: direct JSON boundary call ${JSON.stringify(needle)}`);
      }
    }
  }
}

for (const path of ["Cargo.toml", "crates/proto/Cargo.toml", "crates/proto-codec/Cargo.toml"]) {
  rejectText(path, "connectrpc");
}
requireExactDirectoryEntries("crates", [
  "api",
  "artifact-package",
  "artifacts",
  "backend-bb",
  "cli",
  "demo-fixture-generator",
  "noir-witness-core",
  "platform-ffi",
  "proto",
  "proto-codec",
  "release-assembly",
  "release-process",
  "root-status-authority",
]);
requireExactDirectoryEntries("crates/proto", [
  "Cargo.toml",
  "LICENSE-APACHE",
  "LICENSE-MIT",
  "README.md",
  "baselines",
  "proto",
  "src",
  "tests",
]);

for (const dependency of [
  "reallyme-zk-api",
  "reallyme-zk-artifacts",
  "reallyme-zk-backend-bb",
  "reallyme-zk-proto-codec",
]) {
  rejectText("crates/proto/Cargo.toml", dependency);
}
for (const dependency of [
  "buffa",
  "serde_json",
  "reallyme-zk-artifacts",
  "reallyme-zk-backend-bb",
  "reallyme-zk-proto",
  "reallyme-zk-proto-codec",
]) {
  rejectText("crates/api/Cargo.toml", dependency);
}
requireText("crates/proto-codec/Cargo.toml", "reallyme-zk-api =");
requireText("crates/proto-codec/Cargo.toml", "reallyme-zk-artifacts =");
requireText("crates/proto-codec/Cargo.toml", "reallyme-zk-proto =");
rejectText("crates/proto-codec/Cargo.toml", "reallyme-zk-backend-bb");
requireText("crates/backend-bb/Cargo.toml", "reallyme-zk-api =");
requireText("crates/backend-bb/Cargo.toml", "reallyme-zk-artifacts =");
for (const dependency of ["reallyme-zk-proto", "reallyme-zk-proto-codec"]) {
  if (cargoDependencies("crates/backend-bb/Cargo.toml").includes(dependency)) {
    failures.push(`crates/backend-bb/Cargo.toml: production backend dependency on ${dependency}`);
  }
}
requireText("crates/platform-ffi/Cargo.toml", "reallyme-zk-backend-bb =");
requireText("crates/platform-ffi/Cargo.toml", "reallyme-zk-proto-codec =");
requireText("crates/platform-ffi/src/lib.rs", "typed platform ABI adapter");
rejectText("buf.gen.yaml", "protoc-gen-connect");
{
  const allowedSwiftGeneratedTarget =
    "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated";
  const bufGenWithoutAllowedSwiftTarget = read("buf.gen.yaml").replaceAll(
    allowedSwiftGeneratedTarget,
    "",
  );
  if (bufGenWithoutAllowedSwiftTarget.includes("packages/")) {
    failures.push("buf.gen.yaml: forbidden package generator target outside reviewed Swift proto output");
  }
}
requireText("buf.gen.yaml", "buf.build/apple/swift:v1.39.0");
requireText("buf.gen.yaml", "buf.build/protocolbuffers/java:v35.1");
requireText("buf.gen.yaml", "buf.build/protocolbuffers/kotlin:v35.1");
requireText("buf.gen.yaml", "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated");
requireText("buf.gen.yaml", "gen/java/zk");
requireText("buf.gen.yaml", "gen/kotlin/zk");
rejectText(
  "crates/proto/proto/reallyme/zk/v1/manifest.proto",
  "service ZkProviderService",
);
requireText(
  "crates/proto/proto/reallyme/zk/v1/manifest.proto",
  "enum ZkWitnessEncoding",
);
requireText(
  "crates/proto/proto/reallyme/zk/v1/manifest.proto",
  "ZkWitnessEncoding encoding = 3;",
);
requireText(
  "crates/proto/proto/reallyme/zk/v1/zk_service.proto",
  "service ZkProviderService",
);
requireText(
  "crates/proto/proto/reallyme/zk/v1/zk_service.proto",
  "rpc ZkProviderOperation(ZkProviderOperationRequest) returns (ZkProviderOperationResponse);",
);
requireExactDirectoryFiles("crates/proto/proto/reallyme/zk/v1", [
  "capabilities.proto",
  "manifest.proto",
  "zk_service.proto",
]);
requireText("scripts/harden-zk-generated.mjs", 'from "./proto-hardening/core.mjs"');
requireText(
  "scripts/harden-zk-generated.mjs",
  'binaryOnlyJsonMessages: ["ZkWitness"]',
);
requireText("scripts/proto-hardening/core.mjs", "export function hardenGeneratedProto");
requireText("scripts/proto-hardening/core.mjs", "parseProtoContracts");
requireText("scripts/proto-hardening/core.mjs", "messageReferences");
requireText("scripts/proto-hardening/core.mjs", "transitivelySensitiveMessages");
requireText("scripts/proto-hardening/core.mjs", "hardenSensitiveByteSerializers");
requireText("scripts/proto-hardening/core.mjs", "hardenUnknownFieldOwners");
requireText("scripts/proto-hardening/core.mjs", "ReallyMeZeroizingUnknownFields");
requireText("scripts/proto-hardening/core.mjs", "hardenBinaryOnlyJsonMessages");
requireText("scripts/proto-hardening/core.mjs", "__reallyme_reject_binary_only_bytes");
requireText("scripts/proto-hardening/core.mjs", "zeroizingSerializationHelper");
requireText("scripts/proto-hardening/core.mjs", "::reallyme_codec::base64::bytes_to_base64");
requireText("scripts/proto-hardening/core.mjs", "decoded.as_mut_slice().zeroize()");
requireText(
  "scripts/proto-hardening/zk-scalar-policy.mjs",
  "ZK_SCALAR_FIELD_CLASSIFICATIONS",
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.rs",
  'serialize_with = "__reallyme_reject_binary_only_bytes"',
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.rs",
  "binary-only protobuf transport",
);
requireText(
  "crates/proto/tests/generated_tests.rs",
  "fn witness_protojson_is_binary_only()",
);
requireText(
  "crates/proto/tests/generated_tests/sensitive_bindings.rs",
  "fn sensitive_borrowed_views_are_binary_only()",
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.__view.rs",
  "JSON serialization is disabled for this binary-only view",
);
for (const ownedView of [
  "DigestOwnedView",
  "ZkArtifactManifestOwnedView",
  "ZkPublicInputsOwnedView",
  "NamedPublicInputOwnedView",
  "ZkProofPackageOwnedView",
  "ZkClaimProofBundleStageProofPackageOwnedView",
  "ZkClaimProofBundleOwnedView",
  "ZkSessionBindingOwnedView",
  "ZkExpectedStageProofShapeOwnedView",
  "ZkExpectedClaimProofBundleProofShapeOwnedView",
  "ZkWitnessOwnedView",
  "ZkClaimProofBundleWitnessOwnedView",
  "ZkClaimProofBundleProveOperationOwnedView",
  "ZkClaimProofBundleVerifyOperationOwnedView",
  "ZkStageProveOperationOwnedView",
  "ZkStageVerifyOperationOwnedView",
  "ZkProviderOperationRequestOwnedView",
  "ZkProviderOperationResultOwnedView",
  "ZkProviderOperationResponseOwnedView",
  "ZkProvingVectorOwnedView",
  "ZkProvingVectorSetOwnedView",
  "ZkReleaseArtifactPinOwnedView",
  "ZkVerificationVectorOwnedView",
  "ZkVerificationVectorSetOwnedView",
  "ZkReleaseVerificationVectorPinOwnedView",
  "ZkReleaseIndexOwnedView",
]) {
  rejectText(
    "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.__view.rs",
    ownedView,
  );
  rejectText("crates/proto/src/generated/buffa/reallyme.zk.v1.mod.rs", ownedView);
}
rejectText(
  "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.__view.rs",
  "OwnedView",
);
rejectText("crates/proto/src/generated/buffa/reallyme.zk.v1.mod.rs", "OwnedView");

for (const sdkOwnedPath of [
  "crates/wasm",
  "crates/proto/src/generated/connect",
]) {
  if (existsSync(resolve(repoRoot, sdkOwnedPath))) {
    failures.push(`${sdkOwnedPath}: platform or Connect output must remain outside ZK`);
  }
}
if (existsSync(resolve(repoRoot, "packages"))) {
  requireExactDirectoryEntries("packages", ["bbjs-provider", "kotlin", "swift"]);
  requireText(
    "PACKAGING.md",
    "ReallyMe ZK provides Rust protocol contracts, native Swift and Kotlin provider",
  );
  requireText("PACKAGING.md", "`packages/bbjs-provider`");
  requireText("docs/platform-binding-contract.md", "`packages/swift`");
  requireText("docs/platform-binding-contract.md", "`packages/kotlin`");
  requireText("docs/platform-binding-contract.md", "`packages/bbjs-provider`");
}

for (const directory of [
  "crates/api/src",
  "crates/artifact-package/src",
  "crates/artifacts/src",
  "crates/backend-bb/src",
  "crates/cli/src",
  "conformance/src",
  "crates/proto-codec/src",
  "crates/release-assembly/src",
  "crates/release-process/src",
]) {
  rejectDirectJsonCalls(
    rustFiles(directory),
    new Set([
      "crates/backend-bb/src/bbapi_abi/compiled_program_json.rs",
      "crates/proto-codec/src/protojson.rs",
      "crates/release-process/src/artifact_compatibility.rs",
    ]),
  );
}
requireText(
  "crates/backend-bb/src/bbapi_abi/compiled_program_json.rs",
  "let container: CompiledProgramContainer<'_> = serde_json::from_slice(program_json)",
);
requireText(
  "crates/backend-bb/src/bbapi_abi/compiled_program_json.rs",
  "provider operation boundary",
);
rejectText("crates/backend-bb/src/bbapi_abi/command.rs", "serde_json::from_");
rejectText("crates/backend-bb/src/bbapi_abi/command.rs", "serde_json::to_");
rejectText("crates/backend-bb/src/bbapi_abi/command.rs", "serde_json::json!");

requireText("crates/proto-codec/src/protojson.rs", "MAX_ZK_PROTO_JSON_BYTES");
requireText("crates/proto-codec/src/protojson.rs", "BoundedJsonWriter");
requireText("crates/proto-codec/src/protojson.rs", "Zeroizing<String>");
requireText("crates/proto-codec/src/protojson.rs", "ZkProtoJson");
requireText("crates/proto-codec/src/operation.rs", "zk_proto_from_json");
requireText("crates/proto-codec/src/operation.rs", "encode_canonical_operation");
requireText("crates/proto-codec/src/operation.rs", "Zeroizing<Vec<u8>>");
requireText(
  "crates/proto-codec/src/operation.rs",
  "ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1",
);
requireText(
  "crates/proto-codec/tests/operation_tests/validation_failure_tests.rs",
  "fn unspecified_witness_encoding_fails_closed()",
);
requireText(
  "crates/proto-codec/tests/operation_tests/validation_failure_tests.rs",
  "fn unknown_witness_encoding_fails_closed()",
);
requireText("crates/api/src/proof.rs", "pub enum ZkWitnessEncoding");
requireText(
  "crates/api/src/proof.rs",
  "try_from_noir_witness_stack_v1_zeroizing",
);
requireText("crates/proto-codec/src/result.rs", "encode_canonical_response");
requireText("crates/proto-codec/src/result.rs", "Zeroizing<Vec<u8>>");
rejectText("crates/proto-codec/src/operation.rs", "request.encode_to_vec()");
rejectText("crates/proto-codec/src/result.rs", "response.encode_to_vec()");
requireText(
  "crates/proto-codec/src/vector.rs",
  "let mutated = Zeroizing::new(request.encode_to_vec())",
);
requireText(
  "crates/proto-codec/src/verification_vector.rs",
  "let mutated = Zeroizing::new(request.encode_to_vec())",
);
rejectText("crates/proto-codec/src/vector.rs", "let mut canonical = vector_set.encode_to_vec()");
rejectText(
  "crates/proto-codec/src/verification_vector.rs",
  "let mut canonical = vector_set.encode_to_vec()",
);
requireText(
  "crates/proto-codec/src/vector/decoding.rs",
  "let canonical = Zeroizing::new(vector_set.encode_to_vec())",
);
requireText(
  "crates/proto-codec/src/verification_vector/decoding.rs",
  "let canonical = Zeroizing::new(vector_set.encode_to_vec())",
);
requireText("crates/proto-codec/src/protojson.rs", "enforce_operation_request_json_policy");
requireText("crates/proto-codec/src/protojson.rs", "SecretOperationUnsupported");
requireText("crates/proto-codec/src/protojson.rs", "advance_json_cursor");
rejectText("crates/proto-codec/src/protojson.rs", "pb::ZkProvingVectorSet");
rejectText("crates/proto-codec/src/protojson.rs", "saturating_add");
requireText(
  "crates/proto-codec/tests/protojson_fixtures.rs",
  "generic_protojson_cannot_bypass_binary_only_proving_policy",
);
requireText(
  "crates/proto/src/generated/buffa/reallyme.zk.v1.manifest.rs",
  "fn __reallyme_serialize_zeroizing_bytes",
);
requireText(
  "crates/proto/tests/generated_tests/sensitive_bindings.rs",
  "sensitive_protojson_bytes_use_zeroizing_base64_staging",
);
requireText(
  "crates/proto/tests/generated_tests/sensitive_bindings.rs",
  "sensitive_generated_fields_are_redacted_and_zeroized_on_drop",
);
requireText(
  "crates/proto/tests/generated_tests/sensitive_bindings.rs",
  "sensitive_protojson_bytes_reject_malformed_base64",
);
requireText(
  "crates/proto/tests/generated_tests/sensitive_bindings.rs",
  "sensitive_protojson_bytes_preserve_protojson_base64_compatibility",
);
requireText("fuzz/fuzz_targets/protojson_contracts.rs", "ZkProviderOperationRequest");
requireText("fuzz/fuzz_targets/protojson_contracts.rs", "zk_proto_to_json");
requireExactDirectoryFiles("fuzz/corpus/protojson_contracts", [
  "malicious-secret-operation",
  "valid-artifact-request",
  "valid-backend-response",
]);
requireText("fuzz/.gitignore", "!corpus/protojson_contracts/malicious-secret-operation");
requireText(
  "crates/release-process/src/artifact_compatibility.rs",
  "struct CompiledProgramArtifact",
);
requireText(
  "crates/release-process/src/artifact_compatibility.rs",
  "MAX_COMPILED_PROGRAM_ARTIFACT_BYTES",
);
requireText(
  "crates/release-process/src/artifact_compatibility.rs",
  "PINNED_NOIRC_VERSION_PREFIX",
);
requireText(
  "crates/release-process/src/process/tests.rs",
  "compiled_artifact_boundary_rejects_duplicate_and_recursive_fields",
);
requireText(
  "crates/release-process/src/process/tests.rs",
  "compiled_artifact_boundary_rejects_empty_and_oversized_inputs",
);

const protoJsonFixtures = [
  "artifact-operation.json",
  "backend-unavailable-response.json",
  "malicious-duplicate-field.json",
  "malicious-unknown-enum.json",
];
for (const fixture of protoJsonFixtures) {
  const path = `crates/proto/tests/fixtures/protojson/${fixture}`;
  if (!existsSync(resolve(repoRoot, path))) {
    failures.push(`${path}: required generated ProtoJSON fixture is missing`);
  }
}
requireExactDirectoryFiles("crates/proto/tests/fixtures/protojson", protoJsonFixtures);

const protobufFixtures = [
  "artifact-operation.pb.hex",
  "backend-unavailable-response.pb.hex",
];
for (const fixture of protobufFixtures) {
  const path = `crates/proto/tests/fixtures/protobuf/${fixture}`;
  if (!existsSync(resolve(repoRoot, path))) {
    failures.push(`${path}: required protobuf wire fixture is missing`);
  }
}
requireExactDirectoryFiles("crates/proto/tests/fixtures/protobuf", protobufFixtures);
requireText(
  "crates/proto-codec/tests/protojson_fixtures.rs",
  "protobuf_wire_fixtures_match_protojson_contracts",
);
rejectText("docs/platform-binding-contract.md", "identity-sdk");
requireText("docs/platform-binding-contract.md", "canonical `reallyme.zk.v1` messages");
requireText("docs/platform-binding-contract.md", "They must not duplicate");
requireText("docs/platform-binding-contract.md", "tests/fixtures/protobuf");
requireText("docs/platform-binding-contract.md", "tests/fixtures/protojson");

if (failures.length !== 0) {
  console.error("proto-first boundary checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("proto-first boundary checks passed");
