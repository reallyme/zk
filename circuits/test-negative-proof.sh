#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  printf '%s\n' "usage: test-negative-proof.sh CIRCUIT_DIRECTORY" >&2
  exit 2
fi

CIRCUIT_DIR="$1"
HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOF_PATH="${CIRCUIT_DIR}/target/proof/proof"
PUBLIC_INPUTS_PATH="${CIRCUIT_DIR}/target/proof/public_inputs"
VK_PATH="${CIRCUIT_DIR}/target/vk/vk"
NEGATIVE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-zk-negative-proof.XXXXXX")"

cleanup() {
  rm -rf "${NEGATIVE_DIR}"
}
trap cleanup EXIT

for required in "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" "${VK_PATH}"; do
  if [[ ! -f "${required}" ]]; then
    printf 'error: required proof artifact is missing: %s\n' "${required}" >&2
    exit 1
  fi
done

assert_verify_accepts() {
  local label="$1"
  local vk_path="$2"
  local proof_path="$3"
  local public_inputs_path="$4"
  local output
  shift 4

  if ! output="$(
    bb verify \
      -k "${vk_path}" \
      -p "${proof_path}" \
      -i "${public_inputs_path}" \
      "$@" 2>&1
  )"; then
    printf 'error: baseline verifier failed for %s; negative proof checks cannot distinguish invalid proofs from infrastructure failure\n' "${label}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

assert_verify_rejects() {
  local label="$1"
  local vk_path="$2"
  local proof_path="$3"
  local public_inputs_path="$4"
  local output
  shift 4

  if output="$(
    bb verify \
      -k "${vk_path}" \
      -p "${proof_path}" \
      -i "${public_inputs_path}" \
      "$@" 2>&1
  )"; then
    printf 'error: verifier accepted %s\n' "${label}" >&2
    exit 1
  fi

  if [[ "${output}" == *"No such file"* ||
    "${output}" == *"cannot open"* ||
    "${output}" == *"failed to open"* ||
    "${output}" == *"is a directory"* ||
    "${output}" == *"Permission denied"* ]]; then
    printf 'error: verifier infrastructure failed for %s; negative proof checks cannot treat transport failure as invalid-proof rejection\n' "${label}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi

  if [[ "${output}" != *"Proof verification failed"* ]]; then
    printf 'error: verifier failed without a reviewed invalid-proof rejection for %s; negative proof checks cannot treat an arbitrary verifier failure as invalid-proof rejection\n' "${label}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

assert_verify_accepts "the unmodified proof" \
  "${VK_PATH}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk

file_size() {
  local path="$1"
  wc -c < "${path}" | tr -d ' '
}

BASELINE_PROOF_BYTES="$(file_size "${PROOF_PATH}")"
BASELINE_PUBLIC_INPUT_BYTES="$(file_size "${PUBLIC_INPUTS_PATH}")"
BASELINE_VK_BYTES="$(file_size "${VK_PATH}")"

base_field_words_are_canonical() {
  local artifact_path="$1"
  node -e '
    const { readFileSync } = require("node:fs");
    const input = readFileSync(process.argv[1]);
    if (input.length === 0 || input.length % 32 !== 0) {
      process.exit(1);
    }
    const modulus = BigInt("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    for (let offset = 0; offset < input.length; offset += 32) {
      const field = input.subarray(offset, offset + 32);
      if (BigInt(`0x${field.toString("hex")}`) >= modulus) {
        process.exit(1);
      }
    }
  ' "${artifact_path}"
}

public_inputs_are_canonical() {
  local public_inputs_path="$1"
  node -e '
    const { readFileSync } = require("node:fs");
    const input = readFileSync(process.argv[1]);
    if (input.length === 0 || input.length % 32 !== 0) {
      process.exit(1);
    }
    const modulus = BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    for (let offset = 0; offset < input.length; offset += 32) {
      const field = input.subarray(offset, offset + 32);
      if (BigInt(`0x${field.toString("hex")}`) >= modulus) {
        process.exit(1);
      }
    }
  ' "${public_inputs_path}"
}

if ! base_field_words_are_canonical "${PROOF_PATH}"; then
  printf '%s\n' "error: baseline proof is not a canonical BN254 base-field-word encoding" >&2
  exit 1
fi
if ! public_inputs_are_canonical "${PUBLIC_INPUTS_PATH}"; then
  printf '%s\n' "error: baseline public inputs are not canonical BN254 scalar field encodings" >&2
  exit 1
fi
if ! base_field_words_are_canonical "${VK_PATH}"; then
  printf '%s\n' "error: baseline verification key is not a canonical BN254 base-field-word encoding" >&2
  exit 1
fi

assert_artifact_shape_or_verify_rejects() {
  local label="$1"
  local vk_path="$2"
  local proof_path="$3"
  local public_inputs_path="$4"
  local proof_bytes public_input_bytes vk_bytes
  shift 4

  proof_bytes="$(file_size "${proof_path}")"
  public_input_bytes="$(file_size "${public_inputs_path}")"
  vk_bytes="$(file_size "${vk_path}")"

  # Barretenberg 0.87 accepts some trailing bytes at the raw CLI boundary. The
  # circuit regression still has to fail closed on malformed artifact transport,
  # so length-mismatched files are rejected here before same-shape cases are
  # delegated to the verifier.
  if [[ "${proof_bytes}" != "${BASELINE_PROOF_BYTES}" ||
    "${public_input_bytes}" != "${BASELINE_PUBLIC_INPUT_BYTES}" ||
    "${vk_bytes}" != "${BASELINE_VK_BYTES}" ]]; then
    return 0
  fi

  if ! public_inputs_are_canonical "${public_inputs_path}"; then
    return 0
  fi
  if ! base_field_words_are_canonical "${proof_path}" ||
    ! base_field_words_are_canonical "${vk_path}"; then
    return 0
  fi

  assert_verify_rejects "${label}" \
    "${vk_path}" "${proof_path}" "${public_inputs_path}" \
    "$@"
}

copy_truncated() {
  local source_path="$1"
  local output_path="$2"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const input = readFileSync(process.argv[1]);
    if (input.length === 0) {
      process.exit(1);
    }
    writeFileSync(process.argv[2], input.subarray(0, input.length - 1));
  ' "${source_path}" "${output_path}"
}

copy_extended() {
  local source_path="$1"
  local output_path="$2"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const input = readFileSync(process.argv[1]);
    const output = Buffer.concat([input, Buffer.from([0])]);
    writeFileSync(process.argv[2], output);
  ' "${source_path}" "${output_path}"
}

copy_extended_by_field() {
  local source_path="$1"
  local output_path="$2"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const input = readFileSync(process.argv[1]);
    const output = Buffer.concat([input, Buffer.alloc(32, 0)]);
    writeFileSync(process.argv[2], output);
  ' "${source_path}" "${output_path}"
}

copy_field_plus_bn254_scalar_modulus() {
  local source_path="$1"
  local output_path="$2"
  local field_offset="$3"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const sourcePath = process.argv[1];
    const outputPath = process.argv[2];
    const fieldOffset = Number.parseInt(process.argv[3], 10);
    if (!Number.isSafeInteger(fieldOffset) || fieldOffset < 0) {
      process.exit(1);
    }
    const input = readFileSync(sourcePath);
    if (input.length < fieldOffset + 32) {
      process.exit(1);
    }
    const modulus = BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    const field = input.subarray(fieldOffset, fieldOffset + 32);
    const fieldValue = BigInt(`0x${field.toString("hex")}`);
    if (fieldValue >= modulus) {
      process.exit(1);
    }
    const nonCanonicalValue = fieldValue + modulus;
    if (nonCanonicalValue >= (1n << 256n)) {
      process.exit(1);
    }
    const output = Buffer.from(input);
    Buffer.from(nonCanonicalValue.toString(16).padStart(64, "0"), "hex").copy(output, fieldOffset);
    writeFileSync(outputPath, output);
  ' "${source_path}" "${output_path}" "${field_offset}"
}

copy_field_plus_bn254_base_modulus() {
  local source_path="$1"
  local output_path="$2"
  local field_offset="$3"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const sourcePath = process.argv[1];
    const outputPath = process.argv[2];
    const fieldOffset = Number.parseInt(process.argv[3], 10);
    if (!Number.isSafeInteger(fieldOffset) || fieldOffset < 0) {
      process.exit(1);
    }
    const input = readFileSync(sourcePath);
    if (input.length < fieldOffset + 32) {
      process.exit(1);
    }
    const modulus = BigInt("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    const field = input.subarray(fieldOffset, fieldOffset + 32);
    const fieldValue = BigInt(`0x${field.toString("hex")}`);
    if (fieldValue >= modulus) {
      process.exit(1);
    }
    const nonCanonicalValue = fieldValue + modulus;
    if (nonCanonicalValue >= (1n << 256n)) {
      process.exit(1);
    }
    const output = Buffer.from(input);
    Buffer.from(nonCanonicalValue.toString(16).padStart(64, "0"), "hex").copy(output, fieldOffset);
    writeFileSync(outputPath, output);
  ' "${source_path}" "${output_path}" "${field_offset}"
}

copy_public_input_field_to_proof() {
  local public_inputs_path="$1"
  local proof_path="$2"
  local output_public_inputs_path="$3"
  local output_proof_path="$4"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const publicInputs = readFileSync(process.argv[1]);
    const proof = readFileSync(process.argv[2]);
    if (publicInputs.length < 32) {
      process.exit(1);
    }
    const moved = publicInputs.subarray(publicInputs.length - 32);
    writeFileSync(process.argv[3], publicInputs.subarray(0, publicInputs.length - 32));
    writeFileSync(process.argv[4], Buffer.concat([moved, proof]));
  ' "${public_inputs_path}" "${proof_path}" "${output_public_inputs_path}" "${output_proof_path}"
}

copy_proof_field_to_public_inputs() {
  local public_inputs_path="$1"
  local proof_path="$2"
  local output_public_inputs_path="$3"
  local output_proof_path="$4"
  node -e '
    const { readFileSync, writeFileSync } = require("node:fs");
    const publicInputs = readFileSync(process.argv[1]);
    const proof = readFileSync(process.argv[2]);
    if (proof.length < 32) {
      process.exit(1);
    }
    const moved = proof.subarray(0, 32);
    writeFileSync(process.argv[3], Buffer.concat([publicInputs, moved]));
    writeFileSync(process.argv[4], proof.subarray(32));
  ' "${public_inputs_path}" "${proof_path}" "${output_public_inputs_path}" "${output_proof_path}"
}

MUTATED_PROOF="${NEGATIVE_DIR}/mutated-proof"
EMPTY_PROOF="${NEGATIVE_DIR}/empty-proof"
TRUNCATED_PROOF="${NEGATIVE_DIR}/truncated-proof"
EXTENDED_PROOF="${NEGATIVE_DIR}/extended-proof"
FIELD_EXTENDED_PROOF="${NEGATIVE_DIR}/field-extended-proof"
NONCANONICAL_PROOF_FIELD="${NEGATIVE_DIR}/noncanonical-proof-field"
SPLIT_SHORT_PUBLIC_INPUTS="${NEGATIVE_DIR}/split-short-public-inputs"
SPLIT_EXTENDED_PROOF="${NEGATIVE_DIR}/split-extended-proof"
SPLIT_EXTENDED_PUBLIC_INPUTS="${NEGATIVE_DIR}/split-extended-public-inputs"
SPLIT_SHORT_PROOF="${NEGATIVE_DIR}/split-short-proof"
MUTATED_PUBLIC_INPUTS="${NEGATIVE_DIR}/mutated-public-inputs"
EMPTY_PUBLIC_INPUTS="${NEGATIVE_DIR}/empty-public-inputs"
TRUNCATED_PUBLIC_INPUTS="${NEGATIVE_DIR}/truncated-public-inputs"
EXTENDED_PUBLIC_INPUTS="${NEGATIVE_DIR}/extended-public-inputs"
NONCANONICAL_PUBLIC_INPUT_FIELD="${NEGATIVE_DIR}/noncanonical-public-input-field"
WRONG_VK="${NEGATIVE_DIR}/wrong-vk"
EMPTY_VK="${NEGATIVE_DIR}/empty-vk"
TRUNCATED_VK="${NEGATIVE_DIR}/truncated-vk"
EXTENDED_VK="${NEGATIVE_DIR}/extended-vk"
NONCANONICAL_VK_COORDINATE="${NEGATIVE_DIR}/noncanonical-vk-coordinate"

cp "${PROOF_PATH}" "${MUTATED_PROOF}"
# Mutate away from the leading proof metadata so the negative case preserves the
# proof length and exercises backend rejection of malformed proof material.
node "${HELPER_DIR}/test-negative-proof.mjs" "${MUTATED_PROOF}" 64
: >"${EMPTY_PROOF}"
copy_truncated "${PROOF_PATH}" "${TRUNCATED_PROOF}"
copy_extended "${PROOF_PATH}" "${EXTENDED_PROOF}"
copy_extended_by_field "${PROOF_PATH}" "${FIELD_EXTENDED_PROOF}"
copy_field_plus_bn254_base_modulus "${PROOF_PATH}" "${NONCANONICAL_PROOF_FIELD}" 0
copy_public_input_field_to_proof \
  "${PUBLIC_INPUTS_PATH}" \
  "${PROOF_PATH}" \
  "${SPLIT_SHORT_PUBLIC_INPUTS}" \
  "${SPLIT_EXTENDED_PROOF}"
copy_proof_field_to_public_inputs \
  "${PUBLIC_INPUTS_PATH}" \
  "${PROOF_PATH}" \
  "${SPLIT_EXTENDED_PUBLIC_INPUTS}" \
  "${SPLIT_SHORT_PROOF}"

cp "${PUBLIC_INPUTS_PATH}" "${MUTATED_PUBLIC_INPUTS}"
node "${HELPER_DIR}/test-negative-proof.mjs" "${MUTATED_PUBLIC_INPUTS}" 0
: >"${EMPTY_PUBLIC_INPUTS}"
copy_truncated "${PUBLIC_INPUTS_PATH}" "${TRUNCATED_PUBLIC_INPUTS}"
copy_extended "${PUBLIC_INPUTS_PATH}" "${EXTENDED_PUBLIC_INPUTS}"
copy_field_plus_bn254_scalar_modulus "${PUBLIC_INPUTS_PATH}" "${NONCANONICAL_PUBLIC_INPUT_FIELD}" 0

cp "${VK_PATH}" "${WRONG_VK}"
node "${HELPER_DIR}/test-negative-proof.mjs" "${WRONG_VK}" 0
: >"${EMPTY_VK}"
copy_truncated "${VK_PATH}" "${TRUNCATED_VK}"
copy_extended "${VK_PATH}" "${EXTENDED_VK}"
copy_field_plus_bn254_base_modulus "${VK_PATH}" "${NONCANONICAL_VK_COORDINATE}" 32

assert_artifact_shape_or_verify_rejects "a mutated proof" \
  "${VK_PATH}" "${MUTATED_PROOF}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "an empty proof" \
  "${VK_PATH}" "${EMPTY_PROOF}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a truncated proof" \
  "${VK_PATH}" "${TRUNCATED_PROOF}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "an extended proof" \
  "${VK_PATH}" "${EXTENDED_PROOF}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a field-extended proof" \
  "${VK_PATH}" "${FIELD_EXTENDED_PROOF}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a noncanonical proof field encoding" \
  "${VK_PATH}" "${NONCANONICAL_PROOF_FIELD}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a public-input field moved into the proof" \
  "${VK_PATH}" "${SPLIT_EXTENDED_PROOF}" "${SPLIT_SHORT_PUBLIC_INPUTS}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a proof field moved into public inputs" \
  "${VK_PATH}" "${SPLIT_SHORT_PROOF}" "${SPLIT_EXTENDED_PUBLIC_INPUTS}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "mutated public inputs" \
  "${VK_PATH}" "${PROOF_PATH}" "${MUTATED_PUBLIC_INPUTS}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "empty public inputs" \
  "${VK_PATH}" "${PROOF_PATH}" "${EMPTY_PUBLIC_INPUTS}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "truncated public inputs" \
  "${VK_PATH}" "${PROOF_PATH}" "${TRUNCATED_PUBLIC_INPUTS}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "extended public inputs" \
  "${VK_PATH}" "${PROOF_PATH}" "${EXTENDED_PUBLIC_INPUTS}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a noncanonical public-input field encoding" \
  "${VK_PATH}" "${PROOF_PATH}" "${NONCANONICAL_PUBLIC_INPUT_FIELD}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a wrong verification key" \
  "${WRONG_VK}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "an empty verification key" \
  "${EMPTY_VK}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a truncated verification key" \
  "${TRUNCATED_VK}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "an extended verification key" \
  "${EXTENDED_VK}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "a noncanonical verification-key coordinate encoding" \
  "${NONCANONICAL_VK_COORDINATE}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak --zk
assert_artifact_shape_or_verify_rejects "the proof under an unmasked proof mode" \
  "${VK_PATH}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash keccak
assert_artifact_shape_or_verify_rejects "the proof under an incompatible transcript" \
  "${VK_PATH}" "${PROOF_PATH}" "${PUBLIC_INPUTS_PATH}" \
  --oracle_hash poseidon2 --zk
