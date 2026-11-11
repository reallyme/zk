#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TOOLCHAIN_LOCK="${TOOLCHAIN_LOCK:-${ROOT}/circuits/toolchain-lock.json}"
CIRCUITS_ROOT="${REALLYME_ZK_ALL_CIRCUITS_V1_ROOT:-${ROOT}/circuits}"
OUTPUT_PARENT="${OUTPUT_PARENT:-${ROOT}/target}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
ISOLATED_HOME="${ISOLATED_HOME:-${ROOT}/target/modern-linked-cli-cross-verify-home}"
ISOLATED_CACHE="${ISOLATED_CACHE:-${ROOT}/target/modern-linked-cli-cross-verify-cache}"

fail() {
  echo "modern linked/CLI cross-verification gate failed: $1" >&2
  exit 2
}

lock_value() {
  local json_path="$1"

  node -e '
const fs = require("node:fs");
const keys = process.argv[2].split(".");
let value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const key of keys) {
  if (value === null || typeof value !== "object" || !(key in value)) process.exit(3);
  value = value[key];
}
if (typeof value !== "number" && typeof value !== "string") process.exit(4);
process.stdout.write(String(value));
' "${TOOLCHAIN_LOCK}" "${json_path}"
}

sha256_file() {
  local path="$1"

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{ print $1 }'
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{ print $1 }'
    return 0
  fi
  fail "no SHA-256 command is available"
}

platform_key() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}:${arch}" in
    Darwin:arm64) printf 'darwinArm64' ;;
    Darwin:x86_64) printf 'darwinX86_64' ;;
    Linux:x86_64) printf 'linuxX86_64' ;;
    Linux:aarch64 | Linux:arm64) printf 'linuxArm64' ;;
    *) fail "unsupported platform ${os}:${arch}" ;;
  esac
}

require_file() {
  local path="$1" label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} must be a plain file"
}

require_one_test_passed() {
  local log_path="$1"

  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' "${log_path}"; then
    fail "native_linked_cli_cross_verify did not execute exactly one test"
  fi
}

[[ -n "${BB:-}" ]] || fail "BB must point at the pinned official candidate bb executable"
[[ -n "${BB_CRS_DIR:-}" && "${BB_CRS_DIR}" = /* && -d "${BB_CRS_DIR}" && ! -L "${BB_CRS_DIR}" ]] ||
  fail "BB_CRS_DIR must name a plain absolute CRS directory"
[[ "${CIRCUITS_ROOT}" = /* && -d "${CIRCUITS_ROOT}" && ! -L "${CIRCUITS_ROOT}" ]] ||
  fail "REALLYME_ZK_ALL_CIRCUITS_V1_ROOT must name a plain absolute circuit root"
[[ "${OUTPUT_PARENT}" = /* && -d "${OUTPUT_PARENT}" && ! -L "${OUTPUT_PARENT}" ]] ||
  fail "OUTPUT_PARENT must name a plain absolute directory"
[[ -x "${BB}" && ! -L "${BB}" ]] || fail "BB must be an executable plain file"
require_file "${TOOLCHAIN_LOCK}" "toolchain lock"

platform="$(platform_key)"
if [[ -z "${REALLYME_BARRETENBERG_LIB_DIR:-}" ]]; then
  toolchain_root="$(dirname "$(dirname "${BB}")")"
  REALLYME_BARRETENBERG_LIB_DIR="${toolchain_root}/lib/${platform}"
  export REALLYME_BARRETENBERG_LIB_DIR
fi
[[ -d "${REALLYME_BARRETENBERG_LIB_DIR}" && ! -L "${REALLYME_BARRETENBERG_LIB_DIR}" ]] ||
  fail "pinned linked Barretenberg library directory is missing"
expected_bb_sha256="$(
  lock_value "candidateMatchedPair.localBinaryIdentities.${platform}.barretenbergExecutableSha256"
)" || fail "candidate bb hash is missing for ${platform}"
[[ "$(sha256_file "${BB}")" == "${expected_bb_sha256}" ]] ||
  fail "BB hash does not match circuits/toolchain-lock.json"
expected_bb_version="$(lock_value "candidateMatchedPair.barretenberg.aztecPackagesVersion")" ||
  fail "candidate bb version is missing"
[[ "$("${BB}" --version)" == "${expected_bb_version}" ]] ||
  fail "BB version does not match circuits/toolchain-lock.json"

g1_path="${BB_CRS_DIR}/bn254_g1.dat"
g2_path="${BB_CRS_DIR}/bn254_g2.dat"
require_file "${g1_path}" "G1 CRS"
require_file "${g2_path}" "G2 CRS"
expected_g1_bytes="$(
  lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g1SourceBytes"
)"
expected_g1_sha256="$(
  lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g1SourceSha256"
)"
expected_g2_bytes="$(
  lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g2Bytes"
)"
expected_g2_sha256="$(
  lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g2Sha256"
)"
if [[ "$(wc -c < "${g1_path}" | tr -d ' ')" != "${expected_g1_bytes}" ||
      "$(sha256_file "${g1_path}")" != "${expected_g1_sha256}" ||
      "$(wc -c < "${g2_path}" | tr -d ' ')" != "${expected_g2_bytes}" ||
      "$(sha256_file "${g2_path}")" != "${expected_g2_sha256}" ]]; then
  fail "CRS file identity does not match the toolchain lock"
fi

if [[ -z "${OUTPUT_DIR}" ]]; then
  OUTPUT_DIR="$(mktemp -d "${OUTPUT_PARENT}/modern-linked-cli-cross-verify.XXXXXX")" ||
    fail "unable to create output directory"
else
  [[ "${OUTPUT_DIR}" = /* && ! -e "${OUTPUT_DIR}" ]] ||
    fail "OUTPUT_DIR must be an absent absolute path"
  mkdir -m 0700 "${OUTPUT_DIR}"
fi
[[ -d "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] || fail "output directory must be plain"
mkdir -p "${ISOLATED_HOME}" "${ISOLATED_CACHE}"

export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"
RUST_TEST_LOG="${RUST_TEST_LOG:-${OUTPUT_DIR}/cargo-test.log}"
(
  cd "${ROOT}"
  REALLYME_ZK_ALL_CIRCUITS_V1_ROOT="${CIRCUITS_ROOT}" \
    REALLYME_BN254_G1_PATH="${g1_path}" \
    REALLYME_BN254_G2_PATH="${g2_path}" \
    REALLYME_LINKED_CLI_CROSS_VERIFY_OUTPUT_DIR="${OUTPUT_DIR}" \
    cargo test -p reallyme-zk-backend-bb --features native \
      --test native_linked_cli_cross_verify -- --ignored --nocapture --test-threads=1
) 2>&1 | tee "${RUST_TEST_LOG}"
require_one_test_passed "${RUST_TEST_LOG}"

require_file "${OUTPUT_DIR}/proof" "linked proof"
require_file "${OUTPUT_DIR}/public_inputs" "linked public inputs"
require_file "${OUTPUT_DIR}/vk" "linked verification key"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for negative proof checks"

HOME="${ISOLATED_HOME}" XDG_CACHE_HOME="${ISOLATED_CACHE}" \
  "${BB}" verify -c "${BB_CRS_DIR}" \
    -k "${OUTPUT_DIR}/vk" \
    -p "${OUTPUT_DIR}/proof" \
    -i "${OUTPUT_DIR}/public_inputs" \
    -t evm

# The independent verifier must reject both a changed proof transcript and
# changed public inputs. Keep the originals intact for evidence inspection.
python3 - "${OUTPUT_DIR}" <<'PY'
from pathlib import Path
import sys

directory = Path(sys.argv[1])
for source_name, target_name, offset in (
    ("proof", "proof-tampered", -1),
    ("public_inputs", "public_inputs-tampered", 31),
):
    value = bytearray((directory / source_name).read_bytes())
    if not value:
        raise ValueError("cross-verification evidence is too short")
    if offset == -1:
        offset = len(value) // 2
    if len(value) <= offset:
        raise ValueError("cross-verification evidence is too short")
    value[offset] ^= 1
    (directory / target_name).write_bytes(value)
PY

expect_cli_rejection() {
  local proof_path="$1" public_inputs_path="$2" label="$3"
  local log_path="${OUTPUT_DIR}/${label}.log"

  if HOME="${ISOLATED_HOME}" XDG_CACHE_HOME="${ISOLATED_CACHE}" \
    "${BB}" verify -c "${BB_CRS_DIR}" \
      -k "${OUTPUT_DIR}/vk" -p "${proof_path}" \
      -i "${public_inputs_path}" -t evm >"${log_path}" 2>&1; then
    fail "official bb accepted ${label}"
  fi
  grep -Fq 'Proof verification failed' "${log_path}" ||
    fail "official bb did not report proof rejection for ${label}"
}

expect_cli_rejection "${OUTPUT_DIR}/proof-tampered" "${OUTPUT_DIR}/public_inputs" "tampered-proof"
expect_cli_rejection "${OUTPUT_DIR}/proof" "${OUTPUT_DIR}/public_inputs-tampered" "tampered-public-inputs"

printf 'linked-generated proof verified by isolated official bb: %s\n' "${OUTPUT_DIR}"
