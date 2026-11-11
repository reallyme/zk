#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="${LOG_DIR:-${ROOT}/target/modern-linked-all30-matrix}"

fail() {
  echo "modern linked request-bound circuit matrix failed: $1" >&2
  exit 2
}

require_file() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" ]]; then
    fail "${name} must be set"
  fi
  if [[ ! -f "${value}" ]]; then
    fail "${name} does not point at a file"
  fi
}

require_dir() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" ]]; then
    fail "${name} must be set"
  fi
  if [[ ! -d "${value}" ]]; then
    fail "${name} does not point at a directory"
  fi
}

require_one_test_passed() {
  local log_path="$1"
  local label="$2"

  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' "${log_path}"; then
    fail "${label} did not execute exactly one test"
  fi
}

# The CI installer keeps the pinned native archive and CRS beside its bb
# binary. Explicit paths still take precedence for independently staged builds.
if [[ -z "${REALLYME_BARRETENBERG_LIB_DIR:-}" && -n "${BB:-}" ]]; then
  bb_real="$(realpath "${BB}")" || fail "BB executable cannot be resolved"
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) platform="darwinArm64" ;;
    Linux:x86_64) platform="linuxX86_64" ;;
    *) fail "no default linked library for this platform" ;;
  esac
  REALLYME_BARRETENBERG_LIB_DIR="$(dirname "$(dirname "${bb_real}")")/lib/${platform}"
fi
REALLYME_ZK_ALL_CIRCUITS_V1_ROOT="${REALLYME_ZK_ALL_CIRCUITS_V1_ROOT:-${ROOT}/circuits}"
if [[ -n "${BB_CRS_DIR:-}" ]]; then
  REALLYME_BN254_G1_PATH="${REALLYME_BN254_G1_PATH:-${BB_CRS_DIR}/bn254_g1.dat}"
  REALLYME_BN254_G2_PATH="${REALLYME_BN254_G2_PATH:-${BB_CRS_DIR}/bn254_g2.dat}"
fi
export REALLYME_BARRETENBERG_LIB_DIR REALLYME_ZK_ALL_CIRCUITS_V1_ROOT \
  REALLYME_BN254_G1_PATH REALLYME_BN254_G2_PATH

require_dir REALLYME_BARRETENBERG_LIB_DIR
require_dir REALLYME_ZK_ALL_CIRCUITS_V1_ROOT
require_file REALLYME_BN254_G1_PATH
require_file REALLYME_BN254_G2_PATH

mkdir -p "${LOG_DIR}"

export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"

(
  cd "${ROOT}"
  REALLYME_NATIVE_ALL30_VERIFY_ONLY=1 \
    REALLYME_LINKED_ALL30_VERIFY_SUMMARY="${LOG_DIR}/verifier-only-summary.tsv" \
    cargo test -p reallyme-zk-backend-bb --features native \
      --test native_linked_all30_verify_only -- --nocapture --test-threads=1
)

(
  cd "${ROOT}"
  REALLYME_NATIVE_ALL30_PROVE_VERIFY=1 \
    REALLYME_LINKED_ALL30_PROVE_SUMMARY="${LOG_DIR}/prove-verify-summary.tsv" \
    cargo test -p reallyme-zk-backend-bb --features native \
      --test native_linked_all30_prove_verify -- --nocapture --test-threads=1
)

(
  cd "${ROOT}"
  cargo test -p reallyme-zk-backend-bb --features native \
    --test native_linked_private_persona_composition \
    linked_private_persona_same_fixture_compares_verified_session_links \
    -- --ignored --nocapture --test-threads=1
) 2>&1 | tee "${LOG_DIR}/private-persona-composition.log"
require_one_test_passed \
  "${LOG_DIR}/private-persona-composition.log" \
  "private-persona provider-boundary regression"

echo "verifier-only summary: ${LOG_DIR}/verifier-only-summary.tsv"
echo "prove/verify summary: ${LOG_DIR}/prove-verify-summary.tsv"
echo "private-persona provider-boundary regression: native_linked_private_persona_composition"
