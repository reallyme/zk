#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="${LOG_DIR:-${ROOT}/target/native-linked-claim-bundle-capacity}"

fail() {
  echo "native linked claim-bundle capacity gate failed: $1" >&2
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

  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' "${log_path}"; then
    fail "native_linked_claim_bundle_capacity did not execute exactly one test"
  fi
}

require_dir REALLYME_BARRETENBERG_LIB_DIR
require_dir REALLYME_ZK_ALL_CIRCUITS_V1_ROOT
require_file REALLYME_BN254_G1_PATH
require_file REALLYME_BN254_G2_PATH

mkdir -p "${LOG_DIR}"
export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"
LOG_PATH="${LOG_PATH:-${LOG_DIR}/cargo-test.log}"
SUMMARY_PATH="${SUMMARY_PATH:-${LOG_DIR}/claim-bundle-capacity-summary.tsv}"

(
  cd "${ROOT}"
  REALLYME_CLAIM_BUNDLE_CAPACITY_SUMMARY="${SUMMARY_PATH}" \
    cargo test -p reallyme-zk-backend-bb --features native \
      --test native_linked_claim_bundle_capacity \
      claim_bundle_4_capacity_is_measured_with_negative_binding_checks \
      -- --ignored --nocapture --test-threads=1
) 2>&1 | tee "${LOG_PATH}"

require_one_test_passed "${LOG_PATH}"
if [[ "$(wc -l < "${SUMMARY_PATH}" | tr -d ' ')" != "5" ]]; then
  fail "capacity summary must contain a header plus four claim_bundle_4 rows"
fi

echo "claim_bundle_4 capacity summary: ${SUMMARY_PATH}"
