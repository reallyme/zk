#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() {
  echo "linked private-persona distinct-subject gate failed: $1" >&2
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
    fail "filtered cargo test did not execute exactly one signed-vector proof test"
  fi
}

require_dir REALLYME_BARRETENBERG_LIB_DIR
require_dir REALLYME_ZK_ALL_CIRCUITS_V1_ROOT
require_dir REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT
require_file REALLYME_BN254_G1_PATH
require_file REALLYME_BN254_G2_PATH

export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"
LOG_PATH="${LOG_PATH:-${ROOT}/target/linked-private-persona-distinct-subject.log}"
mkdir -p "$(dirname "${LOG_PATH}")"

(
  cd "${ROOT}"
  cargo test -p reallyme-zk-backend-bb --features native \
    --test native_linked_private_persona_composition \
    linked_private_persona_distinct_hidden_subject_credentials_share_session_link \
    -- --ignored --nocapture --test-threads=1
) 2>&1 | tee "${LOG_PATH}"

require_one_test_passed "${LOG_PATH}"
