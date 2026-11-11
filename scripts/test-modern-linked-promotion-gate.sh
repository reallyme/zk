#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="${LOG_DIR:-${ROOT}/target/modern-linked-promotion-gate}"

fail() {
  echo "modern linked promotion gate failed: $1" >&2
  exit 2
}

require_file_env() {
  local name="$1"
  local value="${!name:-}"

  if [[ -z "${value}" ]]; then
    fail "${name} must be set"
  fi
  if [[ ! -f "${value}" ]]; then
    fail "${name} does not name a file"
  fi
}

require_dir_env() {
  local name="$1"
  local value="${!name:-}"

  if [[ -z "${value}" ]]; then
    fail "${name} must be set"
  fi
  if [[ ! -d "${value}" ]]; then
    fail "${name} does not name a directory"
  fi
}

run_cargo_test() {
  local log_name="$1"
  shift

  local log_path
  log_path="${LOG_DIR}/${log_name}.log"
  (
    cd "${ROOT}"
    cargo test "$@"
  ) >"${log_path}" 2>&1 || {
    cat "${log_path}" >&2
    fail "${log_name} failed"
  }
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed; 0 failed' "${log_path}"; then
    cat "${log_path}" >&2
    fail "${log_name} did not execute any tests"
  fi
}

require_dir_env REALLYME_BARRETENBERG_LIB_DIR
require_dir_env REALLYME_ZK_ALL_CIRCUITS_V1_ROOT
require_file_env REALLYME_CLI_RETAINED_PROVE_COMMAND
require_file_env REALLYME_CLI_RETAINED_PUBLIC_INPUTS
require_file_env REALLYME_CLI_RETAINED_SRS_COMMAND
require_file_env REALLYME_CLI_RETAINED_WRONG_VERIFICATION_KEY

mkdir -p "${LOG_DIR}"

export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"

run_cargo_test \
  "noir-witness-boundary-contracts" \
  -p reallyme-zk-noir-witness-core \
  --all-features \
  --test circuit_boundary_contracts \
  --test bounded_hash_tail_vectors \
  --bin poseidon2-bounded-fixture \
  -- \
  --nocapture

export REALLYME_NATIVE_PROVE_THEN_VERIFY=1
export REALLYME_RETAINED_PROVE_COMMAND="${REALLYME_CLI_RETAINED_PROVE_COMMAND}"
export REALLYME_RETAINED_PROVE_PUBLIC_INPUTS="${REALLYME_CLI_RETAINED_PUBLIC_INPUTS}"
export REALLYME_PROVER_CRS_COMMAND="${REALLYME_CLI_RETAINED_SRS_COMMAND}"
export REALLYME_RETAINED_WRONG_VERIFICATION_KEY="${REALLYME_CLI_RETAINED_WRONG_VERIFICATION_KEY}"
export REALLYME_CLI_PROVE_VERIFY_RETAINED=1

run_cargo_test \
  "backend-native-linked-prove-verify" \
  -p reallyme-zk-backend-bb \
  --features native \
  --test native_linked_retained_verify \
  native_backend_proves_and_verifies_public_persona_session \
  -- \
  --nocapture

run_cargo_test \
  "cli-linked-prove-verify" \
  -p reallyme-zk-cli \
  --all-features \
  --test cli_tests \
  opt_in_prove_and_verify_commands_use_linked_backend \
  -- \
  --nocapture

printf 'modern linked promotion gate passed; logs written under %s\n' "${LOG_DIR}"
