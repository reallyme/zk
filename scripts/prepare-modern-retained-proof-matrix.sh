#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s <all-circuits-v1-root> <empty-output-root>\n' "$0" >&2
  exit 2
fi

SOURCE_ROOT="$1"
OUTPUT_ROOT="$2"
RUN_LABEL="${REALLYME_RETAINED_RUN_LABEL:-modern-run-01}"

fail() {
  printf 'retained proof matrix preparation failed: %s\n' "$1" >&2
  exit 2
}

require_directory() {
  local path="$1"
  local label="$2"
  if [[ ! -d "${path}" ]]; then
    fail "${label} does not name a directory"
  fi
  if [[ -L "${path}" ]]; then
    fail "${label} must not be a symbolic link"
  fi
}

require_empty_or_absent_directory() {
  local path="$1"
  if [[ -e "${path}" && ! -d "${path}" ]]; then
    fail "output root exists and is not a directory"
  fi
  if [[ -L "${path}" ]]; then
    fail "output root must not be a symbolic link"
  fi
  if [[ -d "${path}" ]]; then
    local first_entry
    first_entry="$(find "${path}" -mindepth 1 -print -quit)"
    if [[ -n "${first_entry}" ]]; then
      fail "output root must be empty"
    fi
  fi
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    fail "${label} is missing"
  fi
  if [[ -L "${path}" ]]; then
    fail "${label} must not be a symbolic link"
  fi
  if [[ ! -s "${path}" ]]; then
    fail "${label} is empty"
  fi
}

copy_stage_file() {
  local source_file="$1"
  local destination_file="$2"
  local label="$3"
  require_file "${source_file}" "${label}"
  if [[ -e "${destination_file}" ]]; then
    fail "destination already exists for ${label}"
  fi
  cp -p "${source_file}" "${destination_file}"
}

require_directory "${SOURCE_ROOT}" "all-circuits-v1 root"
require_empty_or_absent_directory "${OUTPUT_ROOT}"
mkdir -p "${OUTPUT_ROOT}"

hash_strategies=(sha256 poseidon2)
families=(
  credential_subject_claim_v1
  private_persona_claim_v1
)
stages=(
  session
  credential_envelope
  credential_root
  claim
  claim_bundle_4
)
# claim_bundle_4 is retained with the four staged proof flow so release
# evidence preserves the largest modern circuit without making mobile demo
# packages execute that diagnostic path by default.

for credential_hash_algorithm in "${hash_strategies[@]}"; do
  for family in "${families[@]}"; do
    for stage in "${stages[@]}"; do
      source_stage_root="${SOURCE_ROOT}/${credential_hash_algorithm}/families/${family}/${stage}/target/${RUN_LABEL}"
      destination_stage_root="${OUTPUT_ROOT}/${credential_hash_algorithm}/${family}/${stage}"
      destination_proof_root="${destination_stage_root}/proof"
      destination_vk_root="${destination_stage_root}/verification_key"
      mkdir -p "${destination_proof_root}" "${destination_vk_root}"
      copy_stage_file "${source_stage_root}/proof" "${destination_proof_root}/proof" "${credential_hash_algorithm}/${family}/${stage} proof"
      copy_stage_file "${source_stage_root}/public_inputs" "${destination_proof_root}/public_inputs" "${credential_hash_algorithm}/${family}/${stage} public inputs"
      copy_stage_file "${source_stage_root}/vk" "${destination_vk_root}/vk" "${credential_hash_algorithm}/${family}/${stage} verification key"
    done
  done
done

printf 'prepared retained proof matrix at %s from %s (%s)\n' "${OUTPUT_ROOT}" "${SOURCE_ROOT}" "${RUN_LABEL}"
