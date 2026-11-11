#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CIRCUITS_ROOT="${CIRCUITS_ROOT:-${ROOT}/circuits}"
RUNS="${RUNS:-1}"
SUMMARY="${SUMMARY:-${ROOT}/target/modern-circuits-summary.tsv}"
SOURCE_HASHES="${SOURCE_HASHES:-${ROOT}/target/modern-circuits-source-hashes.tsv}"
SOURCE_FILE_HASHES="${SOURCE_FILE_HASHES:-${ROOT}/target/modern-circuits-source-file-hashes.tsv}"
SOURCE_LOCK="${SOURCE_LOCK:-${ROOT}/circuits/modern-circuit-source-lock.tsv}"
APPROVED_SOURCE_HASHES="${APPROVED_SOURCE_HASHES:-${ROOT}/target/modern-circuits-approved-source-hashes.tsv}"
PUBLIC_INPUT_COMPATIBILITY_LOCK="${PUBLIC_INPUT_COMPATIBILITY_LOCK:-${ROOT}/vectors/modern-transaction-bound-public-inputs-v1.tsv}"
PROOF_PREFIX="${PROOF_PREFIX:-modern}"
ISOLATED_HOME="${ISOLATED_HOME:-${ROOT}/target/modern-circuits-home}"
ISOLATED_CACHE="${ISOLATED_CACHE:-${ROOT}/target/modern-circuits-cache}"
TOOLCHAIN_LOCK="${TOOLCHAIN_LOCK:-${ROOT}/circuits/toolchain-lock.json}"
MANIFEST_LIST="${MANIFEST_LIST:-${ROOT}/target/modern-circuits-manifests.txt}"
DISCOVERED_REGISTRY_LIST="${DISCOVERED_REGISTRY_LIST:-${ROOT}/target/modern-circuits-discovered.txt}"
API_REGISTRY_LIST="${API_REGISTRY_LIST:-${ROOT}/target/modern-circuits-api-registry.txt}"
PRODUCTION_PROOF_SUITE="barretenberg_ultra_honk_keccak_zk_no_ipa"
BB_VERIFIER_TARGET="evm"
CARGO_BIN="${CARGO:-cargo}"

fail() {
  echo "modern circuit gate failed: $1" >&2
  exit 2
}

lock_value() {
  local json_path="$1"

  node -e '
const fs = require("node:fs");
const lockPath = process.argv[1];
const jsonPath = process.argv[2].split(".");
let value = JSON.parse(fs.readFileSync(lockPath, "utf8"));
for (const key of jsonPath) {
  if (typeof value !== "object" || value === null || Array.isArray(value) || !(key in value)) {
    process.exit(3);
  }
  value = value[key];
}
if (typeof value !== "string" && typeof value !== "number") {
  process.exit(4);
}
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

sha256_stream() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{ print $1 }'
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
    return 0
  fi
  fail "no SHA-256 command is available"
}

mutate_first_byte() {
  local source="$1"
  local target="$2"

  node -e '
const fs = require("node:fs");
const source = process.argv[1];
const target = process.argv[2];
if (source === undefined || target === undefined || source === target) {
  process.exit(2);
}
const metadata = fs.lstatSync(source);
if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > 16 * 1024 * 1024) {
  process.exit(3);
}
const bytes = fs.readFileSync(source);
bytes[0] ^= 1;
const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW;
const descriptor = fs.openSync(target, flags, 0o600);
try {
  fs.writeFileSync(descriptor, bytes);
  fs.fsyncSync(descriptor);
} finally {
  fs.closeSync(descriptor);
}
' "${source}" "${target}"
}

circuit_source_closure_sha256() {
  local circuit_rel="$1"

  circuit_source_file_hash_lines "${circuit_rel}" | sha256_stream
}

circuit_source_file_hash_lines() {
  local circuit_rel="$1"

  (
    cd "${CIRCUITS_ROOT}"
    {
      find "${circuit_rel}" \
        -type f \
        \( -name '*.nr' -o -name 'Nargo.toml' \) \
        -not -path '*/target/*' \
        -print
      if [[ -d vendor ]]; then
        find vendor \
          -type f \
          \( -name '*.nr' -o -name 'Nargo.toml' \) \
          -not -path '*/target/*' \
          -print
      fi
    } | sort | while IFS= read -r source_path; do
      printf '%s\t' "${source_path}"
      sha256_file "${source_path}"
    done
  )
}

validate_source_hash_manifests() {
  local source_hash_count

  if ! awk -F '\t' '
    NR == 1 {
      if ($0 != "circuit\tpackage\tsource_closure_sha256") {
        exit 1
      }
      next
    }
    length($3) != 64 || $3 !~ /^[0-9a-f]+$/ { exit 1 }
  ' "${SOURCE_HASHES}"; then
    fail "source hash manifest is malformed"
  fi
  source_hash_count="$(tail -n +2 "${SOURCE_HASHES}" | wc -l | tr -d ' ')"
  if [[ "${source_hash_count}" != "${expected_circuit_count}" ]]; then
    fail "source hash manifest does not cover every registered circuit"
  fi
  if [[ ! -f "${SOURCE_LOCK}" ]]; then
    fail "approved source hash lock is missing"
  fi
  if ! awk -F '\t' 'NR == 1 || ($1 !~ /\/common_credential_root_v1\// && $1 !~ /\/persona_credential_evidence_v1\//)' \
    "${SOURCE_LOCK}" > "${APPROVED_SOURCE_HASHES}"; then
    fail "approved source hash lock could not be filtered to promoted circuits"
  fi
  if ! cmp -s "${APPROVED_SOURCE_HASHES}" "${SOURCE_HASHES}"; then
    diff -u "${APPROVED_SOURCE_HASHES}" "${SOURCE_HASHES}" >&2 || true
    fail "observed source hashes do not match the approved source lock"
  fi
  if ! awk -F '\t' '
    NR == 1 {
      if ($0 != "circuit\tpackage\tsource_path\tsource_file_sha256") {
        exit 1
      }
      next
    }
    length($4) != 64 || $4 !~ /^[0-9a-f]+$/ { exit 1 }
  ' "${SOURCE_FILE_HASHES}"; then
    fail "source file hash manifest is malformed"
  fi
  while IFS=$'\t' read -r circuit_rel package_name source_closure_sha256; do
    if [[ "${circuit_rel}" == "circuit" ]]; then
      continue
    fi
    recomputed_source_closure_sha256="$(
      awk -F '\t' -v circuit="${circuit_rel}" -v package="${package_name}" '
        $1 == circuit && $2 == package { print $3 "\t" $4 }
      ' "${SOURCE_FILE_HASHES}" | sha256_stream
    )"
    if [[ "${recomputed_source_closure_sha256}" != "${source_closure_sha256}" ]]; then
      fail "source closure hash does not match its per-file manifest"
    fi
  done < "${SOURCE_HASHES}"
}

validate_summary() {
  local expected_summary_rows summary_rows

  expected_summary_rows=$((1 + (expected_circuit_count * RUNS)))
  summary_rows="$(wc -l < "${SUMMARY}" | tr -d ' ')"
  if [[ "${summary_rows}" != "${expected_summary_rows}" ]]; then
    fail "summary row count does not match the executed circuit matrix"
  fi
  if ! awk -F '\t' '
    NR == 1 {
      if ($0 != "run\tcircuit\tpackage\tsource_closure_sha256\tproof_bytes\tpublic_input_bytes\tvk_bytes\tvk_hash_bytes") {
        exit 1
      }
      next
    }
    NF != 8 { exit 1 }
    length($4) != 64 || $4 !~ /^[0-9a-f]+$/ { exit 1 }
    $5 !~ /^[1-9][0-9]*$/ { exit 1 }
    $6 !~ /^[1-9][0-9]*$/ { exit 1 }
    $7 !~ /^[1-9][0-9]*$/ { exit 1 }
    $8 != "32" { exit 1 }
    {
      key = $1 "\t" $2
      if (seen[key] == 1) {
        exit 1
      }
      seen[key] = 1
    }
  ' "${SUMMARY}"; then
    fail "summary manifest is malformed"
  fi
}

validate_public_input_compatibility_lock() {
  local compatibility_count

  if [[ ! -f "${PUBLIC_INPUT_COMPATIBILITY_LOCK}" ]]; then
    fail "public-input compatibility lock is missing"
  fi
  if ! awk -F '\t' '
    NR == 1 {
      if ($0 != "circuit\tpublic_input_bytes\tmodern_transaction_bound_public_inputs_sha256") {
        exit 1
      }
      next
    }
    NF != 3 { exit 1 }
    $1 == "" { exit 1 }
    $2 !~ /^[1-9][0-9]*$/ { exit 1 }
    length($3) != 64 || $3 !~ /^[0-9a-f]+$/ { exit 1 }
    seen[$1] == 1 { exit 1 }
    { seen[$1] = 1 }
  ' "${PUBLIC_INPUT_COMPATIBILITY_LOCK}"; then
    fail "public-input compatibility lock is malformed"
  fi
  compatibility_count="$(tail -n +2 "${PUBLIC_INPUT_COMPATIBILITY_LOCK}" | wc -l | tr -d ' ')"
  if [[ "${compatibility_count}" != "${expected_circuit_count}" ]]; then
    fail "public-input compatibility lock does not cover every registered circuit"
  fi
}

platform_key() {
  local kernel machine

  kernel="$(uname -s)"
  machine="$(uname -m)"
  case "${kernel}:${machine}" in
    Darwin:arm64) echo "darwinArm64" ;;
    Darwin:x86_64) echo "darwinX86_64" ;;
    Linux:aarch64) echo "linuxArm64" ;;
    Linux:x86_64) echo "linuxX86_64" ;;
    *) fail "unsupported local toolchain platform ${kernel}:${machine}" ;;
  esac
}

if [[ -z "${NARGO:-}" ]]; then
  fail "NARGO must point to the pinned nargo binary"
fi

if [[ -z "${BB:-}" ]]; then
  fail "BB must point to the pinned Barretenberg binary"
fi

if [[ -z "${BB_CRS_DIR:-}" || "${BB_CRS_DIR}" != /* || ! -d "${BB_CRS_DIR}" || -L "${BB_CRS_DIR}" ]]; then
  fail "BB_CRS_DIR must name a plain absolute CRS directory"
fi

if [[ ! -x "${NARGO}" ]]; then
  fail "NARGO is not executable"
fi

if [[ ! -x "${BB}" ]]; then
  fail "BB is not executable"
fi

if [[ ! "${RUNS}" =~ ^[1-9][0-9]*$ ]]; then
  fail "RUNS must be a positive integer"
fi
if ((RUNS > 3)); then
  fail "RUNS must not exceed the reviewed three-run promotion gate"
fi

if [[ ! -f "${TOOLCHAIN_LOCK}" ]]; then
  fail "toolchain lock is missing"
fi
if ! command -v node >/dev/null 2>&1; then
  fail "node is required to read the toolchain lock"
fi
if ! command -v "${CARGO_BIN}" >/dev/null 2>&1; then
  fail "cargo is required to read the canonical API circuit registry"
fi

expected_proof_suite="$(lock_value "candidateMatchedPair.proofSuite")"
if [[ "${expected_proof_suite}" != "${PRODUCTION_PROOF_SUITE}" ]]; then
  fail "toolchain lock does not name the production Keccak ZK proof suite"
fi

expected_nargo_version="$(lock_value "candidateMatchedPair.noir.version")"
expected_noirc_revision="$(lock_value "candidateMatchedPair.noir.revision")"
expected_bb_version="$(lock_value "candidateMatchedPair.barretenberg.aztecPackagesVersion")"
expected_circuit_count="$(lock_value "candidateMatchedPair.expectedCircuitCount")"
host_key="$(platform_key)"
expected_nargo_sha256="$(lock_value "candidateMatchedPair.localBinaryIdentities.${host_key}.nargoExecutableSha256")"
expected_bb_sha256="$(lock_value "candidateMatchedPair.localBinaryIdentities.${host_key}.barretenbergExecutableSha256")"

nargo_version_output="$("${NARGO}" --version)"
nargo_version="$(sed -n '1s/^nargo version = //p' <<<"${nargo_version_output}")"
noirc_revision="$(sed -n '2s/^noirc version = [^+]*+//p' <<<"${nargo_version_output}")"
if [[ "${nargo_version}" != "${expected_nargo_version}" ]]; then
  fail "NARGO version does not match the toolchain lock"
fi
if [[ "${noirc_revision}" != "${expected_noirc_revision}" ]]; then
  fail "Noirc revision does not match the toolchain lock"
fi

bb_version="$("${BB}" --version)"
if [[ "${bb_version}" != "${expected_bb_version}" ]]; then
  fail "Barretenberg version does not match the toolchain lock"
fi

if [[ "$(sha256_file "${NARGO}")" != "${expected_nargo_sha256}" ]]; then
  fail "NARGO binary hash does not match the toolchain lock"
fi
if [[ "$(sha256_file "${BB}")" != "${expected_bb_sha256}" ]]; then
  fail "Barretenberg binary hash does not match the toolchain lock"
fi

g1_path="${BB_CRS_DIR}/bn254_g1.dat"
g2_path="${BB_CRS_DIR}/bn254_g2.dat"
if [[ ! -f "${g1_path}" || -L "${g1_path}" || ! -f "${g2_path}" || -L "${g2_path}" ]]; then
  fail "pinned CRS files are missing or symlinked"
fi
expected_g1_bytes="$(lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g1SourceBytes")"
expected_g1_sha256="$(lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g1SourceSha256")"
expected_g2_bytes="$(lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g2Bytes")"
expected_g2_sha256="$(lock_value "candidateMatchedPair.barretenberg.crsIdentities.bn254FullProver1048577Points.g2Sha256")"
if [[ "$(wc -c < "${g1_path}" | tr -d ' ')" != "${expected_g1_bytes}" || \
      "$(sha256_file "${g1_path}")" != "${expected_g1_sha256}" || \
      "$(wc -c < "${g2_path}" | tr -d ' ')" != "${expected_g2_bytes}" || \
      "$(sha256_file "${g2_path}")" != "${expected_g2_sha256}" ]]; then
  fail "CRS file identity does not match the toolchain lock"
fi

run_bb() {
  local command="$1"
  shift
  "${BB}" "${command}" -c "${BB_CRS_DIR}" "$@"
}

mkdir -p "$(dirname "${SUMMARY}")" "$(dirname "${SOURCE_HASHES}")" "$(dirname "${SOURCE_FILE_HASHES}")" "$(dirname "${APPROVED_SOURCE_HASHES}")" "$(dirname "${MANIFEST_LIST}")" "${ISOLATED_HOME}" "${ISOLATED_CACHE}"
printf 'run\tcircuit\tpackage\tsource_closure_sha256\tproof_bytes\tpublic_input_bytes\tvk_bytes\tvk_hash_bytes\n' > "${SUMMARY}"
printf 'circuit\tpackage\tsource_closure_sha256\n' > "${SOURCE_HASHES}"
printf 'circuit\tpackage\tsource_path\tsource_file_sha256\n' > "${SOURCE_FILE_HASHES}"

reference_circuit=""
reference_vk=""
reference_proof=""
reference_public_inputs=""
last_vk=""

find "${CIRCUITS_ROOT}" \
  -maxdepth 5 \
  -name Nargo.toml \
  -not -path '*/vendor/*' \
  -not -path '*/security-regressions/*' \
  -print |
  awk '$0 !~ /\/common_credential_root_v1\// && $0 !~ /\/persona_credential_evidence_v1\//' |
  sort > "${MANIFEST_LIST}"
sed "s#^${CIRCUITS_ROOT}/##; s#/Nargo.toml\$##" "${MANIFEST_LIST}" | sort > "${DISCOVERED_REGISTRY_LIST}"
"${CARGO_BIN}" run --quiet -p reallyme-zk-cli -- circuits --paths |
  sed '1d' |
  awk '$0 !~ /\/common_credential_root_v1\// && $0 !~ /\/persona_credential_evidence_v1\//' |
  sort > "${API_REGISTRY_LIST}"
discovered_circuit_count="$(wc -l < "${MANIFEST_LIST}" | tr -d ' ')"
canonical_registry_count="$(wc -l < "${API_REGISTRY_LIST}" | tr -d ' ')"
if [[ "${discovered_circuit_count}" != "${expected_circuit_count}" ||
  "${canonical_registry_count}" != "${expected_circuit_count}" ]]; then
  fail "circuit tree count does not match the canonical registry"
fi
if ! cmp -s "${DISCOVERED_REGISTRY_LIST}" "${API_REGISTRY_LIST}"; then
  diff -u "${API_REGISTRY_LIST}" "${DISCOVERED_REGISTRY_LIST}" >&2 || true
  fail "circuit tree identities do not match the canonical registry"
fi
validate_public_input_compatibility_lock

while IFS= read -r manifest; do
  circuit_dir="$(dirname "${manifest}")"
  circuit_rel="${circuit_dir#"${CIRCUITS_ROOT}"/}"
  package_name="$(awk -F ' *= *' '$1 == "name" { gsub(/"/, "", $2); print $2; exit }' "${manifest}")"

  if [[ -z "${package_name}" ]]; then
    fail "missing package name for ${circuit_rel}"
  fi
  source_closure_sha256="$(circuit_source_closure_sha256 "${circuit_rel}")"
  printf '%s\t%s\t%s\n' "${circuit_rel}" "${package_name}" "${source_closure_sha256}" >> "${SOURCE_HASHES}"
  circuit_source_file_hash_lines "${circuit_rel}" | while IFS=$'\t' read -r source_path source_file_sha256; do
    printf '%s\t%s\t%s\t%s\n' "${circuit_rel}" "${package_name}" "${source_path}" "${source_file_sha256}" >> "${SOURCE_FILE_HASHES}"
  done

  # Repeated promotion proofs share the same admitted program and witness.
  # Recompiling deterministic inputs for each proof adds no coverage.
  (
    cd "${circuit_dir}"
    HOME="${ISOLATED_HOME}" XDG_CACHE_HOME="${ISOLATED_CACHE}" "${NARGO}" compile --force
    HOME="${ISOLATED_HOME}" XDG_CACHE_HOME="${ISOLATED_CACHE}" "${NARGO}" execute
  )
  for run in $(seq 1 "${RUNS}"); do
    run_label="$(printf 'run-%02d' "${run}")"
    proof_dir="target/${PROOF_PREFIX}-${run_label}"

    (
      cd "${circuit_dir}"
      mkdir -p "${proof_dir}"
      run_bb prove \
        -b "target/${package_name}.json" \
        -w "target/${package_name}.gz" \
        -o "${proof_dir}" \
        -t "${BB_VERIFIER_TARGET}" \
        --write_vk \
        --verify
      run_bb verify \
        -k "${proof_dir}/vk" \
        -p "${proof_dir}/proof" \
        -i "${proof_dir}/public_inputs" \
        -t "${BB_VERIFIER_TARGET}"
      mutate_first_byte "${proof_dir}/proof" "${proof_dir}/proof.tampered"
      if run_bb verify \
        -k "${proof_dir}/vk" \
        -p "${proof_dir}/proof.tampered" \
        -i "${proof_dir}/public_inputs" \
        -t "${BB_VERIFIER_TARGET}" >/dev/null 2>&1; then
        fail "tampered proof was accepted for ${circuit_rel}"
      fi
      mutate_first_byte "${proof_dir}/public_inputs" "${proof_dir}/public_inputs.tampered"
      if run_bb verify \
        -k "${proof_dir}/vk" \
        -p "${proof_dir}/proof" \
        -i "${proof_dir}/public_inputs.tampered" \
        -t "${BB_VERIFIER_TARGET}" >/dev/null 2>&1; then
        fail "tampered public inputs were accepted for ${circuit_rel}"
      fi
      if [[ -n "${reference_vk}" && "${circuit_rel}" != "${reference_circuit}" ]]; then
        if run_bb verify \
          -k "${reference_vk}" \
          -p "${proof_dir}/proof" \
          -i "${proof_dir}/public_inputs" \
          -t "${BB_VERIFIER_TARGET}" >/dev/null 2>&1; then
          fail "wrong verification key was accepted for ${circuit_rel}"
        fi
      fi
      proof_bytes="$(wc -c < "${proof_dir}/proof" | tr -d ' ')"
      public_input_bytes="$(wc -c < "${proof_dir}/public_inputs" | tr -d ' ')"
      expected_public_input_bytes="$(
        awk -F '\t' -v circuit="${circuit_rel}" '$1 == circuit { print $2 }' \
          "${PUBLIC_INPUT_COMPATIBILITY_LOCK}"
      )"
      expected_public_input_sha256="$(
        awk -F '\t' -v circuit="${circuit_rel}" '$1 == circuit { print $3 }' \
          "${PUBLIC_INPUT_COMPATIBILITY_LOCK}"
      )"
      if [[ -z "${expected_public_input_bytes}" || -z "${expected_public_input_sha256}" ]]; then
        fail "public-input compatibility entry is missing for ${circuit_rel}"
      fi
      if [[ "${public_input_bytes}" != "${expected_public_input_bytes}" ]]; then
        fail "public-input byte length changed for ${circuit_rel}"
      fi
      if [[ "$(sha256_file "${proof_dir}/public_inputs")" != "${expected_public_input_sha256}" ]]; then
        fail "public-input bytes changed for ${circuit_rel}"
      fi
      vk_bytes="$(wc -c < "${proof_dir}/vk" | tr -d ' ')"
      vk_hash_bytes="$(wc -c < "${proof_dir}/vk_hash" | tr -d ' ')"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${run_label}" \
        "${circuit_rel}" \
        "${package_name}" \
        "${source_closure_sha256}" \
        "${proof_bytes}" \
        "${public_input_bytes}" \
        "${vk_bytes}" \
        "${vk_hash_bytes}" >> "${SUMMARY}"
    )
    current_proof_dir="${circuit_dir}/${proof_dir}"
    if [[ -z "${reference_vk}" ]]; then
      reference_circuit="${circuit_rel}"
      reference_vk="${current_proof_dir}/vk"
      reference_proof="${current_proof_dir}/proof"
      reference_public_inputs="${current_proof_dir}/public_inputs"
    fi
    last_vk="${current_proof_dir}/vk"
  done
done < "${MANIFEST_LIST}"

if [[ -z "${reference_vk}" || -z "${last_vk}" || "${reference_vk}" == "${last_vk}" ]]; then
  fail "wrong-verification-key matrix did not cover the first circuit"
fi
if run_bb verify \
  -k "${last_vk}" \
  -p "${reference_proof}" \
  -i "${reference_public_inputs}" \
  -t "${BB_VERIFIER_TARGET}" >/dev/null 2>&1; then
  fail "wrong verification key was accepted for ${reference_circuit}"
fi

validate_source_hash_manifests
validate_summary

# The claim-family fixtures are generated from repository source, including
# the Poseidon2 oracle, so build that oracle from this checkout first.
"${CARGO_BIN}" build --locked --target-dir "${ROOT}/target" \
  --package reallyme-zk-noir-witness-core \
  --bin poseidon2-bounded-fixture
POSEIDON2_FIXTURE_BIN="${ROOT}/target/debug/poseidon2-bounded-fixture" \
  NARGO="${NARGO}" python3 "${ROOT}/scripts/test-claim-family-fixed-depth.py" ||
  fail "claim-family fixed-depth fixtures or negatives failed"

echo "summary: ${SUMMARY}"
echo "source-hashes: ${SOURCE_HASHES}"
echo "source-file-hashes: ${SOURCE_FILE_HASHES}"
