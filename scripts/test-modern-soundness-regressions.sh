#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TOOLCHAIN_LOCK="${TOOLCHAIN_LOCK:-${ROOT}/circuits/toolchain-lock.json}"
ISOLATED_HOME="${ISOLATED_HOME:-${ROOT}/target/modern-soundness-home}"
ISOLATED_CACHE="${ISOLATED_CACHE:-${ROOT}/target/modern-soundness-cache}"
LOG_DIR="${LOG_DIR:-${ROOT}/target/modern-soundness-regressions}"

fail() {
  echo "modern soundness regression gate failed: $1" >&2
  exit 2
}

source "${ROOT}/scripts/soundness-regression-assertions.sh"

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

run_nargo() {
  local fixture_rel="$1"
  local operation="$2"
  local fixture_name log_path

  fixture_name="${fixture_rel//\//__}"
  log_path="${LOG_DIR}/${fixture_name}.${operation}.log"
  (
    cd "${ROOT}/${fixture_rel}"
    HOME="${ISOLATED_HOME}" XDG_CACHE_HOME="${ISOLATED_CACHE}" "${NARGO}" "${operation}"
  ) >"${log_path}" 2>&1 || {
    cat "${log_path}" >&2
    fail "${fixture_rel} ${operation} failed"
  }
}

run_bb() {
  local expected_status="$1"
  local log_name="$2"
  shift 2

  local log_path status
  log_path="${LOG_DIR}/${log_name}.log"
  set +e
  local command="$1"
  shift
  "${BB}" "${command}" -c "${BB_CRS_DIR}" "$@" >"${log_path}" 2>&1
  status=$?
  set -e

  case "${expected_status}:${status}" in
    success:0 | failure:[1-9]*)
      return 0
      ;;
    success:*)
      cat "${log_path}" >&2
      fail "bb ${log_name} was expected to succeed"
      ;;
    failure:0)
      cat "${log_path}" >&2
      fail "bb ${log_name} was expected to fail"
      ;;
    *)
      fail "invalid expected status ${expected_status}"
      ;;
  esac
}

run_bb_verify_rejects() {
  local log_name="$1"
  shift

  local log_path status
  log_path="${LOG_DIR}/${log_name}.log"
  set +e
  "${BB}" verify -c "${BB_CRS_DIR}" "$@" >"${log_path}" 2>&1
  status=$?
  set -e

  if ((status == 0)); then
    cat "${log_path}" >&2
    fail "bb ${log_name} was expected to reject an invalid proof"
  fi
  if ! grep -Fq "Proof verification failed" "${log_path}"; then
    cat "${log_path}" >&2
    fail "bb ${log_name} failed without the reviewed invalid-proof verifier message"
  fi
}

mutate_witness_field() {
  local source="$1"
  local target="$2"
  local witness_index="$3"
  local replacement="$4"

  node -e '
const fs = require("node:fs");
const zlib = require("node:zlib");
const source = process.argv[1];
const target = process.argv[2];
const witnessIndex = Number(process.argv[3]);
const replacement = BigInt(process.argv[4]);
if (!Number.isInteger(witnessIndex) || witnessIndex < 0 || witnessIndex > 127) {
  process.exit(2);
}
if (replacement < 0n || replacement > ((1n << 256n) - 1n)) {
  process.exit(3);
}
const inflated = zlib.gunzipSync(fs.readFileSync(source));
if (inflated.length < 36 || inflated[0] !== 3) {
  process.exit(4);
}
let offset = -1;
for (let index = 0; index + 34 < inflated.length; index += 1) {
  if (
    inflated[index] === witnessIndex &&
    inflated[index + 1] === 0xc4 &&
    inflated[index + 2] === 0x20
  ) {
    offset = index + 3;
    break;
  }
}
if (offset < 0) {
  process.exit(5);
}
for (let index = 0; index < 32; index += 1) {
  inflated[offset + index] = 0;
}
let remaining = replacement;
for (let index = 31; index >= 0; index -= 1) {
  inflated[offset + index] = Number(remaining & 0xffn);
  remaining >>= 8n;
}
fs.writeFileSync(target, zlib.gzipSync(inflated));
' "${source}" "${target}" "${witness_index}" "${replacement}" ||
    fail "unable to mutate witness ${source}"
}

mutate_witness_fields() {
  local source="$1"
  local target="$2"
  shift 2

  if ((("$#" == 0) || ("$#" % 2 != 0))); then
    fail "witness mutation requires index/value pairs"
  fi
  cp "${source}" "${target}"
  while (("$#" > 0)); do
    mutate_witness_field "${target}" "${target}" "$1" "$2"
    shift 2
  done
}

copy_circuit_fixture() {
  local fixture_rel="$1"
  local case_name="$2"
  local source_root target_root

  source_root="${ROOT}/${fixture_rel}"
  target_root="${LOG_DIR}/${case_name}"
  rm -rf "${target_root}"
  mkdir -p "${target_root}"
  cp -R "${source_root}/." "${target_root}/"
  printf '%s\n' "${target_root}"
}

mutate_private_persona_negated_point() {
  local prover_toml="$1"

  # JavaScript template literals must reach Node without shell expansion.
  # shellcheck disable=SC2016
  node -e '
const fs = require("node:fs");
const p256Prime = (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n;
const path = process.argv[1];
let source = fs.readFileSync(path, "utf8");
const arrayFor = (name) => {
  const match = source.match(new RegExp(`^${name} = \\[([^\\n]+)\\]$`, "m"));
  if (match === null) {
    process.exit(2);
  }
  const values = match[1].split(",").map((value) => Number(value.trim()));
  if (values.length !== 32 || values.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    process.exit(3);
  }
  return values;
};
const bytesToBigInt = (bytes) => bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const bigIntToBytes = (value) => {
  const bytes = new Array(32).fill(0);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
};
const subjectX = arrayFor("pk_subject_x");
const subjectY = arrayFor("pk_subject_y");
const negatedY = bigIntToBytes((p256Prime - bytesToBigInt(subjectY)) % p256Prime);
source = source.replace(/^pk_persona_x = \[[^\n]+\]$/m, `pk_persona_x = [${subjectX.join(",")}]`);
source = source.replace(/^pk_persona_y = \[[^\n]+\]$/m, `pk_persona_y = [${negatedY.join(",")}]`);
fs.writeFileSync(path, source);
' "${prover_toml}" || fail "unable to mutate private persona point"
}

mutate_toml_scalar() {
  local prover_toml="$1"
  local field_name="$2"
  local replacement="$3"

  # JavaScript template literals must reach Node without shell expansion.
  # shellcheck disable=SC2016
  node -e '
const fs = require("node:fs");
const path = process.argv[1];
const fieldName = process.argv[2];
const replacement = process.argv[3];
if (!/^[a-z_]+$/.test(fieldName) || !/^[0-9]+$/.test(replacement)) {
  process.exit(2);
}
let source = fs.readFileSync(path, "utf8");
const pattern = new RegExp(`^${fieldName} = [0-9]+$`, "m");
if (!pattern.test(source)) {
  process.exit(3);
}
source = source.replace(pattern, `${fieldName} = ${replacement}`);
fs.writeFileSync(path, source);
' "${prover_toml}" "${field_name}" "${replacement}" ||
    fail "unable to mutate ${field_name} in ${prover_toml}"
}

run_nargo_execute_rejects_in_dir() {
  local fixture_dir="$1"
  local log_name="$2"
  local expected_message="$3"
  local log_path status

  log_path="${LOG_DIR}/${log_name}.log"
  set +e
  (
    cd "${fixture_dir}"
    HOME="${ISOLATED_HOME}" XDG_CACHE_HOME="${ISOLATED_CACHE}" "${NARGO}" execute
  ) >"${log_path}" 2>&1
  status=$?
  set -e

  if ((status == 0)); then
    cat "${log_path}" >&2
    fail "${log_name} was expected to fail"
  fi
  if ! grep -Fq "${expected_message}" "${log_path}"; then
    cat "${log_path}" >&2
    fail "${log_name} failed without reviewed assertion: ${expected_message}"
  fi
}

run_private_persona_negated_subject_regression() {
  local fixture_dir

  fixture_dir="$(copy_circuit_fixture \
    "circuits/sha256/families/private_persona_claim_v1/claim" \
    "private-persona-negated-subject")"
  mutate_private_persona_negated_point "${fixture_dir}/Prover.toml"
  run_nargo_execute_rejects_in_dir \
    "${fixture_dir}" \
    "private-persona-negated-subject.execute" \
    "private persona x must differ from credential subject x"
}

run_high_index_bit_regression() {
  local fixture_dir

  fixture_dir="$(copy_circuit_fixture \
    "circuits/sha256/families/credential_subject_claim_v1/claim" \
    "private-claim-high-index-bits")"
  # Every index bit selects a side at one level of the fixed-depth tree, so
  # a changed high bit must change the recomputed root.
  mutate_toml_scalar "${fixture_dir}/Prover.toml" "index" "4"
  run_nargo_execute_rejects_in_dir \
    "${fixture_dir}" \
    "private-claim-high-index-bits.execute" \
    "merkle root mismatch"
  # An index outside the 64-leaf tree is rejected by its range check.
  mutate_toml_scalar "${fixture_dir}/Prover.toml" "index" "64"
  run_nargo_execute_rejects_in_dir \
    "${fixture_dir}" \
    "private-claim-index-out-of-range.execute" \
    "index exceeds path depth"
}

run_fixture_with_tamper() {
  local fixture_rel="$1"
  local package_name="$2"
  local fixture_name fixture_root artifact witness workdir
  shift 2

  fixture_name="${fixture_rel//\//__}"
  fixture_root="${ROOT}/${fixture_rel}"
  artifact="${fixture_root}/target/${package_name}.json"
  witness="${fixture_root}/target/${package_name}.gz"
  workdir="${LOG_DIR}/${fixture_name}.bb"

  run_nargo "${fixture_rel}" "compile"
  run_nargo "${fixture_rel}" "execute"
  rm -rf "${workdir}"
  mkdir -p "${workdir}"
  run_bb "success" "${fixture_name}.write-vk" \
    write_vk -b "${artifact}" -o "${workdir}/vk"
  run_bb "success" "${fixture_name}.prove" \
    prove -b "${artifact}" -w "${witness}" -o "${workdir}/proof" -k "${workdir}/vk/vk"
  run_bb "success" "${fixture_name}.verify" \
    verify -k "${workdir}/vk/vk" -p "${workdir}/proof/proof" -i "${workdir}/proof/public_inputs"
  mutate_witness_fields "${witness}" "${workdir}/tampered-witness.gz" "$@"
  run_bb_prove_rejects "${fixture_name}.tampered-prove" "${workdir}/rejected-proof" \
    -b "${artifact}" -w "${workdir}/tampered-witness.gz" \
    -k "${workdir}/vk/vk"
  mutate_proof_bytes "${workdir}/proof/proof" "${workdir}/tampered-proof"
  run_bb_verify_rejects "${fixture_name}.tampered-verify" \
    -k "${workdir}/vk/vk" -p "${workdir}/tampered-proof" \
    -i "${workdir}/proof/public_inputs"
}

if [[ -z "${NARGO:-}" ]]; then
  fail "NARGO must point at the pinned modern nargo executable"
fi
if [[ -z "${BB:-}" ]]; then
  fail "BB must point at the pinned modern bb executable"
fi
if [[ -z "${BB_CRS_DIR:-}" || "${BB_CRS_DIR}" != /* || ! -d "${BB_CRS_DIR}" || -L "${BB_CRS_DIR}" ]]; then
  fail "BB_CRS_DIR must name a plain absolute CRS directory"
fi
if [[ ! -x "${NARGO}" || ! -x "${BB}" ]]; then
  fail "NARGO and BB must be executable"
fi
if [[ ! -f "${TOOLCHAIN_LOCK}" ]]; then
  fail "toolchain lock is missing"
fi

candidate_version="$(lock_value "candidateMatchedPair.noir.version")" ||
  fail "candidate Noir version is missing"
candidate_revision="$(lock_value "candidateMatchedPair.noir.revision")" ||
  fail "candidate Noir revision is missing"
platform="$(platform_key)"
expected_nargo_sha256="$(lock_value "candidateMatchedPair.localBinaryIdentities.${platform}.nargoExecutableSha256")" ||
  fail "candidate nargo hash is missing for ${platform}"
observed_nargo_sha256="$(sha256_file "${NARGO}")"
if [[ "${observed_nargo_sha256}" != "${expected_nargo_sha256}" ]]; then
  fail "NARGO hash does not match circuits/toolchain-lock.json"
fi
expected_bb_sha256="$(lock_value "candidateMatchedPair.localBinaryIdentities.${platform}.barretenbergExecutableSha256")" ||
  fail "candidate bb hash is missing for ${platform}"
if [[ "$(sha256_file "${BB}")" != "${expected_bb_sha256}" ]]; then
  fail "BB hash does not match circuits/toolchain-lock.json"
fi
expected_bb_version="$(lock_value "candidateMatchedPair.barretenberg.aztecPackagesVersion")" ||
  fail "candidate bb version is missing"
if [[ "$("${BB}" --version)" != "${expected_bb_version}" ]]; then
  fail "BB version does not match circuits/toolchain-lock.json"
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

version_output="$("${NARGO}" --version)"
case "${version_output}" in
  *"nargo version = ${candidate_version}"*"noirc version = ${candidate_version}+${candidate_revision}"*) ;;
  *)
    printf '%s\n' "${version_output}" >&2
    fail "NARGO version does not match circuits/toolchain-lock.json"
    ;;
esac

mkdir -p "${ISOLATED_HOME}" "${ISOLATED_CACHE}" "${LOG_DIR}"

run_fixture_with_tamper \
  "circuits/security-regressions/field-to-u128-zero-branch" \
  "reallyme_field_to_u128_zero_branch_regression" \
  1 \
  2 \
  2 \
  64323764613183177041862057485226039389 \
  3 \
  53438638232309528389504892708671455233 \
  10 \
  2
run_fixture_with_tamper \
  "circuits/security-regressions/acir-five-distinct-witnesses" \
  "reallyme_acir_five_distinct_witnesses_regression" \
  0 \
  1
run_private_persona_negated_subject_regression
run_high_index_bit_regression

printf 'modern soundness regression gate passed for Noir %s at %s\n' \
  "${candidate_version}" "${candidate_revision}"
