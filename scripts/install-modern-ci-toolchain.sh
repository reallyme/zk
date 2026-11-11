#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOCK="${ROOT}/circuits/toolchain-lock.json"
DEST="${1:?pass an absolute destination directory}"

fail() {
  printf 'modern CI toolchain installation failed: %s\n' "$1" >&2
  exit 2
}

if [[ "${DEST}" != /* ]]; then
  fail "destination must be an absolute path"
fi
for command in node curl date shasum tar; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is unavailable"
done

lock_value() {
  node -e '
const fs = require("node:fs");
const keys = process.argv[2].split("/");
let value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const key of keys) {
  if (value === null || typeof value !== "object" || !(key in value)) process.exit(2);
  value = value[key];
}
if (typeof value !== "number" && typeof value !== "string") process.exit(2);
process.stdout.write(String(value));
' "${LOCK}" "$1"
}

download_pinned() {
  local url="$1" target="$2" size="$3" digest="$4"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --proto-redir '=https' \
    --retry 3 --output "${target}" "${url}"
  [[ "$(wc -c < "${target}" | tr -d ' ')" == "${size}" ]] || fail "downloaded size differs from lock"
  [[ "$(shasum -a 256 "${target}" | awk '{ print $1 }')" == "${digest}" ]] ||
    fail "downloaded hash differs from lock"
}

platform_key() {
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) printf 'darwinArm64' ;;
    Linux:x86_64) printf 'linuxX86_64' ;;
    *) fail "this installer supports only Darwin arm64 and Linux x86_64" ;;
  esac
}

noir_archive_for_platform() {
  case "$1" in
    darwinArm64) printf 'noir-aarch64-apple-darwin.tar.gz' ;;
    linuxX86_64) printf 'noir-x86_64-unknown-linux-gnu.tar.gz' ;;
    *) fail "unsupported Noir platform" ;;
  esac
}

bb_archive_for_platform() {
  case "$1" in
    darwinArm64) printf 'barretenberg-arm64-darwin.tar.gz' ;;
    linuxX86_64) printf 'barretenberg-amd64-linux.tar.gz' ;;
    *) fail "unsupported Barretenberg platform" ;;
  esac
}

bb_static_archive_for_platform() {
  case "$1" in
    darwinArm64) printf 'barretenberg-static-arm64-darwin.tar.gz' ;;
    linuxX86_64) printf 'barretenberg-static-amd64-linux.tar.gz' ;;
    *) fail "unsupported Barretenberg static-library platform" ;;
  esac
}

verify_installed_file() {
  local path="$1" size="$2" digest="$3"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "installed toolchain file is missing"
  [[ "$(wc -c < "${path}" | tr -d ' ')" == "${size}" ]] ||
    fail "installed toolchain file size differs from lock"
  [[ "$(shasum -a 256 "${path}" | awk '{ print $1 }')" == "${digest}" ]] ||
    fail "installed toolchain file hash differs from lock"
}

verify_installed_digest() {
  local path="$1" digest="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "installed toolchain file is missing"
  [[ "$(shasum -a 256 "${path}" | awk '{ print $1 }')" == "${digest}" ]] ||
    fail "installed toolchain file hash differs from lock"
}

platform="$(platform_key)"
static_library_key="${platform}"
if [[ "${platform}" == 'linuxX86_64' ]]; then
  static_library_key='linuxAmd64'
fi
noir_archive="$(noir_archive_for_platform "${platform}")"
bb_archive="$(bb_archive_for_platform "${platform}")"
bb_static_archive="$(bb_static_archive_for_platform "${platform}")"
crs_key="candidateMatchedPair/barretenberg/crsIdentities/bn254FullProver1048577Points"
if [[ -e "${DEST}" || -L "${DEST}" ]]; then
  [[ -d "${DEST}" && ! -L "${DEST}" ]] || fail "existing destination is not a plain directory"
  for directory in "${DEST}/bin" "${DEST}/crs" "${DEST}/lib" "${DEST}/lib/${platform}"; do
    [[ -d "${directory}" && ! -L "${directory}" ]] ||
      fail "installed toolchain directory is missing or is a symlink"
  done
  verify_installed_file "${DEST}/${noir_archive}" \
    "$(lock_value "candidateMatchedPair/noir/archives/${noir_archive}/size")" \
    "$(lock_value "candidateMatchedPair/noir/archives/${noir_archive}/sha256")"
  verify_installed_file "${DEST}/${bb_archive}" \
    "$(lock_value "candidateMatchedPair/barretenberg/cliArchives/${bb_archive}/size")" \
    "$(lock_value "candidateMatchedPair/barretenberg/cliArchives/${bb_archive}/sha256")"
  verify_installed_file "${DEST}/${bb_static_archive}" \
    "$(lock_value "candidateMatchedPair/barretenberg/archives/${bb_static_archive}/size")" \
    "$(lock_value "candidateMatchedPair/barretenberg/archives/${bb_static_archive}/sha256")"
  verify_installed_digest "${DEST}/bin/nargo" \
    "$(lock_value "candidateMatchedPair/localBinaryIdentities/${platform}/nargoExecutableSha256")"
  verify_installed_digest "${DEST}/bin/bb" \
    "$(lock_value "candidateMatchedPair/localBinaryIdentities/${platform}/barretenbergExecutableSha256")"
  verify_installed_file "${DEST}/lib/${platform}/libbb-external.a" \
    "$(lock_value "candidateMatchedPair/barretenberg/extractedStaticLibraries/${static_library_key}/size")" \
    "$(lock_value "candidateMatchedPair/barretenberg/extractedStaticLibraries/${static_library_key}/sha256")"
  verify_installed_file "${DEST}/crs/bn254_g1.dat" \
    "$(lock_value "${crs_key}/g1SourceBytes")" \
    "$(lock_value "${crs_key}/g1SourceSha256")"
  verify_installed_file "${DEST}/crs/bn254_g2.dat" \
    "$(lock_value "${crs_key}/g2Bytes")" \
    "$(lock_value "${crs_key}/g2Sha256")"
  [[ -f "${DEST}/crs/download-receipt.tsv" && ! -L "${DEST}/crs/download-receipt.tsv" ]] ||
    fail "installed CRS provenance receipt is missing"
  printf 'Pinned modern toolchain and full-prover CRS verified at %s\n' "${DEST}"
  exit 0
fi

mkdir -m 0700 "${DEST}"
mkdir -m 0700 "${DEST}/bin" "${DEST}/crs"
nargo_base="$(lock_value candidateMatchedPair/noir/downloadBaseUrl)"
bb_base="$(lock_value candidateMatchedPair/barretenberg/downloadBaseUrl)"
download_pinned "${nargo_base}${noir_archive}" "${DEST}/${noir_archive}" \
  "$(lock_value "candidateMatchedPair/noir/archives/${noir_archive}/size")" \
  "$(lock_value "candidateMatchedPair/noir/archives/${noir_archive}/sha256")"
download_pinned "${bb_base}${bb_archive}" "${DEST}/${bb_archive}" \
  "$(lock_value "candidateMatchedPair/barretenberg/cliArchives/${bb_archive}/size")" \
  "$(lock_value "candidateMatchedPair/barretenberg/cliArchives/${bb_archive}/sha256")"
download_pinned "${bb_base}${bb_static_archive}" "${DEST}/${bb_static_archive}" \
  "$(lock_value "candidateMatchedPair/barretenberg/archives/${bb_static_archive}/size")" \
  "$(lock_value "candidateMatchedPair/barretenberg/archives/${bb_static_archive}/sha256")"

tar -xzf "${DEST}/${noir_archive}" -C "${DEST}/bin" --no-same-owner --no-same-permissions
tar -xzf "${DEST}/${bb_archive}" -C "${DEST}/bin" --no-same-owner --no-same-permissions
mkdir -m 0700 "${DEST}/lib" "${DEST}/lib/${platform}"
tar -xzf "${DEST}/${bb_static_archive}" -C "${DEST}/lib/${platform}" \
  --no-same-owner --no-same-permissions
static_lib="${DEST}/lib/${platform}/libbb-external.a"
[[ -f "${static_lib}" && ! -L "${static_lib}" ]] ||
  fail "static archive did not contain a plain Barretenberg library"
[[ "$(wc -c < "${static_lib}" | tr -d ' ')" == \
  "$(lock_value "candidateMatchedPair/barretenberg/extractedStaticLibraries/${static_library_key}/size")" ]] ||
  fail "Barretenberg static library size differs from lock"
[[ "$(shasum -a 256 "${static_lib}" | awk '{ print $1 }')" == \
  "$(lock_value "candidateMatchedPair/barretenberg/extractedStaticLibraries/${static_library_key}/sha256")" ]] ||
  fail "Barretenberg static library hash differs from lock"
for binary in nargo bb; do
  [[ -f "${DEST}/bin/${binary}" && ! -L "${DEST}/bin/${binary}" ]] ||
    fail "archive did not contain a plain executable"
done
[[ "$(shasum -a 256 "${DEST}/bin/nargo" | awk '{ print $1 }')" == \
  "$(lock_value "candidateMatchedPair/localBinaryIdentities/${platform}/nargoExecutableSha256")" ]] ||
  fail "nargo executable hash differs from lock"
[[ "$(shasum -a 256 "${DEST}/bin/bb" | awk '{ print $1 }')" == \
  "$(lock_value "candidateMatchedPair/localBinaryIdentities/${platform}/barretenbergExecutableSha256")" ]] ||
  fail "bb executable hash differs from lock"

g1_size="$(lock_value "${crs_key}/g1SourceBytes")"
g1_last="$((g1_size - 1))"
g1_effective_url="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --proto-redir '=https' \
  --retry 3 --range "0-${g1_last}" \
  --write-out '%{url_effective}' \
  --output "${DEST}/crs/bn254_g1.dat" \
  'https://crs.aztec-cdn.foundation/g1.dat')"
g1_retrieved_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
[[ "$(wc -c < "${DEST}/crs/bn254_g1.dat" | tr -d ' ')" == "${g1_size}" ]] ||
  fail "G1 source size differs from lock"
[[ "$(shasum -a 256 "${DEST}/crs/bn254_g1.dat" | awk '{ print $1 }')" == \
  "$(lock_value "${crs_key}/g1SourceSha256")" ]] ||
  fail "G1 source hash differs from lock"
g2_effective_url="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --proto-redir '=https' --retry 3 --write-out '%{url_effective}' \
  --output "${DEST}/crs/bn254_g2.dat" \
  'https://crs.aztec-cdn.foundation/g2.dat')"
g2_retrieved_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
[[ "$(wc -c < "${DEST}/crs/bn254_g2.dat" | tr -d ' ')" == \
  "$(lock_value "${crs_key}/g2Bytes")" ]] || fail "G2 source size differs from lock"
[[ "$(shasum -a 256 "${DEST}/crs/bn254_g2.dat" | awk '{ print $1 }')" == \
  "$(lock_value "${crs_key}/g2Sha256")" ]] || fail "G2 source hash differs from lock"
[[ "${g1_effective_url}" =~ ^https://[^[:space:]]+$ ]] ||
  fail "G1 download did not end at a recordable HTTPS URL"
[[ "${g2_effective_url}" =~ ^https://[^[:space:]]+$ ]] ||
  fail "G2 download did not end at a recordable HTTPS URL"

# Keep the source URL, retrieval time, byte count, and verified digest alongside
# the installed CRS so a package can be traced to its exact input bytes.
{
  printf 'asset\trequested_url\teffective_url\tretrieved_utc\tbytes\tsha256\n'
  printf 'bn254_g1.dat\thttps://crs.aztec-cdn.foundation/g1.dat\t%s\t%s\t%s\t%s\n' \
    "${g1_effective_url}" "${g1_retrieved_at}" "${g1_size}" \
    "$(lock_value "${crs_key}/g1SourceSha256")"
  printf 'bn254_g2.dat\thttps://crs.aztec-cdn.foundation/g2.dat\t%s\t%s\t%s\t%s\n' \
    "${g2_effective_url}" "${g2_retrieved_at}" "$(lock_value "${crs_key}/g2Bytes")" \
    "$(lock_value "${crs_key}/g2Sha256")"
} >"${DEST}/crs/download-receipt.tsv"

printf 'Pinned modern toolchain and full-prover CRS installed at %s\n' "${DEST}"
