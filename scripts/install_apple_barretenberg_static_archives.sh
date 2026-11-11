#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STACK_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"
ARCHIVE_ROOT="${REALLYME_ZK_APPLE_STATIC_ARCHIVE_ROOT:-${STACK_ROOT}/apple-static-archives}"
LIB_ROOT="${REALLYME_ZK_APPLE_STATIC_LIB_ROOT:-${STACK_ROOT}/apple-static-libs}"
AZTEC_DOWNLOAD_BASE_URL="${AZTEC_DOWNLOAD_BASE_URL:-https://github.com/AztecProtocol/aztec-packages/releases/download/v6.0.0}"

fail() {
  echo "Apple Barretenberg static archive installation failed: $1" >&2
  exit 2
}

sha256_file() {
  if [[ ! -f "$1" ]]; then
    fail "missing file $1"
  fi
  shasum -a 256 "$1" | awk '{ print $1 }'
}

require_hash() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(sha256_file "${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    fail "${path} has SHA-256 ${actual}"
  fi
}

install_static_library() {
  local archive_name="$1"
  local archive_sha256="$2"
  local platform_name="$3"
  local library_sha256="$4"
  local archive_path="${ARCHIVE_ROOT}/${archive_name}"
  local output_dir="${LIB_ROOT}/${platform_name}"
  local output_library="${output_dir}/libbb-external.a"
  local temporary_dir

  if [[ -f "${output_library}" && "$(sha256_file "${output_library}")" == "${library_sha256}" ]]; then
    return
  fi

  mkdir -p "${ARCHIVE_ROOT}" "${output_dir}"
  if [[ ! -f "${archive_path}" || "$(sha256_file "${archive_path}")" != "${archive_sha256}" ]]; then
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      --output "${archive_path}.download" \
      "${AZTEC_DOWNLOAD_BASE_URL}/${archive_name}"
    require_hash "${archive_path}.download" "${archive_sha256}"
    mv "${archive_path}.download" "${archive_path}"
  fi
  require_hash "${archive_path}" "${archive_sha256}"

  temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-zk-apple-bb.XXXXXX")"
  trap 'rm -rf "${temporary_dir}"' RETURN
  tar -xzf "${archive_path}" -C "${temporary_dir}"
  if [[ ! -f "${temporary_dir}/libbb-external.a" ]]; then
    fail "${archive_name} did not contain libbb-external.a"
  fi
  require_hash "${temporary_dir}/libbb-external.a" "${library_sha256}"
  rm -f "${output_library}"
  mv "${temporary_dir}/libbb-external.a" "${output_library}"
  chmod 0644 "${output_library}"
  rm -rf "${temporary_dir}"
  trap - RETURN
}

install_static_library \
  "barretenberg-static-arm64-darwin.tar.gz" \
  "310b2baaee0f8c8a96725d9cc246ffd41243ed8606965ad0c87f99428288d964" \
  "darwinArm64" \
  "c554fc906e3d306946cb0620b2f5ee1d434fc0f7c02d9b2a56abd6b64b65ef87"
install_static_library \
  "barretenberg-static-arm64-ios.tar.gz" \
  "c7350fb21963da64d59d1b94835dfcdf71a78ea05752ed56af7004e5fa7f671d" \
  "iosArm64" \
  "5f6fce5ef64354e0307a1adcde0e7ac7349ddc6164c43d75f1471b39ae1fdde3"
install_static_library \
  "barretenberg-static-arm64-ios-sim.tar.gz" \
  "5ca108540b0cf88731cb6e6c3017eb630efbcfa3091c234971b78f0fb012f494" \
  "iosSimulatorArm64" \
  "68ac9359b2a859a8e975e2db4c91e188280711b13b4bf70e632a96497520511b"

printf 'MACOS_BB_LIB_DIR=%s\n' "${LIB_ROOT}/darwinArm64"
printf 'IOS_BB_LIB_DIR=%s\n' "${LIB_ROOT}/iosArm64"
printf 'IOS_SIM_BB_LIB_DIR=%s\n' "${LIB_ROOT}/iosSimulatorArm64"
