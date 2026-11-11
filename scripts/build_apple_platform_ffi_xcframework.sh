#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MACOS_BB_LIB_DIR="${MACOS_BB_LIB_DIR:-}"
IOS_BB_LIB_DIR="${IOS_BB_LIB_DIR:-}"
IOS_SIM_BB_LIB_DIR="${IOS_SIM_BB_LIB_DIR:-}"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/release-artifacts/modern-v1-bb-6.0.0}"
OUTPUT_DIR="${OUTPUT_DIR:-${LOCAL_ARTIFACT_ROOT}/apple-platform-ffi}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="${ROOT}/${TARGET_DIR}"
fi
CARGO_PROFILE="${CARGO_PROFILE:-mobile-release}"
PLATFORM_FFI_FEATURES="${PLATFORM_FFI_FEATURES:-native}"
MACOS_DEPLOYMENT_TARGET="27.0"
IOS_DEPLOYMENT_TARGET="18.0"
if [[ -z "${HOME:-}" || "${HOME}" != /* ]]; then
  echo "apple platform ffi build failed: HOME must be an absolute path for source remapping" >&2
  exit 2
fi
SOURCE_REMAP_FLAG="--remap-path-prefix=${HOME}=source-root"
HEADER_DIR="${OUTPUT_DIR}/include"
XCFRAMEWORK_PATH="${OUTPUT_DIR}/ReallyMeZKPlatformFFI.xcframework"
METADATA_PATH="${OUTPUT_DIR}/ReallyMeZKPlatformFFI.xcframework.build.tsv"
CRATE="reallyme-zk-platform-ffi"
HEADER_SOURCE="${ROOT}/crates/proto-codec/include/reallyme_zk_platform_abi.h"
MODULE_MAP_SOURCE="${ROOT}/crates/proto-codec/include/module.modulemap"
TOOLCHAIN_LOCK="${ROOT}/circuits/toolchain-lock.json"
EXPECTED_BARRETENBERG_VERSION="6.0.0"
EXPECTED_MACOS_BB_LIB_SHA256="c554fc906e3d306946cb0620b2f5ee1d434fc0f7c02d9b2a56abd6b64b65ef87"
EXPECTED_IOS_BB_LIB_SHA256="5f6fce5ef64354e0307a1adcde0e7ac7349ddc6164c43d75f1471b39ae1fdde3"
EXPECTED_IOS_SIM_BB_LIB_SHA256="68ac9359b2a859a8e975e2db4c91e188280711b13b4bf70e632a96497520511b"

fail() {
  echo "apple platform ffi build failed: $1" >&2
  exit 2
}

require_dir() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" ]]; then
    fail "${name} must be set"
  fi
  if [[ ! -d "${value}" ]]; then
    fail "${name} does not name a directory"
  fi
  if [[ ! -f "${value}/libbb-external.a" ]]; then
    fail "${name} must contain libbb-external.a"
  fi
}

require_dir MACOS_BB_LIB_DIR
require_dir IOS_BB_LIB_DIR
require_dir IOS_SIM_BB_LIB_DIR

sha256_file() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

require_toolchain_lock_pin() {
  local value="$1"
  if ! grep -Fq "\"${value}\"" "${TOOLCHAIN_LOCK}"; then
    fail "toolchain lock does not contain reviewed pin ${value}"
  fi
}

verify_bb_lib_identity() {
  local name="$1"
  local lib_dir="$2"
  local expected_sha256="$3"
  local actual_sha256
  actual_sha256="$(sha256_file "${lib_dir}/libbb-external.a")"
  if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
    fail "${name} libbb-external.a does not match circuits/toolchain-lock.json"
  fi
}

verify_archive_deployment_target() {
  local archive="$1"
  local expected_maximum="$2"
  local incompatible_target

  incompatible_target="$(
    otool -l "${archive}" | awk -v expected_maximum="${expected_maximum}" '
      function is_greater(actual, expected, actual_parts, expected_parts, component) {
        split(actual, actual_parts, ".")
        split(expected, expected_parts, ".")
        for (component = 1; component <= 3; component += 1) {
          if ((actual_parts[component] + 0) > (expected_parts[component] + 0)) {
            return 1
          }
          if ((actual_parts[component] + 0) < (expected_parts[component] + 0)) {
            return 0
          }
        }
        return 0
      }
      $1 == "minos" && is_greater($2, expected_maximum) {
        print $2
        exit
      }
    '
  )"
  if [[ -n "${incompatible_target}" ]]; then
    fail "archive contains an object requiring deployment target ${incompatible_target}, later than ${expected_maximum}"
  fi
}

require_toolchain_lock_pin "${EXPECTED_BARRETENBERG_VERSION}"
require_toolchain_lock_pin "${EXPECTED_MACOS_BB_LIB_SHA256}"
require_toolchain_lock_pin "${EXPECTED_IOS_BB_LIB_SHA256}"
require_toolchain_lock_pin "${EXPECTED_IOS_SIM_BB_LIB_SHA256}"
verify_bb_lib_identity \
  "MACOS_BB_LIB_DIR" \
  "${MACOS_BB_LIB_DIR}" \
  "${EXPECTED_MACOS_BB_LIB_SHA256}"
verify_bb_lib_identity "IOS_BB_LIB_DIR" "${IOS_BB_LIB_DIR}" "${EXPECTED_IOS_BB_LIB_SHA256}"
verify_bb_lib_identity \
  "IOS_SIM_BB_LIB_DIR" \
  "${IOS_SIM_BB_LIB_DIR}" \
  "${EXPECTED_IOS_SIM_BB_LIB_SHA256}"
if [[ "${PLATFORM_FFI_FEATURES}" != *native* ]]; then
  fail "PLATFORM_FFI_FEATURES must include native"
fi

source_closure_file_hash_lines() {
  (
    cd "${ROOT}"
    {
      printf '%s\n' Cargo.lock Cargo.toml circuits/toolchain-lock.json
      find \
        crates/api \
        crates/artifacts \
        crates/backend-bb \
        crates/noir-witness-core \
        crates/platform-ffi \
        crates/proto \
        crates/proto-codec \
        -type f \
        \( -name '*.rs' -o -name '*.toml' -o -name '*.cc' -o -name '*.h' -o -name '*.modulemap' \) \
        -not -path '*/tests/*' \
        -not -name 'tests.rs' \
        -not -name '*_tests.rs' \
        -not -path '*/src/bin/*' \
        -not -path '*/target/*' \
        -print
    } | LC_ALL=C sort | while IFS= read -r source_path; do
      printf '%s\t%s\n' "${source_path}" "$(sha256_file "${ROOT}/${source_path}")"
    done
  )
}

source_closure_sha256() {
  source_closure_file_hash_lines | shasum -a 256 | awk '{ print $1 }'
}

write_metadata() {
  {
    printf 'key\tvalue\n'
    printf 'format\tapple-platform-ffi-xcframework-v4\n'
    printf 'cargo_profile\t%s\n' "${CARGO_PROFILE}"
    printf 'cargo_features\t%s\n' "${PLATFORM_FFI_FEATURES}"
    printf 'macos_deployment_target\t%s\n' "${MACOS_DEPLOYMENT_TARGET}"
    printf 'ios_deployment_target\t%s\n' "${IOS_DEPLOYMENT_TARGET}"
    printf 'source_path_remapping\thome-to-source-root-v1\n'
    printf 'barretenberg_version\t%s\n' "${EXPECTED_BARRETENBERG_VERSION}"
    printf 'macos_barretenberg_lib_sha256\t%s\n' "${EXPECTED_MACOS_BB_LIB_SHA256}"
    printf 'ios_barretenberg_lib_sha256\t%s\n' "${EXPECTED_IOS_BB_LIB_SHA256}"
    printf 'ios_simulator_barretenberg_lib_sha256\t%s\n' "${EXPECTED_IOS_SIM_BB_LIB_SHA256}"
    printf 'source_closure_sha256\t%s\n' "$(source_closure_sha256)"
    printf 'header_sha256\t%s\n' "$(sha256_file "${HEADER_SOURCE}")"
    printf 'module_map_sha256\t%s\n' "$(sha256_file "${MODULE_MAP_SOURCE}")"
    printf 'macos_arm64_archive_sha256\t%s\n' \
      "$(sha256_file "${TARGET_DIR}/aarch64-apple-darwin/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a")"
    printf 'ios_arm64_archive_sha256\t%s\n' \
      "$(sha256_file "${TARGET_DIR}/aarch64-apple-ios/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a")"
    printf 'ios_arm64_simulator_archive_sha256\t%s\n' \
      "$(sha256_file "${TARGET_DIR}/aarch64-apple-ios-sim/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a")"
  } >"${METADATA_PATH}"
}

rm -rf "${OUTPUT_DIR}"
mkdir -p "${HEADER_DIR}"
cp "${HEADER_SOURCE}" "${HEADER_DIR}/reallyme_zk_platform_abi.h"
cp "${MODULE_MAP_SOURCE}" "${HEADER_DIR}/module.modulemap"

build_target() {
  local target="$1"
  local bb_lib_dir="$2"
  local target_cflags=""

  case "${target}" in
    aarch64-apple-darwin)
      target_cflags="-mmacosx-version-min=${MACOS_DEPLOYMENT_TARGET}"
      ;;
    aarch64-apple-ios)
      target_cflags="-miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}"
      ;;
    aarch64-apple-ios-sim)
      target_cflags="-mios-simulator-version-min=${IOS_DEPLOYMENT_TARGET}"
      ;;
  esac

  (
    cd "${ROOT}"
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" \
      IPHONEOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET}" \
      CFLAGS="${CFLAGS:+${CFLAGS} }${target_cflags}" \
      REALLYME_BARRETENBERG_LIB_DIR="${bb_lib_dir}" \
      RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }${SOURCE_REMAP_FLAG}" \
      cargo build \
        --profile "${CARGO_PROFILE}" \
        --locked \
        --target "${target}" \
        -p "${CRATE}" \
        --features "${PLATFORM_FFI_FEATURES}"
  )
}

build_target "aarch64-apple-darwin" "${MACOS_BB_LIB_DIR}"
build_target "aarch64-apple-ios" "${IOS_BB_LIB_DIR}"
build_target "aarch64-apple-ios-sim" "${IOS_SIM_BB_LIB_DIR}"

verify_archive_deployment_target \
  "${TARGET_DIR}/aarch64-apple-darwin/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  "${MACOS_DEPLOYMENT_TARGET}"
verify_archive_deployment_target \
  "${TARGET_DIR}/aarch64-apple-ios/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  "${IOS_DEPLOYMENT_TARGET}"
verify_archive_deployment_target \
  "${TARGET_DIR}/aarch64-apple-ios-sim/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  "${IOS_DEPLOYMENT_TARGET}"

"${ROOT}/scripts/check-platform-ffi-symbols.sh" \
  apple \
  "${TARGET_DIR}/aarch64-apple-darwin/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a"
"${ROOT}/scripts/check-platform-ffi-symbols.sh" \
  apple \
  "${TARGET_DIR}/aarch64-apple-ios/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a"
"${ROOT}/scripts/check-platform-ffi-symbols.sh" \
  apple \
  "${TARGET_DIR}/aarch64-apple-ios-sim/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a"

for target in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim; do
  archive="${TARGET_DIR}/${target}/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a"
  if strings "${archive}" | grep -F "${HOME}" >/dev/null; then
    fail "${target} archive contains a build-host home path"
  fi
done

xcodebuild -create-xcframework \
  -library "${TARGET_DIR}/aarch64-apple-darwin/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  -headers "${HEADER_DIR}" \
  -library "${TARGET_DIR}/aarch64-apple-ios/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  -headers "${HEADER_DIR}" \
  -library "${TARGET_DIR}/aarch64-apple-ios-sim/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  -headers "${HEADER_DIR}" \
  -output "${XCFRAMEWORK_PATH}"

write_metadata
printf '%s\n' "${XCFRAMEWORK_PATH}"
