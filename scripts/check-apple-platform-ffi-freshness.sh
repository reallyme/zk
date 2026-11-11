#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/release-artifacts/modern-v1-bb-6.0.0}"
OUTPUT_DIR="${OUTPUT_DIR:-${LOCAL_ARTIFACT_ROOT}/apple-platform-ffi}"
XCFRAMEWORK_PATH="${OUTPUT_DIR}/ReallyMeZKPlatformFFI.xcframework"
METADATA_PATH="${OUTPUT_DIR}/ReallyMeZKPlatformFFI.xcframework.build.tsv"
HEADER_SOURCE="${ROOT}/crates/proto-codec/include/reallyme_zk_platform_abi.h"
MODULE_MAP_SOURCE="${ROOT}/crates/proto-codec/include/module.modulemap"
TOOLCHAIN_LOCK="${ROOT}/circuits/toolchain-lock.json"
EXPECTED_BARRETENBERG_VERSION="6.0.0"
EXPECTED_CARGO_PROFILE="mobile-release"
EXPECTED_CARGO_FEATURES="native"
EXPECTED_MACOS_DEPLOYMENT_TARGET="27.0"
EXPECTED_IOS_DEPLOYMENT_TARGET="18.0"
EXPECTED_MACOS_BB_LIB_SHA256="c554fc906e3d306946cb0620b2f5ee1d434fc0f7c02d9b2a56abd6b64b65ef87"
EXPECTED_IOS_BB_LIB_SHA256="5f6fce5ef64354e0307a1adcde0e7ac7349ddc6164c43d75f1471b39ae1fdde3"
EXPECTED_IOS_SIM_BB_LIB_SHA256="68ac9359b2a859a8e975e2db4c91e188280711b13b4bf70e632a96497520511b"

fail() {
  echo "apple platform ffi freshness check failed: $1" >&2
  exit 2
}

sha256_file() {
  if [[ ! -f "$1" ]]; then
    fail "missing file $1"
  fi
  shasum -a 256 "$1" | awk '{ print $1 }'
}

metadata_value() {
  local key="$1"
  awk -F '\t' -v key="${key}" '$1 == key { print $2; found = 1 } END { if (found != 1) exit 1 }' \
    "${METADATA_PATH}" || fail "metadata is missing ${key}"
}

require_toolchain_lock_pin() {
  local value="$1"
  if ! grep -Fq "\"${value}\"" "${TOOLCHAIN_LOCK}"; then
    fail "toolchain lock does not contain reviewed pin ${value}"
  fi
}

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

if [[ ! -d "${XCFRAMEWORK_PATH}" ]]; then
  fail "missing ${XCFRAMEWORK_PATH}; run scripts/build_apple_platform_ffi_xcframework.sh"
fi
if [[ ! -f "${METADATA_PATH}" ]]; then
  fail "missing build metadata; rebuild the Apple platform FFI XCFramework"
fi
if [[ "$(sed -n '1p' "${METADATA_PATH}")" != $'key\tvalue' ]]; then
  fail "metadata header is malformed"
fi
if [[ "$(metadata_value format)" != "apple-platform-ffi-xcframework-v4" ]]; then
  fail "metadata format is unsupported"
fi
if [[ "$(metadata_value cargo_profile)" != "${EXPECTED_CARGO_PROFILE}" ]]; then
  fail "XCFramework was not built with the reviewed mobile Cargo profile"
fi
if [[ "$(metadata_value cargo_features)" != "${EXPECTED_CARGO_FEATURES}" ]]; then
  fail "XCFramework was not built with the reviewed production Cargo feature set"
fi
if [[ "$(metadata_value macos_deployment_target)" != \
  "${EXPECTED_MACOS_DEPLOYMENT_TARGET}" ]]; then
  fail "XCFramework was not built for the reviewed macOS deployment target"
fi
if [[ "$(metadata_value ios_deployment_target)" != \
  "${EXPECTED_IOS_DEPLOYMENT_TARGET}" ]]; then
  fail "XCFramework was not built for the reviewed iOS deployment target"
fi
if [[ "$(metadata_value source_path_remapping)" != "home-to-source-root-v1" ]]; then
  fail "XCFramework was not built with portable source paths"
fi
require_toolchain_lock_pin "${EXPECTED_BARRETENBERG_VERSION}"
require_toolchain_lock_pin "${EXPECTED_MACOS_BB_LIB_SHA256}"
require_toolchain_lock_pin "${EXPECTED_IOS_BB_LIB_SHA256}"
require_toolchain_lock_pin "${EXPECTED_IOS_SIM_BB_LIB_SHA256}"
if [[ "$(metadata_value barretenberg_version)" != "${EXPECTED_BARRETENBERG_VERSION}" ]]; then
  fail "XCFramework metadata was built against the wrong Barretenberg version"
fi
if [[ "$(metadata_value macos_barretenberg_lib_sha256)" != "${EXPECTED_MACOS_BB_LIB_SHA256}" ]]; then
  fail "XCFramework metadata was built against the wrong macOS-arm64 Barretenberg library"
fi
if [[ "$(metadata_value ios_barretenberg_lib_sha256)" != "${EXPECTED_IOS_BB_LIB_SHA256}" ]]; then
  fail "XCFramework metadata was built against the wrong ios-arm64 Barretenberg library"
fi
if [[ "$(metadata_value ios_simulator_barretenberg_lib_sha256)" != \
  "${EXPECTED_IOS_SIM_BB_LIB_SHA256}" ]]; then
  fail "XCFramework metadata was built against the wrong ios-arm64-simulator Barretenberg library"
fi
if [[ "$(metadata_value source_closure_sha256)" != "$(source_closure_sha256)" ]]; then
  fail "source closure has changed since the XCFramework was built"
fi
if [[ "$(metadata_value header_sha256)" != "$(sha256_file "${HEADER_SOURCE}")" ]]; then
  fail "platform ABI header has changed since the XCFramework was built"
fi
if [[ "$(metadata_value module_map_sha256)" != "$(sha256_file "${MODULE_MAP_SOURCE}")" ]]; then
  fail "platform ABI module map has changed since the XCFramework was built"
fi
if [[ "$(metadata_value macos_arm64_archive_sha256)" != \
  "$(sha256_file "${XCFRAMEWORK_PATH}/macos-arm64/libreallyme_zk_platform_ffi.a")" ]]; then
  fail "macos-arm64 archive does not match build metadata"
fi
if [[ "$(metadata_value ios_arm64_archive_sha256)" != \
  "$(sha256_file "${XCFRAMEWORK_PATH}/ios-arm64/libreallyme_zk_platform_ffi.a")" ]]; then
  fail "ios-arm64 archive does not match build metadata"
fi
if [[ "$(metadata_value ios_arm64_simulator_archive_sha256)" != \
  "$(sha256_file "${XCFRAMEWORK_PATH}/ios-arm64-simulator/libreallyme_zk_platform_ffi.a")" ]]; then
  fail "ios-arm64-simulator archive does not match build metadata"
fi

echo "apple platform ffi freshness check passed"
