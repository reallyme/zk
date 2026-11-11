#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STACK_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"
BUILD_DIR="${ROOT}/build/swift"
FRAMEWORK_SOURCE="${STACK_ROOT}/apple-platform-ffi/ReallyMeZKPlatformFFI.xcframework"
FRAMEWORK_BUILD_METADATA_SOURCE="${STACK_ROOT}/apple-platform-ffi/ReallyMeZKPlatformFFI.xcframework.build.tsv"
CHECKSUM_PATH="${BUILD_DIR}/ReallyMeZKPlatformFFI.xcframework.checksum"
BUILD_METADATA_PATH="${BUILD_DIR}/ReallyMeZKPlatformFFI.xcframework.build.tsv"

fail() {
  echo "Swift XCFramework build failed: $1" >&2
  exit 2
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required tool not found: $1"
  fi
}

for tool in cargo curl ditto find mkdir node shasum swift touch xcodebuild zip; do
  require_tool "${tool}"
done

export MACOS_BB_LIB_DIR="${MACOS_BB_LIB_DIR:-${STACK_ROOT}/apple-static-libs/darwinArm64}"
export IOS_BB_LIB_DIR="${IOS_BB_LIB_DIR:-${STACK_ROOT}/apple-static-libs/iosArm64}"
export IOS_SIM_BB_LIB_DIR="${IOS_SIM_BB_LIB_DIR:-${STACK_ROOT}/apple-static-libs/iosSimulatorArm64}"

if [[ ! -f "${MACOS_BB_LIB_DIR}/libbb-external.a" ||
  ! -f "${IOS_BB_LIB_DIR}/libbb-external.a" ||
  ! -f "${IOS_SIM_BB_LIB_DIR}/libbb-external.a" ]]; then
  "${ROOT}/scripts/install_apple_barretenberg_static_archives.sh" >/dev/null
fi

"${ROOT}/scripts/build_apple_platform_ffi_xcframework.sh"
"${ROOT}/scripts/check-apple-platform-ffi-freshness.sh"

mkdir -p "${BUILD_DIR}"
PACKAGE_DIR="$(mktemp -d "${BUILD_DIR}/.package.XXXXXX")"
trap 'rm -rf "${PACKAGE_DIR}"' EXIT
ditto "${FRAMEWORK_SOURCE}" "${PACKAGE_DIR}/ReallyMeZKPlatformFFI.xcframework"
ZIP_PATH="${PACKAGE_DIR}/ReallyMeZKPlatformFFI.xcframework.zip"
cp "${FRAMEWORK_BUILD_METADATA_SOURCE}" "${BUILD_METADATA_PATH}"

(
  cd "${PACKAGE_DIR}"
  # Keep the released DOS timestamp and make ZIP bytes independent of host TZ.
  export TZ=UTC
  find "ReallyMeZKPlatformFFI.xcframework" -exec touch -t 198001010100 {} +
  find "ReallyMeZKPlatformFFI.xcframework" -print \
    | LC_ALL=C sort \
    | zip -X -q "ReallyMeZKPlatformFFI.xcframework.zip" -@
)
swift package compute-checksum "${ZIP_PATH}" >"${CHECKSUM_PATH}"
R2_ZIP_PATH="$(node "${ROOT}/scripts/release-artifact-manifest.mjs" swiftpm/ReallyMeZKPlatformFFI.xcframework.zip "$(cat "${CHECKSUM_PATH}")")"
mkdir -p "$(dirname "${R2_ZIP_PATH}")"
mv "${ZIP_PATH}" "${R2_ZIP_PATH}"
ZIP_PATH="${R2_ZIP_PATH}"
printf 'SwiftPM artifact: %s\n' "${ZIP_PATH}"
printf 'SwiftPM checksum: %s\n' "$(cat "${CHECKSUM_PATH}")"
