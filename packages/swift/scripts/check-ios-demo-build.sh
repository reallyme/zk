#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

PACKAGE_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
ROOT="$(cd "${PACKAGE_ROOT}/../.." && pwd -P)"
DEMO_PROJECT="${PACKAGE_ROOT}/Examples/ReallyMeZKDemo/ReallyMeZKDemo.xcodeproj"
DERIVED_DATA_PATH="${ROOT}/target/ios-demo-derived-data"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"

node "${ROOT}/scripts/stage-demo-mobile-assets.mjs" \
  "${LOCAL_ARTIFACT_ROOT}/ios-demo-resources/zk_demo"
if [ "${REALLYME_ZK_CLAIM_BUNDLE4_DIAGNOSTIC:-}" = "1" ]; then
  "${ROOT}/scripts/stage-mobile-claim-bundle4-diagnostic-assets.sh" \
    "${LOCAL_ARTIFACT_ROOT}/ios-demo-resources/zk_demo"
fi

"${ROOT}/scripts/check-apple-platform-ffi-freshness.sh"

xcodebuild \
  -project "${DEMO_PROJECT}" \
  -scheme ReallyMeZKDemo \
  -sdk iphonesimulator27.2 \
  -destination "generic/platform=iOS Simulator" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO \
  build

DEMO_BINARY="$(
  find "${DERIVED_DATA_PATH}/Build/Products" \
    -path "*/ReallyMeZKDemo.app/ReallyMeZKDemo" \
    -type f \
    | head -n 1
)"
if [ -z "${DEMO_BINARY}" ]; then
  echo "ios demo build failed: app executable was not produced" >&2
  exit 2
fi

"${ROOT}/scripts/check-platform-ffi-symbols.sh" apple-linked "${DEMO_BINARY}"
