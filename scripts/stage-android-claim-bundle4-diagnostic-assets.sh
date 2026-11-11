#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT_ARG="${1:-${ROOT}/packages/kotlin/demo-android/build/generated/reallyme-zk-claim-bundle4-diagnostic-assets}"
OUTPUT_PARENT="$(dirname "${OUTPUT_ARG}")"
mkdir -p "${OUTPUT_PARENT}"
OUTPUT_ROOT="$(
  cd "${OUTPUT_PARENT}"
  printf '%s/%s\n' "$(pwd -P)" "$(basename "${OUTPUT_ARG}")"
)"
LOCAL_BB_DIR="${REALLYME_BARRETENBERG_LIB_DIR:-${ROOT}/target/local-barretenberg-macos}"

fail() {
  echo "android claim_bundle_4 diagnostic asset staging failed: $1" >&2
  exit 2
}

if [[ ! -d "${LOCAL_BB_DIR}" ]]; then
  fail "REALLYME_BARRETENBERG_LIB_DIR does not name a directory"
fi
if [[ ! -f "${LOCAL_BB_DIR}/libbb-external.a" ]]; then
  fail "REALLYME_BARRETENBERG_LIB_DIR must contain libbb-external.a"
fi

mkdir -p "${OUTPUT_ROOT}"

(
  cd "${ROOT}"
  REALLYME_BARRETENBERG_LIB_DIR="${LOCAL_BB_DIR}" \
    "${ROOT}/scripts/stage-mobile-claim-bundle4-diagnostic-assets.sh" "${OUTPUT_ROOT}"
)

printf '%s\n' "${OUTPUT_ROOT}"
