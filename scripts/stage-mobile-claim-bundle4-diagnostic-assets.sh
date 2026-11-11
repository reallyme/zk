#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/release-artifacts/modern-v1-bb-6.0.0}"
OUTPUT_ARG="${1:-${LOCAL_ARTIFACT_ROOT}/ios-demo-resources/zk_demo}"
OUTPUT_PARENT="$(dirname "${OUTPUT_ARG}")"
mkdir -p "${OUTPUT_PARENT}"
OUTPUT_ROOT="$(
  cd "${OUTPUT_PARENT}"
  printf '%s/%s\n' "$(pwd -P)" "$(basename "${OUTPUT_ARG}")"
)"
LOCAL_BB_DIR="${REALLYME_BARRETENBERG_LIB_DIR:-${ROOT}/target/local-barretenberg-macos}"

fail() {
  echo "mobile claim_bundle_4 diagnostic asset staging failed: $1" >&2
  exit 2
}

case "${OUTPUT_ROOT}" in
  "${LOCAL_ARTIFACT_ROOT}/ios-demo-resources/zk_demo" | \
  "${ROOT}/packages/kotlin/demo-android/build/generated/reallyme-zk-claim-bundle4-diagnostic-assets")
    ;;
  *)
    fail "refusing to stage into unapproved target ${OUTPUT_ROOT}"
    ;;
esac

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
  REALLYME_ZK_ALL_CIRCUITS_V1_ROOT="${ROOT}/circuits" \
  REALLYME_ZK_CLAIM_BUNDLE4_DIAGNOSTIC_ASSET_ROOT="${OUTPUT_ROOT}" \
    cargo test \
      --locked \
      -p reallyme-zk-platform-ffi \
      --features diagnostic-exact-source \
      --test prepare_mobile_claim_bundle4_diagnostic \
      -- --ignored --exact prepare_mobile_claim_bundle4_diagnostic_assets
)

printf '%s\n' "${OUTPUT_ROOT}"
