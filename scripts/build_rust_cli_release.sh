#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT}/build/cli}"
METADATA_PATH="${OUTPUT_DIR}/reallyme-zk.build.tsv"
CARGO_PROFILE="${CARGO_PROFILE:-release}"
CLI_FEATURES="${CLI_FEATURES:-}"
CRATE="reallyme-zk-cli"
BIN="reallyme-zk"

fail() {
  echo "rust cli release build failed: $1" >&2
  exit 2
}

sha256_file() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

if [[ -z "${HOME:-}" || "${HOME}" != /* ]]; then
  fail "HOME must be an absolute path for source remapping"
fi

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) TARGET_TRIPLE="aarch64-apple-darwin" ;;
  *) fail "unsupported Rust CLI release host $(uname -s):$(uname -m)" ;;
esac

SOURCE_REMAP_FLAG="--remap-path-prefix=${HOME}=source-root"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="${ROOT}/${TARGET_DIR}"
fi
TARGET_BIN="${TARGET_DIR}/${TARGET_TRIPLE}/${CARGO_PROFILE}/${BIN}"

cargo_args=(
  build
  --locked
  --profile "${CARGO_PROFILE}"
  --target "${TARGET_TRIPLE}"
  -p "${CRATE}"
)
if [[ -n "${CLI_FEATURES}" ]]; then
  cargo_args+=(--features "${CLI_FEATURES}")
fi

(
  cd "${ROOT}"
  RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }${SOURCE_REMAP_FLAG}" \
    cargo "${cargo_args[@]}"
)

if [[ ! -f "${TARGET_BIN}" ]]; then
  fail "cargo did not produce ${TARGET_BIN}"
fi

mkdir -p "${OUTPUT_DIR}"
cp "${TARGET_BIN}" "${OUTPUT_DIR}/${BIN}"

if command -v strip >/dev/null 2>&1; then
  strip -x -S "${OUTPUT_DIR}/${BIN}" || fail "strip failed"
fi

if strings "${OUTPUT_DIR}/${BIN}" | grep -E '/Users/|Documents/GitHub|/private/tmp|/var/folders' >/dev/null; then
  fail "Rust CLI binary contains build-host paths"
fi

BINARY_SHA256="$(sha256_file "${OUTPUT_DIR}/${BIN}")"
R2_BIN="$(node "${ROOT}/scripts/release-artifact-manifest.mjs" rust-cli/darwin-arm64/reallyme-zk "${BINARY_SHA256}")"
mkdir -p "$(dirname "${R2_BIN}")"
mv "${OUTPUT_DIR}/${BIN}" "${R2_BIN}"

{
  printf 'key\tvalue\n'
  printf 'format\trust-cli-darwin-arm64-v1\n'
  printf 'cargo_profile\t%s\n' "${CARGO_PROFILE}"
  printf 'cargo_features\t%s\n' "${CLI_FEATURES:-none}"
  printf 'target_triple\t%s\n' "${TARGET_TRIPLE}"
  printf 'source_path_remapping\thome-to-source-root-v1\n'
  printf 'binary_sha256\t%s\n' "${BINARY_SHA256}"
} >"${METADATA_PATH}"

printf '%s\n' "${R2_BIN}"
