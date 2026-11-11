#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

EXPECTED_BUF_VERSION="1.75.0"
EXPECTED_BUFFA_VERSION="0.9.2"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"

BUF_VERSION="$(buf --version)"
if [ "${BUF_VERSION}" != "${EXPECTED_BUF_VERSION}" ]; then
  echo "buf version mismatch: expected ${EXPECTED_BUF_VERSION}; found ${BUF_VERSION}" >&2
  exit 1
fi

for generator in protoc-gen-buffa protoc-gen-buffa-packaging; do
  GENERATOR_VERSION="$("${generator}" --version 2>/dev/null || true)"
  if [ "${GENERATOR_VERSION}" != "${generator} ${EXPECTED_BUFFA_VERSION}" ]; then
    echo "${generator} version mismatch: expected ${EXPECTED_BUFFA_VERSION};" \
      "found ${GENERATOR_VERSION:-unavailable}" >&2
    exit 1
  fi
done

(
  cd "${REPO_ROOT}"
  buf generate . \
    --path crates/proto/proto/reallyme/zk/v1/manifest.proto \
    --path crates/proto/proto/reallyme/zk/v1/capabilities.proto
  node scripts/harden-zk-generated.mjs
  node scripts/normalize-zk-platform-generated-text.mjs
  cargo fmt --package reallyme-zk-proto
  node scripts/harden-zk-generated.mjs --check-idempotent
)
