#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SNAPSHOT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-zk-proto-freshness.XXXXXX")"
trap 'rm -rf "${SNAPSHOT_DIR}"' EXIT

generated_paths=(
  "crates/proto/src/generated/buffa"
  "packages/swift/Sources/Generated/ReallyMeZkProtoGenerated"
  "gen/java/zk"
  "gen/kotlin/zk"
)

cd "${ROOT_DIR}"
for generated_path in "${generated_paths[@]}"; do
  if [[ ! -d "${generated_path}" ]]; then
    echo "generated protobuf freshness check failed: missing ${generated_path}" >&2
    exit 2
  fi
  mkdir -p "${SNAPSHOT_DIR}/$(dirname "${generated_path}")"
  cp -R "${generated_path}" "${SNAPSHOT_DIR}/${generated_path}"
done

scripts/generate-zk-platform-protos.sh

for generated_path in "${generated_paths[@]}"; do
  if ! diff -r -q "${SNAPSHOT_DIR}/${generated_path}" "${generated_path}" >/dev/null; then
    echo "generated protobuf freshness check failed: ${generated_path} differs from the pinned generators" >&2
    exit 2
  fi
done

echo "generated protobuf freshness check passed"
