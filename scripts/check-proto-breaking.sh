#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_PATH="crates/proto/baselines/reallyme-zk-v1.binpb"
BASELINE_SHA256="9334cca5712d0cf4e72a2e438947b7a3775b73a90b37a5de49a0bf67c82a3449"

cd "${ROOT_DIR}"

if [[ ! -f "${BASELINE_PATH}" ]]; then
  echo "protobuf compatibility baseline is unavailable" >&2
  exit 1
fi

ACTUAL_SHA256="$(shasum -a 256 "${BASELINE_PATH}" | awk '{print $1}')"
if [[ "${ACTUAL_SHA256}" != "${BASELINE_SHA256}" ]]; then
  echo "protobuf compatibility baseline digest mismatch" >&2
  exit 1
fi

buf breaking --against "${BASELINE_PATH}"

# The baseline protects additions too: an omitted new message would otherwise
# be removable later without tripping Buf's backward-compatibility check.
CURRENT_DESCRIPTOR="$(mktemp "${TMPDIR:-/tmp}/reallyme-zk-proto-baseline.XXXXXXXX")"
trap 'rm -f -- "${CURRENT_DESCRIPTOR}"' EXIT
buf build -o "${CURRENT_DESCRIPTOR}"
if ! cmp -s "${BASELINE_PATH}" "${CURRENT_DESCRIPTOR}"; then
  echo "protobuf compatibility baseline does not match the current schema" >&2
  exit 1
fi
