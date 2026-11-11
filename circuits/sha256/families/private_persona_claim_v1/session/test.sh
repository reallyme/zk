#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if ! command -v nargo >/dev/null 2>&1; then
  echo "error: nargo is not installed or not in PATH" >&2
  exit 127
fi

if ! command -v bb >/dev/null 2>&1; then
  echo "error: bb is not installed or not in PATH" >&2
  exit 127
fi

PACKAGE_NAME="$(awk -F ' *= *' '$1 == "name" { gsub(/"/, "", $2); print $2; exit }' Nargo.toml)"
if [[ -z "${PACKAGE_NAME}" ]]; then
  echo "error: failed to read package name from Nargo.toml" >&2
  exit 1
fi

BYTECODE_PATH="target/${PACKAGE_NAME}.json"
WITNESS_PATH="target/${PACKAGE_NAME}.gz"

echo "[1/8] nargo compile"
nargo compile

echo "[2/8] nargo execute"
nargo execute

echo "[3/8] bb prove with ZK verification key"
rm -f target/proof/proof target/proof/public_inputs target/proof/vk target/vk/vk
mkdir -p target/proof target/vk
bb prove \
  -b "${BYTECODE_PATH}" \
  -w "${WITNESS_PATH}" \
  -o target/proof \
  --oracle_hash keccak \
  --zk \
  --write_vk

echo "[4/8] preserve ZK verification key"
cp target/proof/vk target/vk/vk

echo "[5/8] bb verify ZK proof"
bb verify \
  -k target/vk/vk \
  -p target/proof/proof \
  -i target/proof/public_inputs \
  --oracle_hash keccak \
  --zk

echo "[6/8] reject malformed verifier artifacts"
PROOF_TEST="${SCRIPT_DIR}/../../../../test-negative-proof.sh"
if [[ ! -x "${PROOF_TEST}" ]]; then
  echo "error: negative proof test helper is unavailable" >&2
  exit 1
fi
"${PROOF_TEST}" "${SCRIPT_DIR}"

echo "[7/8] reject zero audience"
AUDIENCE_TEST="${SCRIPT_DIR}/../../../../test-negative-audience.sh"
if [[ ! -x "${AUDIENCE_TEST}" ]]; then
  echo "error: negative audience test helper is unavailable" >&2
  exit 1
fi
"${AUDIENCE_TEST}" "${SCRIPT_DIR}"

echo "[8/8] reject zero challenge"
CHALLENGE_TEST="${SCRIPT_DIR}/../../../../test-negative-challenge.sh"
if [[ ! -x "${CHALLENGE_TEST}" ]]; then
  echo "error: negative challenge test helper is unavailable" >&2
  exit 1
fi
"${CHALLENGE_TEST}" "${SCRIPT_DIR}"

echo "ok: proof verified for ${PACKAGE_NAME}"
