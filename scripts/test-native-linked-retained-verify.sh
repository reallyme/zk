#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${REALLYME_BARRETENBERG_LIB_DIR:?must point to the directory containing pinned libbb-external.a}"
: "${REALLYME_RETAINED_VERIFY_COMMAND:?must point to the retained CircuitVerify MessagePack command}"
: "${REALLYME_BN254_G1_PATH:?must point to the canonical BN254 G1 transcript}"
: "${REALLYME_BN254_G2_PATH:?must point to the canonical BN254 G2 point}"

export REALLYME_BARRETENBERG_LIB_DIR
export REALLYME_RETAINED_VERIFY_COMMAND
export REALLYME_BN254_G1_PATH
export REALLYME_BN254_G2_PATH
export REALLYME_NATIVE_RETAINED_VERIFY=1

cd "${ROOT_DIR}"
cargo test -p reallyme-zk-backend-bb --features native --test native_linked_retained_verify -- --nocapture
