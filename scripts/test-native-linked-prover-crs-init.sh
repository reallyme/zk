#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${REALLYME_BARRETENBERG_LIB_DIR:?set REALLYME_BARRETENBERG_LIB_DIR to the directory containing libbb-external.a}"
: "${REALLYME_BN254_G1_PATH:?set REALLYME_BN254_G1_PATH to bn254_g1.dat}"
: "${REALLYME_BN254_G2_PATH:?set REALLYME_BN254_G2_PATH to bn254_g2.dat}"

export REALLYME_NATIVE_PROVER_CRS_INIT=1

cd "${ROOT_DIR}"
cargo test \
  -p reallyme-zk-backend-bb \
  --features native \
  --test native_linked_prover_crs_init \
  -- --nocapture
