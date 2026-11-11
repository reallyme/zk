#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# The pinned Barretenberg API verifies a proof before returning it. A tampered
# witness must reach that rejection; a missing CRS, crash, or generic CLI error
# does not establish that the circuit constrains the witness correctly.
run_bb_prove_rejects() {
  local log_name="$1"
  local output_dir="$2"
  shift 2

  local log_path="${LOG_DIR}/${log_name}.log"
  local status=0
  "${BB}" prove -c "${BB_CRS_DIR}" -o "${output_dir}" "$@" >"${log_path}" 2>&1 || status=$?

  if [[ "${status}" != 1 ]] ||
    ! grep -Fq "Proof verification failed" "${log_path}" ||
    ! grep -Fq "Failed to verify the generated proof!" "${log_path}"; then
    cat "${log_path}" >&2
    fail "bb ${log_name} did not reject the witness through proof verification"
  fi
  if [[ -e "${output_dir}/proof" || -e "${output_dir}/public_inputs" ]]; then
    fail "bb ${log_name} left proof artifacts after rejecting the witness"
  fi
}

mutate_proof_bytes() {
  local source="$1"
  local target="$2"

  # Keep the valid proof's framing and length. Flipping a low byte in its
  # middle field exercises verifier rejection independently of prover checks.
  node -e '
const fs = require("node:fs");
const FIELD_BYTES = 32;
const MAX_PROOF_BYTES = 1024 * 1024;
const source = process.argv[1];
const target = process.argv[2];
const metadata = fs.lstatSync(source);
if (!metadata.isFile() || metadata.size < FIELD_BYTES ||
    metadata.size > MAX_PROOF_BYTES || metadata.size % FIELD_BYTES !== 0) {
  process.exit(2);
}
const proof = fs.readFileSync(source);
if (proof.length !== metadata.size) process.exit(2);
const fieldCount = proof.length / FIELD_BYTES;
const offset = Math.floor(fieldCount / 2) * FIELD_BYTES + FIELD_BYTES - 1;
proof[offset] ^= 1;
fs.writeFileSync(target, proof);
' "${source}" "${target}" || fail "unable to mutate proof bytes"
}
