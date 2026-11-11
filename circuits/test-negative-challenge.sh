#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if (($# != 1)); then
  printf '%s\n' "usage: test-negative-challenge.sh CIRCUIT_DIRECTORY" >&2
  exit 2
fi

CIRCUIT_DIRECTORY="$1"
SOURCE_INPUTS="${CIRCUIT_DIRECTORY}/Prover.toml"
NEGATIVE_INPUTS="${CIRCUIT_DIRECTORY}/ProverInvalidChallenge.toml"

if [[ ! -f "${SOURCE_INPUTS}" || -e "${NEGATIVE_INPUTS}" ]]; then
  printf '%s\n' "error: circuit inputs are missing or the negative fixture already exists" >&2
  exit 1
fi

NEGATIVE_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/reallyme-zk-negative-challenge.XXXXXX")"

cleanup() {
  rm -f -- "${NEGATIVE_INPUTS}"
  rm -f -- "${NEGATIVE_OUTPUT}"
}
trap cleanup EXIT INT TERM

# Keep every signed field from the positive vector unchanged except the verifier
# challenge. The circuit must reject the all-zero challenge before a proof is
# produced, which protects against replay-style empty-session bindings.
awk '
  BEGIN {
    zero = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"
    replaced = 0
  }
  /^challenge = / {
    print "challenge = " zero
    replaced += 1
    next
  }
  { print }
  END {
    if (replaced != 1) {
      exit 1
    }
  }
' "${SOURCE_INPUTS}" >"${NEGATIVE_INPUTS}"

if (
  cd "${CIRCUIT_DIRECTORY}"
  nargo execute rejected-zero-challenge \
    --prover-name ProverInvalidChallenge \
    --deny-warnings >"${NEGATIVE_OUTPUT}" 2>&1
); then
  printf '%s\n' "error: circuit accepted a zero challenge" >&2
  exit 1
fi

if ! grep -Fq "challenge must be non-zero" "${NEGATIVE_OUTPUT}"; then
  printf '%s\n' "error: circuit failed for a reason other than the zero challenge" >&2
  exit 1
fi
