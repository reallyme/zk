#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if (($# != 1)); then
  printf '%s\n' "usage: test-negative-audience.sh CIRCUIT_DIRECTORY" >&2
  exit 2
fi

CIRCUIT_DIRECTORY="$1"
SOURCE_INPUTS="${CIRCUIT_DIRECTORY}/Prover.toml"
NEGATIVE_INPUTS="${CIRCUIT_DIRECTORY}/ProverInvalidAudience.toml"

if [[ ! -f "${SOURCE_INPUTS}" || -e "${NEGATIVE_INPUTS}" ]]; then
  printf '%s\n' "error: circuit inputs are missing or the negative fixture already exists" >&2
  exit 1
fi

NEGATIVE_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/reallyme-zk-negative-audience.XXXXXX")"

cleanup() {
  rm -f -- "${NEGATIVE_INPUTS}"
  rm -f -- "${NEGATIVE_OUTPUT}"
}
trap cleanup EXIT INT TERM

# Generate the negative case from the exact positive vector so every other
# signature and commitment remains unchanged. The circuit must reject the
# zero verifier identity before any backend proof is produced.
awk '
  BEGIN {
    zero = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"
    replaced = 0
  }
  /^audience_hash = / {
    print "audience_hash = " zero
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
  nargo execute rejected-zero-audience \
    --prover-name ProverInvalidAudience \
    --deny-warnings >"${NEGATIVE_OUTPUT}" 2>&1
); then
  printf '%s\n' "error: circuit accepted a zero audience hash" >&2
  exit 1
fi

if ! grep -Fq "audience hash must be non-zero" "${NEGATIVE_OUTPUT}"; then
  printf '%s\n' "error: circuit failed for a reason other than the zero audience hash" >&2
  exit 1
fi
