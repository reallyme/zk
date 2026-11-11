#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if [[ "$#" -ne 1 || ( "$1" != "sha256" && "$1" != "poseidon2" ) ]]; then
  printf 'usage: %s sha256|poseidon2\n' "$0" >&2
  exit 2
fi

: "${BB_CRS_DIR:?BB_CRS_DIR must point to the pinned BN254 CRS directory}"
NARGO_BIN="${NARGO:-nargo}"
BB_BIN="${BB:-bb}"
LANE="$1"
ROOT="$(cd "$(dirname "$0")" && pwd)"
FAMILY="${ROOT}/${LANE}/families/common_credential_root_v1"
python3 "${ROOT}/check-common-credential-root-v1-derivation-vectors.py"
python3 "${ROOT}/check-common-credential-root-v1-commitment-vectors.py" "${LANE}"

# The existing split suite verifies assurance, exact-instance status, and both
# lineage proofs before any public inputs are composed with selected claims.
bash "${ROOT}/test-common-credential-root-assurance-parts.sh" "${LANE}"

# The signed credential-validity and private status opening are separate
# proof stages. Generate their exact VK beside the program before release
# identity checks; this proof must verify with the pinned CRS and backend.
issuer_status_package="${FAMILY}/issuer_credential_status"
issuer_status_name="credential_common_credential_root_v1_issuer_credential_status_${LANE}"
cd "${issuer_status_package}"
"${NARGO_BIN}" check
"${NARGO_BIN}" fmt --check
"${NARGO_BIN}" execute --prover-name Prover
BB="${BB_BIN}" bash "${ROOT}/prove-common-credential-root-with-vk.sh" \
  "${LANE}" "${issuer_status_name}" \
  "target/${issuer_status_name}.json" "target/${issuer_status_name}.gz" \
  "target/issuer-status-proof"
"${NARGO_BIN}" execute --prover-name ProverEmployer
BB="${BB_BIN}" bash "${ROOT}/prove-common-credential-root-with-vk.sh" \
  "${LANE}" "${issuer_status_name}" \
  "target/${issuer_status_name}.json" "target/${issuer_status_name}.gz" \
  "target/issuer-status-proof-employer"

prove_claim() {
  local mode="$1"
  local fixture="$2"
  local output="$3"
  local package="${FAMILY}/${mode}_persona_claim"
  local package_name="common_credential_root_v1_${LANE}_${mode}_persona_claim"
  cd "${package}"
  "${NARGO_BIN}" execute --prover-name "${fixture}"
  BB="${BB_BIN}" bash "${ROOT}/prove-common-credential-root-with-vk.sh" \
    "${LANE}" "${package_name}" \
    "target/${package_name}.json" "target/${package_name}.gz" \
    "target/${output}"
}

prove_session() {
  local mode="$1"
  local fixture="$2"
  local output="$3"
  local package="${ROOT}/${LANE}/families/private_persona_claim_v1/session"
  local package_name="credential_private_persona_claim_v1_session"
  local fixture_prefix="../../common_credential_root_v1/session_fixtures/${mode}"
  if [[ "${mode}" == "public" ]]; then
    package="${FAMILY}/public_session"
    package_name="credential_common_credential_root_v1_public_session_${LANE}"
    fixture_prefix="../session_fixtures/${mode}"
  fi
  cd "${package}"
  "${NARGO_BIN}" execute --prover-name \
    "${fixture_prefix}/${fixture}"
  BB="${BB_BIN}" bash "${ROOT}/prove-common-credential-root-with-vk.sh" \
    "${LANE}" "${package_name}" \
    "target/${package_name}.json" "target/${package_name}.gz" \
    "target/${output}"
}

for mode in private public; do
  session_package="${ROOT}/${LANE}/families/private_persona_claim_v1/session"
  fixture_prefix="../../common_credential_root_v1/session_fixtures/${mode}"
  if [[ "${mode}" == "public" ]]; then
    session_package="${FAMILY}/public_session"
    fixture_prefix="../session_fixtures/${mode}"
  fi
  cd "${session_package}"
  "${NARGO_BIN}" check
  mkdir -p target
  if "${NARGO_BIN}" execute --prover-name \
    "${fixture_prefix}/ProverWrongSignature" \
    >"target/common-credential-root-wrong-signature.log" 2>&1; then
    printf 'persona session accepted invalid signature: %s\n' "${mode}" >&2
    exit 1
  fi
  prove_session "${mode}" Prover common-credential-root-session-proof
  prove_session "${mode}" ProverOtherPersona common-credential-root-other-persona-proof

  package="${FAMILY}/${mode}_persona_claim"
  cd "${package}"
  "${NARGO_BIN}" check
  "${NARGO_BIN}" fmt --check
  mkdir -p target
  for fixture in ProverWrongJoin ProverWrongClaim ProverLineageDisclosure ProverShortPath; do
    if "${NARGO_BIN}" execute --prover-name "${fixture}" >"target/${fixture}.log" 2>&1; then
      printf 'selected-claim negative witness unexpectedly solved: %s %s\n' "${mode}" "${fixture}" >&2
      exit 1
    fi
  done
  if ! grep -q 'lineage claim cannot be disclosed' "target/ProverLineageDisclosure.log"; then
    printf 'reserved lineage disclosure did not fail at its privacy gate: %s\n' "${mode}" >&2
    exit 1
  fi
  if ! grep -q 'claim tree path must have fixed depth' "target/ProverShortPath.log"; then
    printf 'short claim path did not fail at its fixed-depth gate: %s\n' "${mode}" >&2
    exit 1
  fi
  prove_claim "${mode}" Prover proof
  python3 - "${package}/target/proof/public_inputs" \
    "${package}/target/proof/tampered_public_inputs" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_bytes()
if len(source) < 32 or len(source) % 32 != 0:
    raise SystemExit("invalid baseline public-input shape")
tampered = bytearray(source)
tampered[31] ^= 1
Path(sys.argv[2]).write_bytes(tampered)
PY
  if verification_output="$(
    "${BB_BIN}" verify -t evm -c "${BB_CRS_DIR}" \
      -k "${package}/target/proof/vk" \
      -p "${package}/target/proof/proof" \
      -i "${package}/target/proof/tampered_public_inputs" 2>&1
  )"; then
    printf 'tampered selected-claim public input verified: %s\n' "${mode}" >&2
    exit 1
  fi
  if [[ "${verification_output}" != *"Proof verification failed"* ]]; then
    printf 'tampered selected-claim proof failed without reviewed verifier rejection: %s\n' "${mode}" >&2
    printf '%s\n' "${verification_output}" >&2
    exit 1
  fi
  rm -f "${package}/target/proof/tampered_public_inputs"
  prove_claim "${mode}" ProverEmployer proof-employer
  prove_claim "${mode}" ProverOtherValidSubject proof-other-subject
  prove_claim "${mode}" ProverEmployerDifferentPersona proof-different-persona
  python3 "${ROOT}/test-common-credential-root-composition.py" "${LANE}" \
    --joined-claims "${mode}"
done

printf 'common_credential_root_v1 %s selected-claim subject joins passed\n' "${LANE}"
