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

python3 "${FAMILY}/generate_split_fixtures.py"

prove_and_verify() {
  local circuit="$1"
  local package_name="$2"
  local proof_name="$3"
  local fixture="${4:-Prover}"
  cd "${FAMILY}/${circuit}"
  "${NARGO_BIN}" execute --prover-name "${fixture}"
  BB="${BB_BIN}" bash "${ROOT}/prove-common-credential-root-with-vk.sh" \
    "${LANE}" "${package_name}" \
    "target/${package_name}.json" "target/${package_name}.gz" \
    "target/${proof_name}"
}

cd "${FAMILY}/root_attestation"
"${NARGO_BIN}" check
mkdir -p target
for name in ProverWrongRoot ProverWrongJoin ProverWrongAttestationJoin ProverWrongPolicy ProverWrongSignature ProverExpiresBeforePresentation ProverExpired
do
  if "${NARGO_BIN}" execute --prover-name "${name}" >"target/${name}.log" 2>&1; then
    printf 'attestation negative witness unexpectedly solved: %s\n' "${name}" >&2
    exit 1
  fi
done
prove_and_verify root_attestation "credential_common_credential_root_v1_attestation_${LANE}" attestation-proof
prove_and_verify root_attestation "credential_common_credential_root_v1_attestation_${LANE}" attestation-proof-backdated ProverBackdated
prove_and_verify root_attestation "credential_common_credential_root_v1_attestation_${LANE}" attestation-proof-other ProverOtherAttestation

cd "${FAMILY}/root_status"
"${NARGO_BIN}" check
mkdir -p target
"${NARGO_BIN}" execute --prover-name ProverStatusPath
for name in ProverWrongStatus ProverWrongJoin ProverWrongAttestationJoin ProverWrongAttestationId ProverWrongRoot ProverWrongStatusPath
do
  if "${NARGO_BIN}" execute --prover-name "${name}" >"target/${name}.log" 2>&1; then
    printf 'status negative witness unexpectedly solved: %s\n' "${name}" >&2
    exit 1
  fi
done
prove_and_verify root_status "credential_common_credential_root_v1_status_${LANE}" status-proof

cd "${FAMILY}/lineage"
"${NARGO_BIN}" check
"${NARGO_BIN}" test
mkdir -p target
"${NARGO_BIN}" execute --prover-name ProverMerklePath
for name in ProverWrongRoot ProverWrongSubject ProverWrongLineage \
  ProverWrongLineageSlot ProverWrongBinding ProverWrongJoin \
  ProverWrongIssuerSignature ProverWrongMerklePath \
  ProverShortPath ProverShortPathFive
do
  if "${NARGO_BIN}" execute --prover-name "${name}" >"target/${name}.log" 2>&1; then
    printf 'lineage negative witness unexpectedly solved: %s\n' "${name}" >&2
    exit 1
  fi
done
if ! grep -q 'lineage leaf must occupy slot zero' "target/ProverWrongLineageSlot.log"; then
  printf 'alternate lineage slot did not fail at its canonical-slot gate\n' >&2
  exit 1
fi
for name in ProverShortPath ProverShortPathFive; do
  if ! grep -q 'claim tree path must have fixed depth' "target/${name}.log"; then
    printf 'short lineage path did not fail at its fixed-depth gate: %s\n' "${name}" >&2
    exit 1
  fi
done
prove_and_verify lineage "credential_common_credential_root_v1_lineage_${LANE}" lineage-proof
prove_and_verify lineage "credential_common_credential_root_v1_lineage_${LANE}" lineage-proof-employer ProverEmployer

python3 "${ROOT}/test-common-credential-root-composition.py" "${LANE}"
printf 'common_credential_root_v1 %s six-proof composition passed\n' "${LANE}"
