#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  printf '%s\n' "error: ripgrep is required for boundary-policy enforcement" >&2
  exit 1
fi

MATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-zk-boundaries.XXXXXXXX")" || {
  printf '%s\n' "error: secure temporary directory creation failed" >&2
  exit 1
}
if [[ ! -d "${MATCH_DIR}" || -L "${MATCH_DIR}" ]]; then
  printf '%s\n' "error: secure temporary directory creation failed" >&2
  exit 1
fi
cleanup_match_dir() {
  rm -rf -- "${MATCH_DIR}"
}
trap cleanup_match_dir EXIT

# Ripgrep uses 1 for a clean no-match and values greater than 1 for failures.
# Bash suppresses errexit inside conditionals, so promote failures explicitly.
checked_rg() {
  local result
  set +e
  rg "$@"
  result=$?
  set -e
  if ((result > 1)); then
    printf '%s\n' "error: ripgrep boundary check failed with status ${result}" >&2
    exit "${result}"
  fi
  return "${result}"
}

checked_cargo_tree() {
  local package="$1"
  local result
  set +e
  cargo tree --locked --all-features --edges normal,build --package "${package}"
  result=$?
  set -e
  if ((result != 0)); then
    printf '%s\n' "error: cargo tree boundary check failed for ${package} with status ${result}" >&2
    return "${result}"
  fi
  return 0
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALLYME_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
SSI_DIR="${REALLYME_DIR}/ssi"
OPENID4VP_DIR="${REALLYME_DIR}/openid4vp"
OPENID4VCI_DIR="${REALLYME_DIR}/openid4vci"
WALLET_DIR="${REALLYME_DIR}/wallet"
IDENTITY_DIR="${REALLYME_DIR}/identity"

status=0
REQUIRED_OPEN_STACK_CHECKOUTS="${REALLYME_ZK_REQUIRED_OPEN_STACK_CHECKOUTS:-ssi,openid4vci,openid4vp,wallet,identity}"

allow_missing_sibling_checkouts() {
  [[ "${REALLYME_ZK_ALLOW_MISSING_OPEN_STACK_CHECKOUTS:-}" == "1" && "${CI:-}" != "true" ]]
}

is_required_sibling_checkout() {
  local name="$1"
  [[ ",${REQUIRED_OPEN_STACK_CHECKOUTS}," == *",${name},"* ]]
}

require_sibling_checkout() {
  local name="$1"
  local display_name="$2"
  local path="$3"
  if [[ -d "${path}" ]]; then
    return
  fi
  if ! is_required_sibling_checkout "${name}"; then
    printf '%s\n' "warning: ${display_name} checkout not found; ${display_name} boundary check is not in this enforced lane" >&2
    return
  fi
  if allow_missing_sibling_checkouts; then
    printf '%s\n' "warning: ${display_name} checkout not found; skipped ${display_name} boundary check" >&2
    return
  fi
  printf '%s\n' \
    "error: ${display_name} checkout not found; CI must provide pinned sibling checkouts for open-stack boundary enforcement" >&2
  status=1
}

require_sibling_checkout "ssi" "SSI" "${SSI_DIR}"
require_sibling_checkout "openid4vci" "openid4vci" "${OPENID4VCI_DIR}"
require_sibling_checkout "openid4vp" "openid4vp" "${OPENID4VP_DIR}"
require_sibling_checkout "wallet" "wallet" "${WALLET_DIR}"
require_sibling_checkout "identity" "identity" "${IDENTITY_DIR}"

mapfile -t cargo_manifests < <(
  find "${ROOT_DIR}" \
    -path "${ROOT_DIR}/target" -prune -o \
    -name Cargo.toml -print
)

if ((${#cargo_manifests[@]} > 0)); then
  if checked_rg -n '^\s*(swift|kotlin)\s*=' "${cargo_manifests[@]}" \
    >"${MATCH_DIR}/platform-rust-features.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: Rust crates must not define platform package features: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/platform-rust-features.matches"
  fi
fi

package_manifests=()
if [[ -d "${ROOT_DIR}/packages" ]]; then
  mapfile -t package_manifests < <(
    find "${ROOT_DIR}/packages" \
      -type f \( \
        -name package.json -o \
        -name Package.swift -o \
        -name build.gradle -o \
        -name build.gradle.kts -o \
        -name pom.xml \
      \) -print
  )
fi

if ((${#package_manifests[@]} > 0)); then
  if checked_rg -n 'reallyme-identity|@reallyme/identity|ReallyMeIdentity|me\.really:identity' \
    "${package_manifests[@]}" >"${MATCH_DIR}/consumer-package-names.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: consumer identity package name belongs in identity: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/consumer-package-names.matches"
  fi
fi

if checked_rg -n 'Command::new\("bb"\)|std::process::Command|tokio::process::Command' \
  "${ROOT_DIR}/crates/backend-bb/src" \
  --glob '!**/target/**' \
  --glob '!**/tests.rs' \
  --glob '!**/tests/**' >"${MATCH_DIR}/backend-cli.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: production backend-bb must not shell out to bb: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/backend-cli.matches"
fi

if checked_rg -n 'std::process\s+as|process::\{?Command|process::Command|Command::new' \
  "${ROOT_DIR}/crates" \
  --glob '*.rs' \
  --glob '!**/release-process/src/runner.rs' \
  --glob '!**/tests.rs' \
  --glob '!**/tests/**' >"${MATCH_DIR}/release-process-boundary.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: external command execution belongs only in release-process/src/runner.rs: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/release-process-boundary.matches"
fi

if checked_rg -n 'reallyme-zk-backend-bb|backend-bb|backend_bb|barretenberg' \
  "${ROOT_DIR}/crates/api/Cargo.toml" \
  "${ROOT_DIR}/crates/artifacts/Cargo.toml" \
  "${ROOT_DIR}/crates/proto-codec/Cargo.toml" \
  "${ROOT_DIR}/crates/proto/Cargo.toml" \
  --glob '!**/target/**' >"${MATCH_DIR}/local-backend-deps.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: non-backend local crate depends on backend-bb: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/local-backend-deps.matches"
fi

if ((status == 0)); then
  for open_stack_package in \
    reallyme-zk-api \
    reallyme-zk-artifacts \
    reallyme-zk-proto \
    reallyme-zk-proto-codec; do
    if checked_cargo_tree "${open_stack_package}" \
      >"${MATCH_DIR}/${open_stack_package}.cargo-tree"; then
      if checked_rg -n 'reallyme-zk-backend-bb|backend-bb|backend_bb|barretenberg' \
        "${MATCH_DIR}/${open_stack_package}.cargo-tree" \
        >"${MATCH_DIR}/${open_stack_package}.backend-tree.matches"; then
        while IFS= read -r match; do
          printf '%s\n' "error: open-stack crate has transitive backend-bb dependency: ${match}" >&2
          status=1
        done <"${MATCH_DIR}/${open_stack_package}.backend-tree.matches"
      fi
    else
      status=1
    fi
  done
fi

if checked_rg -n 'reallyme-identity(?!-proto)|reallyme-(openid4vp|openid4vc|wallet)|reallyme_identity(?!_proto)|reallyme_(openid4vp|openid4vc|wallet)' \
  "${cargo_manifests[@]}" \
  --pcre2 >"${MATCH_DIR}/sibling-crate-deps.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: reallyme/zk crates must not depend on sibling stack crates; use local ZK protos and reallyme-zk-api boundaries: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/sibling-crate-deps.matches"
fi

non_ssi_adapter_manifests=()
for manifest in "${cargo_manifests[@]}"; do
  if [[ "${manifest}" != "${ROOT_DIR}/Cargo.toml" \
    && "${manifest}" != "${ROOT_DIR}/crates/proto-codec/Cargo.toml" ]]; then
    non_ssi_adapter_manifests+=("${manifest}")
  fi
done

if ((${#non_ssi_adapter_manifests[@]} > 0)); then
  if checked_rg -n 'reallyme-ssi-proto|reallyme_ssi_proto' \
    "${non_ssi_adapter_manifests[@]}" \
    >"${MATCH_DIR}/unauthorized-identity-proto.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: only proto-codec may use the optional published SSI stack-error contract: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/unauthorized-identity-proto.matches"
  fi
fi

mapfile -t zk_proto_files < <(
  find "${ROOT_DIR}/crates/proto/proto" \
    -type f \
    -name '*.proto' -print
)

if ((${#zk_proto_files[@]} > 0)); then
  if checked_rg -n '^import\s+"reallyme/(openid4vp|openid4vci|wallet|identity/(?!common/))' \
    "${zk_proto_files[@]}" \
    --pcre2 >"${MATCH_DIR}/sibling-proto-imports.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: reallyme/zk protos must not import sibling protocol schemas except identity/common: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/sibling-proto-imports.matches"
  fi
fi

if checked_rg -n 'identity-zk-api|identity-zk-native|identity_zk_api|identity_zk_native|NativeZkProver|NativeZkVerifier|ZkNativeError' \
  "${ROOT_DIR}" \
  --glob '!**/target/**' \
  --glob '!**/scripts/check-open-stack-boundaries.sh' >"${MATCH_DIR}/old-identity-zk.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: old meproto identity/zk crate surface must not be copied into reallyme/zk: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/old-identity-zk.matches"
fi

if checked_rg -n 'identity-presentation-vp-zk|identity_presentation_vp_zk|ZkProofVerifier|VpZkError|derive_proof_claims_from_presentation|extract_disclosed_claims_from_zk|DisclosureItem' \
  "${ROOT_DIR}" \
  --glob '!**/target/**' \
  --glob '!**/scripts/check-open-stack-boundaries.sh' >"${MATCH_DIR}/old-presentation-zk.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: old meproto presentation/vp/zk format surface must not be copied into reallyme/zk: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/old-presentation-zk.matches"
fi

# Match the singular identity holder field. The ZK common-credential-root API legitimately
# accepts two subject_public_keys to derive presentation joins.
if checked_rg -n 'VcProofInput|VcClaimPayload|PublicKeyBytes|disclosure intent|issuer_public_key|subject_public_key\b|persona_public_key' \
  "${ROOT_DIR}/crates/api/src" \
  --glob '!**/tests/**' >"${MATCH_DIR}/identity-input-surface.matches"; then
  while IFS= read -r match; do
    printf '%s\n' "error: identity claim/key/disclosure construction belongs in identity-api, not reallyme-zk-api: ${match}" >&2
    status=1
  done <"${MATCH_DIR}/identity-input-surface.matches"
fi

if [[ -d "${SSI_DIR}" ]]; then
  if checked_rg -n 'enum ZkCircuitId|struct ZkCircuitCapabilities|fn circuit_capabilities' \
    "${SSI_DIR}/crates" \
    --glob '!**/target/**' \
    --glob '!**/generated/**' \
    --glob '!crates/disclosure-policy/**' >"${MATCH_DIR}/identity-registry.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: duplicate ZK registry in SSI: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/identity-registry.matches"
  fi

  if checked_rg -n 'backend-bb|backend_bb|barretenberg|BbProver|BbVerifier|Command::new\("bb"\)' \
    "${SSI_DIR}/crates" "${SSI_DIR}/Cargo.toml" \
    --glob '!**/target/**' \
    --glob '!**/generated/**' >"${MATCH_DIR}/identity-backend.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: forbidden ZK backend dependency in SSI: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/identity-backend.matches"
  fi
else
  :
fi

if [[ -x "${OPENID4VCI_DIR}/scripts/check-zk-boundary-policy.sh" ]]; then
  (cd "${OPENID4VCI_DIR}" && scripts/check-zk-boundary-policy.sh)
elif [[ -d "${OPENID4VCI_DIR}" ]]; then
  if checked_rg -n 'reallyme-zk-(?!api)|backend-bb|backend_bb|barretenberg|BbProver|BbVerifier|bb-prover|bb_prover' \
    "${OPENID4VCI_DIR}/Cargo.toml" "${OPENID4VCI_DIR}/crates" \
    --pcre2 \
    --glob '!**/target/**' \
    --glob '!**/generated/**' >"${MATCH_DIR}/openid4vci-backend.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: forbidden ZK backend dependency in openid4vci: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/openid4vci-backend.matches"
  fi
else
  :
fi

if [[ -d "${OPENID4VP_DIR}" ]]; then
  openid4vp_registry_paths=("${OPENID4VP_DIR}/crates")
  if [[ -d "${OPENID4VP_DIR}/proto" ]]; then
    openid4vp_registry_paths+=("${OPENID4VP_DIR}/proto")
  fi

  if checked_rg -n 'enum ZkCircuitId|struct ZkCircuitCapabilities|fn circuit_capabilities' \
    "${openid4vp_registry_paths[@]}" \
    --glob '!**/target/**' \
    --glob '!**/generated/**' >"${MATCH_DIR}/openid4vp-registry.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: duplicate ZK registry in openid4vp: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/openid4vp-registry.matches"
  fi

  if checked_rg -n 'reallyme-zk-(?!api)|backend-bb|backend_bb|barretenberg|BbProver|BbVerifier|bb-prover|bb_prover|Command::new\("bb"\)' \
    "${OPENID4VP_DIR}/Cargo.toml" "${OPENID4VP_DIR}/crates" \
    --pcre2 \
    --glob '!**/target/**' \
    --glob '!**/generated/**' >"${MATCH_DIR}/openid4vp-backend.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: forbidden ZK backend dependency in openid4vp: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/openid4vp-backend.matches"
  fi
else
  :
fi

if [[ -d "${WALLET_DIR}" ]]; then
  if checked_rg -n 'identity-presentation-vp-zk|identity_presentation_vp_zk|reallyme-zk-(?!api)|backend-bb|backend_bb|barretenberg|BbProver|BbVerifier|Command::new\("bb"\)' \
    "${WALLET_DIR}/Cargo.toml" "${WALLET_DIR}/crates" \
    --pcre2 \
    --glob '!**/target/**' \
    --glob '!**/generated/**' >"${MATCH_DIR}/wallet-backend.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: wallet must use reallyme-zk-api injection only, not old VP/ZK facades or backend-bb: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/wallet-backend.matches"
  fi
else
  :
fi

if [[ -d "${IDENTITY_DIR}" ]]; then
  if checked_rg -n 'reallyme-zk-(?!api)|reallyme_zk_(proto|proto_codec|platform|backend|artifacts)' \
    "${IDENTITY_DIR}/crates" \
    --pcre2 \
    --glob '!**/target/**' \
    --glob '!**/generated/**' >"${MATCH_DIR}/identity-product-zk-boundary.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: reusable identity product crates must name only reallyme-zk-api; ZK protobuf, FFI, and provider adapters belong in conformance/app adapter crates: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/identity-product-zk-boundary.matches"
  fi

  if checked_rg -n 'identity-zk-api|identity-zk-native|identity_zk_api|identity_zk_native|NativeZkProver|NativeZkVerifier|ZkNativeError|Command::new\("bb"\)' \
    "${IDENTITY_DIR}" \
    --glob '!**/target/**' \
    --glob '!**/node_modules/**' \
    --glob '!Cargo.lock' >"${MATCH_DIR}/identity-old-zk.matches"; then
    while IFS= read -r match; do
      printf '%s\n' "error: identity must use reallyme/zk providers, not old meproto identity/zk or bb shell-out: ${match}" >&2
      status=1
    done <"${MATCH_DIR}/identity-old-zk.matches"
  fi
else
  :
fi

exit "${status}"
