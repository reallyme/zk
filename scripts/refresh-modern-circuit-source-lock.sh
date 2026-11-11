#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CIRCUITS_ROOT="${CIRCUITS_ROOT:-${ROOT}/circuits}"
SOURCE_LOCK="${SOURCE_LOCK:-${ROOT}/circuits/modern-circuit-source-lock.tsv}"
CARGO_BIN="${CARGO:-cargo}"

fail() {
  echo "modern source lock refresh failed: $1" >&2
  exit 2
}

sha256_file() {
  local path="$1"

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{ print $1 }'
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{ print $1 }'
    return 0
  fi
  fail "no SHA-256 command is available"
}

sha256_stream() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{ print $1 }'
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
    return 0
  fi
  fail "no SHA-256 command is available"
}

circuit_source_file_hash_lines() {
  local circuit_rel="$1"

  (
    cd "${CIRCUITS_ROOT}"
    {
      find "${circuit_rel}" \
        -type f \
        \( -name '*.nr' -o -name 'Nargo.toml' \) \
        -not -path '*/target/*' \
        -print
      if [[ -d vendor ]]; then
        find vendor \
          -type f \
          \( -name '*.nr' -o -name 'Nargo.toml' \) \
          -not -path '*/target/*' \
          -print
      fi
    } | sort | while IFS= read -r source_path; do
      printf '%s\t' "${source_path}"
      sha256_file "${source_path}"
    done
  )
}

circuit_source_closure_sha256() {
  local circuit_rel="$1"

  circuit_source_file_hash_lines "${circuit_rel}" | sha256_stream
}

if ! command -v "${CARGO_BIN}" >/dev/null 2>&1; then
  fail "cargo is required to read the canonical API circuit registry"
fi

tmp_lock="$(mktemp "${TMPDIR:-/tmp}/reallyme-modern-source-lock.XXXXXX")"
trap 'rm -f "${tmp_lock}"' EXIT
printf 'circuit\tpackage\tsource_closure_sha256\n' > "${tmp_lock}"

"${CARGO_BIN}" run --quiet -p reallyme-zk-cli -- circuits --paths | sed '1d' | sort |
while IFS= read -r circuit_rel; do
  manifest="${CIRCUITS_ROOT}/${circuit_rel}/Nargo.toml"
  if [[ ! -f "${manifest}" ]]; then
    fail "registered circuit source is missing"
  fi
  package_name="$(awk -F ' *= *' '$1 == "name" { gsub(/"/, "", $2); print $2; exit }' "${manifest}")"
  if [[ -z "${package_name}" ]]; then
    fail "registered circuit source has no package name"
  fi
  printf '%s\t%s\t%s\n' "${circuit_rel}" "${package_name}" "$(circuit_source_closure_sha256 "${circuit_rel}")" >> "${tmp_lock}"
done

mv "${tmp_lock}" "${SOURCE_LOCK}"
trap - EXIT
echo "source-lock: ${SOURCE_LOCK}"
