#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  printf 'usage: %s sha256|poseidon2 package artifact witness output-dir\n' "$0" >&2
  exit 2
fi

lane="$1"
package="$2"
artifact="$3"
witness="$4"
output="$5"
if [[ "${lane}" != "sha256" && "${lane}" != "poseidon2" ]] ||
   [[ ! "${package}" =~ ^[a-zA-Z0-9_]+$ ]]; then
  printf 'invalid common-credential-root proof identity\n' >&2
  exit 2
fi
: "${BB:?BB must point to the pinned Barretenberg executable}"
: "${BB_CRS_DIR:?BB_CRS_DIR must point to the pinned BN254 CRS directory}"
if [[ ! -f "${artifact}" || ! -f "${witness}" ]]; then
  printf 'common-credential-root artifact or witness is missing\n' >&2
  exit 2
fi

# A circuit's VK depends on its exact bytecode and verifier target. The
# caller's per-run cache prevents fixture variants from regenerating that VK.
artifact_sha256="$(shasum -a 256 "${artifact}" | awk '{ print $1 }')"
if [[ -n "${COMMON_CREDENTIAL_ROOT_VK_CACHE:-}" ]]; then
  cache_root="${COMMON_CREDENTIAL_ROOT_VK_CACHE}"
else
  cache_root="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-common-credential-root-vk.XXXXXX")"
  trap 'rm -rf "${cache_root}"' EXIT
fi
key_dir="${cache_root}/${lane}/${package}/${artifact_sha256}"
if [[ ! -f "${key_dir}/vk" || ! -f "${key_dir}/vk_hash" ]]; then
  mkdir -p "${key_dir}"
  "${BB}" write_vk -t evm -c "${BB_CRS_DIR}" \
    -b "${artifact}" -o "${key_dir}"
fi

"${BB}" prove -t evm -c "${BB_CRS_DIR}" \
  -b "${artifact}" -w "${witness}" -k "${key_dir}/vk" -o "${output}"
cp "${key_dir}/vk" "${key_dir}/vk_hash" "${output}/"
"${BB}" verify -t evm -c "${BB_CRS_DIR}" \
  -k "${output}/vk" -p "${output}/proof" -i "${output}/public_inputs"
