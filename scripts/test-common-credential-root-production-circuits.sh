#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
NARGO_BIN="${NARGO:-$(command -v nargo || true)}"
BB_BIN="${BB:-$(command -v bb || true)}"

fail() {
  printf 'common-credential-root production circuit gate failed: %s\n' "$1" >&2
  exit 2
}

if [[ -z "${NARGO_BIN}" || ! -x "${NARGO_BIN}" ]]; then
  fail "NARGO must point to the pinned executable"
fi
if [[ -z "${BB_BIN}" || ! -x "${BB_BIN}" ]]; then
  fail "BB must point to the pinned executable"
fi
command -v protoc >/dev/null 2>&1 || fail "protoc is required to encode stage request vectors"
NARGO_BIN="$(realpath "${NARGO_BIN}")" || fail "NARGO executable cannot be resolved"
BB_BIN="$(realpath "${BB_BIN}")" || fail "BB executable cannot be resolved"
# A local installation keeps the full CRS beside its pinned binary. Resolve
# the binary before deriving that directory because user-facing commands may
# be symlinks into a versioned installation.
if [[ -z "${BB_CRS_DIR:-}" ]]; then
  BB_CRS_DIR="$(dirname "$(dirname "${BB_BIN}")")/crs"
fi
if [[ -z "${BB_CRS_DIR:-}" || "${BB_CRS_DIR}" != /* || ! -d "${BB_CRS_DIR}" || -L "${BB_CRS_DIR}" ]]; then
  fail "BB_CRS_DIR must point to a plain absolute CRS directory"
fi

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) platform="darwinArm64" ;;
  Linux:x86_64) platform="linuxX86_64" ;;
  *) fail "the pinned toolchain has no binary identity for this platform" ;;
esac
lock_value() {
  node -e '
const fs = require("node:fs");
const lock = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const value = process.argv[2].split("/").reduce((current, key) => current?.[key], lock);
if (typeof value !== "string" && typeof value !== "number") process.exit(2);
process.stdout.write(String(value));
' "${ROOT}/circuits/toolchain-lock.json" "$1"
}
sha256_file() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}
identity_key="candidateMatchedPair/localBinaryIdentities/${platform}"
[[ "$(sha256_file "${NARGO_BIN}")" == "$(lock_value "${identity_key}/nargoExecutableSha256")" ]] ||
  fail "NARGO hash differs from the pinned toolchain"
[[ "$(sha256_file "${BB_BIN}")" == "$(lock_value "${identity_key}/barretenbergExecutableSha256")" ]] ||
  fail "BB hash differs from the pinned toolchain"
crs_key="candidateMatchedPair/barretenberg/crsIdentities/bn254FullProver1048577Points"
[[ "$(sha256_file "${BB_CRS_DIR}/bn254_g1.dat")" == "$(lock_value "${crs_key}/g1SourceSha256")" ]] ||
  fail "G1 CRS hash differs from the pinned toolchain"
[[ "$(sha256_file "${BB_CRS_DIR}/bn254_g2.dat")" == "$(lock_value "${crs_key}/g2Sha256")" ]] ||
  fail "G2 CRS hash differs from the pinned toolchain"
export NARGO="${NARGO_BIN}" BB="${BB_BIN}" BB_CRS_DIR

# Noir resolves Git dependencies while executing the first vector. Give it
# the same isolated writable cache from that point onward.
if [[ -n "${ISOLATED_CACHE:-}" ]]; then
  if [[ "${ISOLATED_CACHE}" != /* || -L "${ISOLATED_CACHE}" ]]; then
    fail "ISOLATED_CACHE must be a plain absolute path when set"
  fi
  mkdir -p "${ISOLATED_CACHE}"
  export XDG_CACHE_HOME="${ISOLATED_CACHE}"
fi

cd "${ROOT}"
mkdir -p "${ROOT}/target"
COMMON_CREDENTIAL_ROOT_VK_CACHE="$(mktemp -d "${ROOT}/target/common-credential-root-vk.XXXXXX")"
export COMMON_CREDENTIAL_ROOT_VK_CACHE
trap 'rm -rf "${COMMON_CREDENTIAL_ROOT_VK_CACHE}"' EXIT

# The commitment-vector oracle is repository source, so build it from this
# checkout before checking vectors. A prior cargo clean must not make the
# circuit gate depend on a stale or missing executable.
cargo build --locked --target-dir "${ROOT}/target" \
  --package reallyme-zk-noir-witness-core \
  --bin poseidon2-bounded-fixture
export POSEIDON2_FIXTURE_BIN="${ROOT}/target/debug/poseidon2-bounded-fixture"
if [[ ! -f "${POSEIDON2_FIXTURE_BIN}" || -L "${POSEIDON2_FIXTURE_BIN}" ||
      ! -x "${POSEIDON2_FIXTURE_BIN}" ]]; then
  fail "the current-source Poseidon2 vector oracle was not built"
fi

node scripts/check-modern-circuit-source-lock.mjs
python3 circuits/check-common-credential-root-v1-derivation-vectors.py
python3 circuits/check-common-credential-root-v1-commitment-vectors.py sha256
python3 circuits/check-common-credential-root-v1-commitment-vectors.py poseidon2
python3 scripts/test-issuer-credential-status-circuits.py

for lane in sha256 poseidon2; do
  bash circuits/test-common-credential-root-joined-claims.sh "${lane}"
done

python3 scripts/generate-common-credential-root-stage-requests.py
python3 scripts/generate-common-credential-root-stage-requests.py check
node scripts/check-common-credential-root-ci-artifacts.mjs exact-artifacts
node scripts/check-common-credential-root-ci-artifacts.mjs stage-requests

printf 'common-credential-root production circuit gate passed\n'
