#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ANDROID_ARM64_BB_LIB_DIR="${ANDROID_ARM64_BB_LIB_DIR:-}"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-26}"
ANDROID_NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
ANDROID_SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/release-artifacts/modern-v1-bb-6.0.0}"
OUTPUT_DIR="${OUTPUT_DIR:-${LOCAL_ARTIFACT_ROOT}/android-platform-ffi/arm64-v8a}"
METADATA_PATH="${OUTPUT_DIR}/ReallyMeZKPlatformFFI.build.tsv"
CARGO_PROFILE="${CARGO_PROFILE:-mobile-release}"
PLATFORM_FFI_FEATURES="${PLATFORM_FFI_FEATURES:-native}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="${ROOT}/${TARGET_DIR}"
fi
if [[ -z "${HOME:-}" || "${HOME}" != /* ]]; then
  echo "android platform ffi build failed: HOME must be an absolute path for source remapping" >&2
  exit 2
fi
SOURCE_REMAP_FLAG="--remap-path-prefix=${HOME}=source-root"
TOOLCHAIN_LOCK="${ROOT}/circuits/toolchain-lock.json"
CRATE="reallyme-zk-platform-ffi"
TARGET="aarch64-linux-android"

fail() {
  echo "android platform ffi build failed: $1" >&2
  exit 2
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

source_closure_file_hash_lines() {
  (
    cd "${ROOT}"
    {
      printf '%s\n' Cargo.lock Cargo.toml circuits/toolchain-lock.json
      find \
        crates/api \
        crates/artifacts \
        crates/backend-bb \
        crates/noir-witness-core \
        crates/platform-ffi \
        crates/proto \
        crates/proto-codec \
        -type f \
        \( -name '*.rs' -o -name '*.toml' -o -name '*.cc' -o -name '*.h' -o -name '*.modulemap' \) \
        -not -path '*/tests/*' \
        -not -name 'tests.rs' \
        -not -name '*_tests.rs' \
        -not -path '*/src/bin/*' \
        -not -path '*/target/*' \
        -print
    } | sort | while IFS= read -r source_path; do
      printf '%s\t%s\n' "${source_path}" "$(sha256_file "${ROOT}/${source_path}")"
    done
  )
}

source_closure_sha256() {
  source_closure_file_hash_lines | shasum -a 256 | awk '{ print $1 }'
}

lock_value() {
  node -e '
const fs = require("fs");
const lock = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
let value = lock;
for (const part of process.argv[2].split(".")) {
  value = Array.isArray(value) ? value[Number(part)] : value[part];
  if (value === undefined) {
    process.exit(3);
  }
}
process.stdout.write(typeof value === "object" ? JSON.stringify(value) : String(value));
' "${TOOLCHAIN_LOCK}" "$1" || fail "missing lock value $1"
}

ANDROID_LOCK_PATH="candidateMatchedPair.barretenberg.linkableStaticLibraries.androidArm64"
EXPECTED_ANDROID_BB_LIB_SIZE="$(lock_value "${ANDROID_LOCK_PATH}.size")"
EXPECTED_ANDROID_BB_LIB_SHA256="$(lock_value "${ANDROID_LOCK_PATH}.sha256")"
EXPECTED_ANDROID_LIBDEFLATE_SIZE="$(lock_value "${ANDROID_LOCK_PATH}.companionStaticLibraries.0.size")"
EXPECTED_ANDROID_LIBDEFLATE_SHA256="$(lock_value "${ANDROID_LOCK_PATH}.companionStaticLibraries.0.sha256")"

if [[ -z "${ANDROID_ARM64_BB_LIB_DIR}" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR must be set"
fi
if [[ ! -d "${ANDROID_ARM64_BB_LIB_DIR}" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR does not name a directory"
fi
if [[ ! -f "${ANDROID_ARM64_BB_LIB_DIR}/libbb-external.a" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR must contain libbb-external.a"
fi
if [[ ! -f "${ANDROID_ARM64_BB_LIB_DIR}/libdeflate.a" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR must contain libdeflate.a"
fi
actual_bb_lib_size="$(wc -c <"${ANDROID_ARM64_BB_LIB_DIR}/libbb-external.a" | tr -d '[:space:]')"
if [[ "${actual_bb_lib_size}" != "${EXPECTED_ANDROID_BB_LIB_SIZE}" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR libbb-external.a size does not match the toolchain lock"
fi
actual_bb_lib_sha256="$(
  shasum -a 256 "${ANDROID_ARM64_BB_LIB_DIR}/libbb-external.a" | awk '{print $1}'
)"
if [[ "${actual_bb_lib_sha256}" != "${EXPECTED_ANDROID_BB_LIB_SHA256}" ]]; then
  # Host compiler comments distinguish the reviewed Linux reproduction from
  # the Darwin release input. Require the matching companion archive as well.
  linux_identity="${ANDROID_LOCK_PATH}.linuxSourceBuild"
  [[ "${actual_bb_lib_sha256}" == "$(lock_value "${linux_identity}.sha256")" ]] ||
    fail "ANDROID_ARM64_BB_LIB_DIR libbb-external.a SHA-256 does not match the toolchain lock"
  [[ "${actual_bb_lib_size}" == "$(lock_value "${linux_identity}.size")" ]] ||
    fail "Android Linux source archive size does not match the toolchain lock"
  EXPECTED_ANDROID_LIBDEFLATE_SIZE="$(lock_value "${linux_identity}.companionStaticLibraries.0.size")"
  EXPECTED_ANDROID_LIBDEFLATE_SHA256="$(lock_value "${linux_identity}.companionStaticLibraries.0.sha256")"
fi
actual_libdeflate_size="$(wc -c <"${ANDROID_ARM64_BB_LIB_DIR}/libdeflate.a" | tr -d '[:space:]')"
if [[ "${actual_libdeflate_size}" != "${EXPECTED_ANDROID_LIBDEFLATE_SIZE}" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR libdeflate.a size does not match the toolchain lock"
fi
actual_libdeflate_sha256="$(
  shasum -a 256 "${ANDROID_ARM64_BB_LIB_DIR}/libdeflate.a" | awk '{print $1}'
)"
if [[ "${actual_libdeflate_sha256}" != "${EXPECTED_ANDROID_LIBDEFLATE_SHA256}" ]]; then
  fail "ANDROID_ARM64_BB_LIB_DIR libdeflate.a SHA-256 does not match the toolchain lock"
fi
if [[ "${PLATFORM_FFI_FEATURES}" != "native" &&
      "${PLATFORM_FFI_FEATURES}" != "native,diagnostic-exact-source" ]]; then
  fail "PLATFORM_FFI_FEATURES must be a supported Android native feature set"
fi
if [[ ",${PLATFORM_FFI_FEATURES}," == *",diagnostic-exact-source,"* &&
      "${OUTPUT_DIR}" == "${LOCAL_ARTIFACT_ROOT}/android-platform-ffi/arm64-v8a" ]]; then
  fail "diagnostic-exact-source must use a separate OUTPUT_DIR from the production Android platform FFI"
fi
if [[ -z "${ANDROID_NDK_ROOT}" ]]; then
  if [[ ! -d "${ANDROID_SDK_ROOT}/ndk" ]]; then
    fail "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set when the SDK NDK directory is unavailable"
  fi
  ANDROID_NDK_ROOT="$(
    find "${ANDROID_SDK_ROOT}/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1
  )"
fi
if [[ ! -d "${ANDROID_NDK_ROOT}" ]]; then
  fail "Android NDK root does not name a directory"
fi

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) NDK_HOST_TAG="darwin-x86_64" ;;
  Darwin:x86_64) NDK_HOST_TAG="darwin-x86_64" ;;
  Linux:x86_64) NDK_HOST_TAG="linux-x86_64" ;;
  *) fail "unsupported Android NDK host $(uname -s):$(uname -m)" ;;
esac

NDK_BIN="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${NDK_HOST_TAG}/bin"
ANDROID_CC="${NDK_BIN}/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
ANDROID_CXX="${NDK_BIN}/aarch64-linux-android${ANDROID_API_LEVEL}-clang++"
ANDROID_AR="${NDK_BIN}/llvm-ar"
ANDROID_STRIP="${NDK_BIN}/llvm-strip"
if [[ ! -x "${ANDROID_CC}" || ! -x "${ANDROID_CXX}" ||
      ! -x "${ANDROID_AR}" || ! -x "${ANDROID_STRIP}" ]]; then
  fail "Android NDK clang/llvm-ar/llvm-strip tools are unavailable for API ${ANDROID_API_LEVEL}"
fi

(
  cd "${ROOT}"
  export CC_aarch64_linux_android="${ANDROID_CC}"
  export CXX_aarch64_linux_android="${ANDROID_CXX}"
  export AR_aarch64_linux_android="${ANDROID_AR}"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ANDROID_CC}"
  REALLYME_BARRETENBERG_LIB_DIR="${ANDROID_ARM64_BB_LIB_DIR}" \
    RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }${SOURCE_REMAP_FLAG}" \
    cargo build \
      --locked \
      --profile "${CARGO_PROFILE}" \
      --target "${TARGET}" \
      -p "${CRATE}" \
      --features "${PLATFORM_FFI_FEATURES}"
)

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"
cp "${TARGET_DIR}/${TARGET}/${CARGO_PROFILE}/libreallyme_zk_platform_ffi.a" \
  "${OUTPUT_DIR}/libreallyme_zk_platform_ffi.a"
cp "${ROOT}/crates/proto-codec/include/reallyme_zk_platform_abi.h" \
  "${OUTPUT_DIR}/reallyme_zk_platform_abi.h"
cp "${ANDROID_ARM64_BB_LIB_DIR}/libdeflate.a" \
  "${OUTPUT_DIR}/libdeflate.a"
# Companion archive debug records can retain the build host's SDK paths even
# when Rust source paths are remapped. Remove those records before packaging.
"${ANDROID_STRIP}" --strip-debug "${OUTPUT_DIR}/libdeflate.a"
if strings "${OUTPUT_DIR}/libdeflate.a" | grep -F "${HOME}" >/dev/null; then
  fail "Android companion archive contains a build-host home path"
fi
if strings "${OUTPUT_DIR}/libreallyme_zk_platform_ffi.a" | grep -F "${ROOT}" >/dev/null; then
  fail "Android platform archive contains an unremapped repository source path"
fi

{
  printf 'key\tvalue\n'
  printf 'format\tandroid-platform-ffi-v1\n'
  printf 'cargo_profile\t%s\n' "${CARGO_PROFILE}"
  printf 'cargo_features\t%s\n' "${PLATFORM_FFI_FEATURES}"
  printf 'source_path_remapping\thome-to-source-root-v1\n'
  printf 'source_closure_sha256\t%s\n' "$(source_closure_sha256)"
  printf 'platform_archive_sha256\t%s\n' \
    "$(sha256_file "${OUTPUT_DIR}/libreallyme_zk_platform_ffi.a")"
  printf 'platform_header_sha256\t%s\n' \
    "$(sha256_file "${OUTPUT_DIR}/reallyme_zk_platform_abi.h")"
  printf 'platform_libdeflate_sha256\t%s\n' "$(sha256_file "${OUTPUT_DIR}/libdeflate.a")"
} >"${METADATA_PATH}"

"${ROOT}/scripts/check-platform-ffi-symbols.sh" \
  android \
  "${OUTPUT_DIR}/libreallyme_zk_platform_ffi.a"

printf '%s\n' "${OUTPUT_DIR}"
