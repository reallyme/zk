#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-26}"
ANDROID_NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
ANDROID_SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"
PLATFORM_FFI_DIR="${PLATFORM_FFI_DIR:-${LOCAL_ARTIFACT_ROOT}/android-platform-ffi/arm64-v8a}"
OUTPUT_ROOT="${OUTPUT_ROOT:-${LOCAL_ARTIFACT_ROOT}/android-platform-jni}"
OUTPUT_DIR="${OUTPUT_DIR:-${OUTPUT_ROOT}/arm64-v8a}"
METADATA_PATH="${METADATA_PATH:-${OUTPUT_ROOT}/ReallyMeZKPlatformJNI.build.tsv}"
JNI_SOURCE="${ROOT}/packages/kotlin/native/jni/reallyme_zk_platform_jni.cc"
JNI_EXPORTS="${ROOT}/packages/kotlin/native/jni/reallyme_zk_platform_jni.map"
PLATFORM_ARCHIVE="${PLATFORM_FFI_DIR}/libreallyme_zk_platform_ffi.a"
PLATFORM_LIBDEFLATE="${PLATFORM_FFI_DIR}/libdeflate.a"
PLATFORM_METADATA="${PLATFORM_FFI_DIR}/ReallyMeZKPlatformFFI.build.tsv"
PLATFORM_HEADER_DIR="${PLATFORM_FFI_DIR}"
PLATFORM_HEADER="${PLATFORM_HEADER_DIR}/reallyme_zk_platform_abi.h"
SOURCE_CLOSURE_SCRIPT="${ROOT}/scripts/android-platform-jni-source-closure.sh"

fail() {
  echo "android platform jni build failed: $1" >&2
  exit 2
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

source_closure_sha256() {
  "${SOURCE_CLOSURE_SCRIPT}" | shasum -a 256 | awk '{print $1}'
}

write_metadata() {
  mkdir -p "$(dirname "${METADATA_PATH}")"
  {
    printf 'key\tvalue\n'
    printf 'format\tandroid-platform-jni-v1\n'
    printf 'source_closure_sha256\t%s\n' "$(source_closure_sha256)"
    printf 'platform_archive_sha256\t%s\n' "$(sha256_file "${PLATFORM_ARCHIVE}")"
    printf 'platform_libdeflate_sha256\t%s\n' "$(sha256_file "${PLATFORM_LIBDEFLATE}")"
    printf 'platform_header_sha256\t%s\n' "$(sha256_file "${PLATFORM_HEADER}")"
    printf 'platform_metadata_sha256\t%s\n' "$(sha256_file "${PLATFORM_METADATA}")"
    printf 'jni_source_sha256\t%s\n' "$(sha256_file "${JNI_SOURCE}")"
    printf 'jni_exports_sha256\t%s\n' "$(sha256_file "${JNI_EXPORTS}")"
    printf 'jni_library_sha256\t%s\n' "$(sha256_file "${OUTPUT_DIR}/libreallyme_zk_platform_jni.so")"
    printf 'libcxx_shared_sha256\t%s\n' "$(sha256_file "${OUTPUT_DIR}/libc++_shared.so")"
  } >"${METADATA_PATH}"
}

if [[ ! -f "${PLATFORM_ARCHIVE}" ]]; then
  fail "PLATFORM_FFI_DIR must contain libreallyme_zk_platform_ffi.a"
fi
if [[ ! -f "${PLATFORM_HEADER}" ]]; then
  fail "PLATFORM_FFI_DIR must contain reallyme_zk_platform_abi.h"
fi
if [[ ! -f "${PLATFORM_LIBDEFLATE}" ]]; then
  fail "PLATFORM_FFI_DIR must contain libdeflate.a"
fi
if [[ ! -f "${PLATFORM_METADATA}" ]]; then
  fail "PLATFORM_FFI_DIR must contain ReallyMeZKPlatformFFI.build.tsv"
fi
if [[ "$(awk -F '\t' '$1 == "source_path_remapping" { print $2 }' "${PLATFORM_METADATA}")" != \
      "home-to-source-root-v1" ]]; then
  fail "Android platform archive was not built with portable source paths"
fi
if [[ "$(awk -F '\t' '$1 == "cargo_features" { print $2 }' "${PLATFORM_METADATA}")" == *diagnostic-exact-source* &&
      "${OUTPUT_ROOT}" == "${LOCAL_ARTIFACT_ROOT}/android-platform-jni" ]]; then
  fail "diagnostic-exact-source must use a separate OUTPUT_ROOT from the production Android JNI library"
fi
if [[ ! -x "${SOURCE_CLOSURE_SCRIPT}" ]]; then
  fail "Android JNI source closure script is unavailable"
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
ANDROID_CXX="${NDK_BIN}/aarch64-linux-android${ANDROID_API_LEVEL}-clang++"
ANDROID_STRIP="${NDK_BIN}/llvm-strip"
ANDROID_LIBCXX_SHARED="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${NDK_HOST_TAG}/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so"
if [[ ! -x "${ANDROID_CXX}" ]]; then
  fail "Android NDK clang++ is unavailable for API ${ANDROID_API_LEVEL}"
fi
if [[ ! -x "${ANDROID_STRIP}" ]]; then
  fail "Android NDK llvm-strip is unavailable"
fi
if [[ ! -f "${ANDROID_LIBCXX_SHARED}" ]]; then
  fail "Android NDK libc++_shared.so is unavailable for arm64-v8a"
fi

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

"${ANDROID_CXX}" \
  -shared \
  -fPIC \
  -fvisibility=hidden \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"${PLATFORM_HEADER_DIR}" \
  "${JNI_SOURCE}" \
  -Wl,--version-script="${JNI_EXPORTS}" \
  -Wl,--no-undefined \
  -Wl,--whole-archive "${PLATFORM_ARCHIVE}" -Wl,--no-whole-archive \
  "${PLATFORM_LIBDEFLATE}" \
  -lc++_shared \
  -llog \
  -latomic \
  -o "${OUTPUT_DIR}/libreallyme_zk_platform_jni.so"

"${ANDROID_STRIP}" \
  --strip-unneeded \
  "${OUTPUT_DIR}/libreallyme_zk_platform_jni.so"
if strings "${OUTPUT_DIR}/libreallyme_zk_platform_jni.so" | grep -F "${HOME}" >/dev/null; then
  fail "Android JNI library contains a build-host home path"
fi

"${ROOT}/scripts/check-platform-ffi-symbols.sh" \
  android-jni \
  "${OUTPUT_DIR}/libreallyme_zk_platform_jni.so"
cp "${ANDROID_LIBCXX_SHARED}" "${OUTPUT_DIR}/libc++_shared.so"
write_metadata

printf '%s\n' "${OUTPUT_DIR}"
