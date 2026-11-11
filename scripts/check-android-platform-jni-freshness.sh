#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"
PLATFORM_FFI_DIR="${PLATFORM_FFI_DIR:-${LOCAL_ARTIFACT_ROOT}/android-platform-ffi/arm64-v8a}"
OUTPUT_ROOT="${OUTPUT_ROOT:-${LOCAL_ARTIFACT_ROOT}/android-platform-jni}"
EXPECTED_CARGO_FEATURES="${EXPECTED_CARGO_FEATURES:-native}"
OUTPUT_DIR="${OUTPUT_DIR:-${OUTPUT_ROOT}/arm64-v8a}"
METADATA_PATH="${METADATA_PATH:-${OUTPUT_ROOT}/ReallyMeZKPlatformJNI.build.tsv}"
JNI_SOURCE="${ROOT}/packages/kotlin/native/jni/reallyme_zk_platform_jni.cc"
JNI_EXPORTS="${ROOT}/packages/kotlin/native/jni/reallyme_zk_platform_jni.map"
PLATFORM_ARCHIVE="${PLATFORM_FFI_DIR}/libreallyme_zk_platform_ffi.a"
PLATFORM_LIBDEFLATE="${PLATFORM_FFI_DIR}/libdeflate.a"
PLATFORM_METADATA="${PLATFORM_FFI_DIR}/ReallyMeZKPlatformFFI.build.tsv"
PLATFORM_HEADER="${PLATFORM_FFI_DIR}/reallyme_zk_platform_abi.h"
JNI_LIBRARY="${OUTPUT_DIR}/libreallyme_zk_platform_jni.so"
LIBCXX_SHARED="${OUTPUT_DIR}/libc++_shared.so"
SOURCE_CLOSURE_SCRIPT="${ROOT}/scripts/android-platform-jni-source-closure.sh"

fail() {
  echo "android platform jni freshness check failed: $1" >&2
  exit 2
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

metadata_value() {
  awk -F '\t' -v key="$1" 'NR > 1 && $1 == key { print $2 }' "${METADATA_PATH}"
}

platform_metadata_value() {
  awk -F '\t' -v key="$1" 'NR > 1 && $1 == key { print $2 }' "${PLATFORM_METADATA}"
}

source_closure_sha256() {
  "${SOURCE_CLOSURE_SCRIPT}" | shasum -a 256 | awk '{print $1}'
}

platform_source_closure_sha256() {
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
  ) | shasum -a 256 | awk '{ print $1 }'
}

require_file() {
  if [[ ! -f "$1" ]]; then
    fail "missing required file $1"
  fi
}

require_file "${METADATA_PATH}"
require_file "${PLATFORM_ARCHIVE}"
require_file "${PLATFORM_LIBDEFLATE}"
require_file "${PLATFORM_METADATA}"
require_file "${PLATFORM_HEADER}"
require_file "${JNI_SOURCE}"
require_file "${JNI_EXPORTS}"
require_file "${JNI_LIBRARY}"
require_file "${LIBCXX_SHARED}"
require_file "${SOURCE_CLOSURE_SCRIPT}"
if [[ ! -x "${SOURCE_CLOSURE_SCRIPT}" ]]; then
  fail "Android JNI source closure script is not executable"
fi

if [[ "$(metadata_value format)" != "android-platform-jni-v1" ]]; then
  fail "metadata format is unsupported"
fi
if [[ "$(platform_metadata_value format)" != "android-platform-ffi-v1" ]]; then
  fail "Android platform FFI metadata format is unsupported"
fi
if [[ "$(platform_metadata_value source_path_remapping)" != "home-to-source-root-v1" ]]; then
  fail "Android platform FFI was not built with portable source paths"
fi
if [[ "$(platform_metadata_value cargo_profile)" != "mobile-release" ]]; then
  fail "Android platform FFI was not built with the reviewed mobile Cargo profile"
fi
if [[ "${EXPECTED_CARGO_FEATURES}" != "native" &&
      "${EXPECTED_CARGO_FEATURES}" != "native,diagnostic-exact-source" ]]; then
  fail "requested Android Cargo feature set is unsupported"
fi
if [[ "${EXPECTED_CARGO_FEATURES}" == "native,diagnostic-exact-source" &&
      "${OUTPUT_ROOT}" == "${LOCAL_ARTIFACT_ROOT}/android-platform-jni" ]]; then
  fail "diagnostic freshness must use a separate output root"
fi
if [[ "$(platform_metadata_value cargo_features)" != "${EXPECTED_CARGO_FEATURES}" ]]; then
  fail "Android platform FFI Cargo features do not match the requested package mode"
fi
if [[ "$(metadata_value source_closure_sha256)" != "$(source_closure_sha256)" ]]; then
  fail "Android JNI metadata source closure is stale"
fi
if [[ -z "$(platform_metadata_value source_closure_sha256)" ]]; then
  fail "Android platform FFI metadata does not record a source closure"
fi
if [[ "$(platform_metadata_value source_closure_sha256)" != \
      "$(platform_source_closure_sha256)" ]]; then
  fail "Android platform FFI source closure is stale"
fi
if [[ "$(metadata_value platform_archive_sha256)" != "$(sha256_file "${PLATFORM_ARCHIVE}")" ]]; then
  fail "Android platform archive changed since JNI was built"
fi
if [[ "$(platform_metadata_value platform_archive_sha256)" != "$(sha256_file "${PLATFORM_ARCHIVE}")" ]]; then
  fail "Android platform archive does not match platform FFI metadata"
fi
if [[ "$(metadata_value platform_libdeflate_sha256)" != "$(sha256_file "${PLATFORM_LIBDEFLATE}")" ]]; then
  fail "Android libdeflate archive changed since JNI was built"
fi
if [[ "$(platform_metadata_value platform_libdeflate_sha256)" != "$(sha256_file "${PLATFORM_LIBDEFLATE}")" ]]; then
  fail "Android libdeflate archive does not match platform FFI metadata"
fi
if [[ "$(metadata_value platform_header_sha256)" != "$(sha256_file "${PLATFORM_HEADER}")" ]]; then
  fail "Android platform ABI header changed since JNI was built"
fi
if [[ "$(platform_metadata_value platform_header_sha256)" != "$(sha256_file "${PLATFORM_HEADER}")" ]]; then
  fail "Android platform ABI header does not match platform FFI metadata"
fi
if [[ "$(metadata_value platform_metadata_sha256)" != "$(sha256_file "${PLATFORM_METADATA}")" ]]; then
  fail "Android platform FFI metadata changed since JNI was built"
fi
if [[ "$(metadata_value jni_source_sha256)" != "$(sha256_file "${JNI_SOURCE}")" ]]; then
  fail "Android JNI source changed since JNI was built"
fi
if [[ "$(metadata_value jni_exports_sha256)" != "$(sha256_file "${JNI_EXPORTS}")" ]]; then
  fail "Android JNI export map changed since JNI was built"
fi
if [[ "$(metadata_value jni_library_sha256)" != "$(sha256_file "${JNI_LIBRARY}")" ]]; then
  fail "Android JNI library does not match build metadata"
fi
if [[ "$(metadata_value libcxx_shared_sha256)" != "$(sha256_file "${LIBCXX_SHARED}")" ]]; then
  fail "Android libc++ shared library does not match build metadata"
fi

"${ROOT}/scripts/check-platform-ffi-symbols.sh" android-jni "${JNI_LIBRARY}"
printf '%s\n' "android platform jni freshness check passed"
