#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLATFORM_ABI_HEADER="${REPO_ROOT}/crates/proto-codec/include/reallyme_zk_platform_abi.h"
PLATFORM="${1:-}"
ARCHIVE="${2:-}"

fail() {
  echo "platform ffi symbol check failed: $1" >&2
  exit 2
}

if [[ "${PLATFORM}" != "apple" && "${PLATFORM}" != "apple-linked" && "${PLATFORM}" != "android" && "${PLATFORM}" != "android-jni" ]]; then
  fail "first argument must be apple, apple-linked, android, or android-jni"
fi
if [[ -z "${ARCHIVE}" || ! -f "${ARCHIVE}" ]]; then
  fail "second argument must name an existing static archive"
fi

require_public_symbol() {
  local symbol="$1"
  local symbols_file="$2"
  if ! grep -Eq "(^|[[:space:]])${symbol}$" "${symbols_file}"; then
    fail "${symbol} is not exported by ${ARCHIVE}"
  fi
}

require_header_text() {
  local text="$1"
  if ! grep -Fq "${text}" "${PLATFORM_ABI_HEADER}"; then
    fail "${PLATFORM_ABI_HEADER} does not contain ${text}"
  fi
}

find_llvm_readelf() {
  if [[ -n "${LLVM_READELF:-}" && -x "${LLVM_READELF}" ]]; then
    printf '%s\n' "${LLVM_READELF}"
    return
  fi
  # Android CI already installs an NDK. Its ELF inspector supports the target
  # ABI without depending on an unrelated host LLVM package or PATH layout.
  local ndk_root host_tag="" candidate
  case "$(uname -s)" in
    Darwin) host_tag="darwin-x86_64" ;;
    Linux) host_tag="linux-x86_64" ;;
  esac
  for ndk_root in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${ANDROID_NDK_LATEST_HOME:-}"; do
    if [[ -n "${ndk_root}" && -n "${host_tag}" ]]; then
      candidate="${ndk_root}/toolchains/llvm/prebuilt/${host_tag}/bin/llvm-readelf"
      if [[ -x "${candidate}" ]]; then
        printf '%s\n' "${candidate}"
        return
      fi
    fi
  done
  if command -v llvm-readelf >/dev/null 2>&1; then
    command -v llvm-readelf
    return
  fi
  for candidate in \
    /opt/homebrew/opt/llvm/bin/llvm-readelf \
    /usr/local/opt/llvm/bin/llvm-readelf \
    /opt/homebrew/Cellar/llvm/*/bin/llvm-readelf \
    /usr/local/Cellar/llvm/*/bin/llvm-readelf; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
  fail "llvm-readelf is required for Android visibility checks"
}

find_llvm_nm() {
  if [[ -n "${LLVM_NM:-}" && -x "${LLVM_NM}" ]]; then
    printf '%s\n' "${LLVM_NM}"
    return
  fi
  if command -v llvm-nm >/dev/null 2>&1; then
    command -v llvm-nm
    return
  fi
  # rustup installs llvm-tools-preview under the active toolchain rather than
  # on PATH. CI installs that component to match the Rust archive's LLVM IR.
  if command -v rustc >/dev/null 2>&1; then
    local sysroot host candidate
    sysroot="$(rustc --print sysroot)"
    host="$(rustc -vV | sed -n 's/^host: //p')"
    candidate="${sysroot}/lib/rustlib/${host}/bin/llvm-nm"
    if [[ -n "${host}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  fi
  for candidate in \
    /opt/homebrew/opt/llvm/bin/llvm-nm \
    /usr/local/opt/llvm/bin/llvm-nm \
    /opt/homebrew/Cellar/llvm/*/bin/llvm-nm \
    /usr/local/Cellar/llvm/*/bin/llvm-nm; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
  fail "llvm-nm is required for Apple Rust archive symbol checks"
}

TMP_SYMBOLS="$(mktemp)"
TMP_PRIVATE_SYMBOLS="$(mktemp)"
TMP_UNDEFINED_SYMBOLS="$(mktemp)"
trap 'rm -f "${TMP_SYMBOLS}" "${TMP_PRIVATE_SYMBOLS}" "${TMP_UNDEFINED_SYMBOLS}"' EXIT

require_header_text "release_index_sha256_ptr"

case "${PLATFORM}" in
  apple)
    llvm_nm_bin="$(find_llvm_nm)"
    "${llvm_nm_bin}" --defined-only "${ARCHIVE}" >"${TMP_SYMBOLS}" 2>/dev/null
    require_public_symbol "_reallyme_zk_platform_context_create" "${TMP_SYMBOLS}"
    require_public_symbol "_reallyme_zk_platform_context_create_with_crs_files" "${TMP_SYMBOLS}"
    require_public_symbol "_reallyme_zk_platform_dispatch" "${TMP_SYMBOLS}"
    require_public_symbol "_reallyme_zk_platform_context_destroy" "${TMP_SYMBOLS}"
    require_public_symbol "_reallyme_zk_platform_buffer_destroy" "${TMP_SYMBOLS}"
    require_public_symbol "_reallyme_zk_platform_encode_failure_response" "${TMP_SYMBOLS}"
    nm -m "${ARCHIVE}" >"${TMP_PRIVATE_SYMBOLS}" 2>/dev/null || true
    if ! grep -Eq "private external _reallyme_bbapi_call$" "${TMP_PRIVATE_SYMBOLS}"; then
      fail "raw bbapi call symbol is not private external in ${ARCHIVE}"
    fi
    if ! grep -Eq "private external _reallyme_bbapi_free$" "${TMP_PRIVATE_SYMBOLS}"; then
      fail "raw bbapi free symbol is not private external in ${ARCHIVE}"
    fi
    ;;
  apple-linked)
    nm -gU "${ARCHIVE}" >"${TMP_SYMBOLS}" 2>/dev/null
    require_public_symbol "_main" "${TMP_SYMBOLS}"
    if grep -Eq "(^|[[:space:]])_(reallyme_bbapi_call|reallyme_bbapi_free|bbapi|bbmalloc|bbfree)$" "${TMP_SYMBOLS}"; then
      fail "raw upstream proving symbols are exported by linked Apple image ${ARCHIVE}"
    fi
    ;;
  android)
    llvm_readelf_bin="$(find_llvm_readelf)"
    "${llvm_readelf_bin}" -Ws "${ARCHIVE}" >"${TMP_SYMBOLS}"
    require_public_symbol "reallyme_zk_platform_context_create" "${TMP_SYMBOLS}"
    require_public_symbol "reallyme_zk_platform_context_create_with_crs_files" "${TMP_SYMBOLS}"
    require_public_symbol "reallyme_zk_platform_dispatch" "${TMP_SYMBOLS}"
    require_public_symbol "reallyme_zk_platform_context_destroy" "${TMP_SYMBOLS}"
    require_public_symbol "reallyme_zk_platform_buffer_destroy" "${TMP_SYMBOLS}"
    require_public_symbol "reallyme_zk_platform_encode_failure_response" "${TMP_SYMBOLS}"
    if ! grep -Eq "FUNC[[:space:]]+GLOBAL[[:space:]]+HIDDEN[[:space:]]+[0-9]+[[:space:]]+reallyme_bbapi_call$" "${TMP_SYMBOLS}"; then
      fail "raw bbapi call symbol is not hidden in ${ARCHIVE}"
    fi
    if ! grep -Eq "FUNC[[:space:]]+GLOBAL[[:space:]]+HIDDEN[[:space:]]+[0-9]+[[:space:]]+reallyme_bbapi_free$" "${TMP_SYMBOLS}"; then
      fail "raw bbapi free symbol is not hidden in ${ARCHIVE}"
    fi
    ;;
  android-jni)
    llvm_readelf_bin="$(find_llvm_readelf)"
    "${llvm_readelf_bin}" --dyn-syms "${ARCHIVE}" >"${TMP_SYMBOLS}"
    # Materialize the full symbol list before matching. A short-circuiting
    # grep can otherwise SIGPIPE awk under pipefail and hide a forbidden symbol.
    awk '$7 == "UND" {print $8}' "${TMP_SYMBOLS}" >"${TMP_UNDEFINED_SYMBOLS}"
    if grep -Eq "^(_ZN(2bb|11acir_format)|bbapi|bbmalloc|bbfree)" "${TMP_UNDEFINED_SYMBOLS}"; then
      fail "JNI library has unresolved internal Barretenberg symbols in ${ARCHIVE}"
    fi
    awk '$7 != "UND" && $5 == "GLOBAL" {print $8}' "${TMP_SYMBOLS}" \
      >"${TMP_PRIVATE_SYMBOLS}"
    require_public_symbol "Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreate" "${TMP_PRIVATE_SYMBOLS}"
    require_public_symbol "Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreateWithCrsFiles" "${TMP_PRIVATE_SYMBOLS}"
    require_public_symbol "Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeDispatch" "${TMP_PRIVATE_SYMBOLS}"
    require_public_symbol "Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextDestroy" "${TMP_PRIVATE_SYMBOLS}"
    if grep -Eq "reallyme_zk_platform|reallyme_bbapi" "${TMP_PRIVATE_SYMBOLS}"; then
      fail "raw platform symbols are exported by ${ARCHIVE}"
    fi
    if grep -Evq "^Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_native(ContextCreate|ContextCreateWithCrsFiles|Dispatch|ContextDestroy)$" "${TMP_PRIVATE_SYMBOLS}"; then
      fail "unexpected global JNI library export in ${ARCHIVE}"
    fi
    ;;
esac

printf '%s\n' "platform ffi symbol check passed for ${PLATFORM}: ${ARCHIVE}"
