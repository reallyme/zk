#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

DEST="${1:?pass an absent absolute destination directory}"
ANDROID_SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Android/Sdk}}"
ANDROID_NDK_VERSION="28.2.13676358"
CMAKE_VERSION="4.4.5"
CMAKE_ARCHIVE="cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz"
CMAKE_URL="https://cmake.org/files/v4.4/${CMAKE_ARCHIVE}"
CMAKE_SHA256="ed85135c5a5135b45e50423cb406dea04ca3338da0b8ef3c9ede963559680be0"
NINJA_VERSION="1.13.2"
NINJA_ARCHIVE="ninja-linux-${NINJA_VERSION}.zip"
NINJA_URL="https://github.com/ninja-build/ninja/releases/download/v${NINJA_VERSION}/ninja-linux.zip"
NINJA_SHA256="5749cbc4e668273514150a80e387a957f933c6ed3f5f11e03fb30955e2bbead6"

fail() {
  printf 'Android native CI toolchain installation failed: %s\n' "$1" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    fail "required command is unavailable: ${command_name}"
  fi
}

download_pinned() {
  local url="$1" target="$2" digest="$3"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --output "${target}" "${url}"
  printf '%s  %s\n' "${digest}" "${target}" | sha256sum --check --strict >/dev/null ||
    fail "downloaded hash differs from pinned ${target}"
}

if [[ "$(uname -s):$(uname -m)" != "Linux:x86_64" ]]; then
  fail "this installer is restricted to Linux x86_64"
fi
if [[ "${DEST}" != /* || -e "${DEST}" ]]; then
  fail "destination must be an absent absolute path"
fi

for command_name in curl sha256sum tar unzip java; do
  require_command "${command_name}"
done

SDKMANAGER="${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"
if [[ ! -x "${SDKMANAGER}" ]]; then
  fail "sdkmanager is unavailable at ${SDKMANAGER}"
fi

mkdir -m 0700 "${DEST}"
mkdir -m 0700 "${DEST}/downloads" "${DEST}/cmake" "${DEST}/ninja"

"${SDKMANAGER}" --install "ndk;${ANDROID_NDK_VERSION}" >/dev/null
ANDROID_NDK_ROOT="${ANDROID_SDK_ROOT}/ndk/${ANDROID_NDK_VERSION}"
if [[ ! -d "${ANDROID_NDK_ROOT}" ]]; then
  fail "sdkmanager did not install pinned NDK ${ANDROID_NDK_VERSION}"
fi
if ! grep -qx "Pkg.Revision = ${ANDROID_NDK_VERSION}" "${ANDROID_NDK_ROOT}/source.properties"; then
  fail "installed NDK source.properties does not match ${ANDROID_NDK_VERSION}"
fi
if [[ ! -x "${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" ]]; then
  fail "installed NDK does not contain the expected Linux arm64 compiler wrapper"
fi

download_pinned "${CMAKE_URL}" "${DEST}/downloads/${CMAKE_ARCHIVE}" "${CMAKE_SHA256}"
tar -xzf "${DEST}/downloads/${CMAKE_ARCHIVE}" -C "${DEST}/cmake" \
  --strip-components=1 --no-same-owner --no-same-permissions
CMAKE_BIN="${DEST}/cmake/bin/cmake"
if [[ "$("${CMAKE_BIN}" --version | sed -n '1s/^cmake version //p')" != "${CMAKE_VERSION}" ]]; then
  fail "installed CMake does not report ${CMAKE_VERSION}"
fi

download_pinned "${NINJA_URL}" "${DEST}/downloads/${NINJA_ARCHIVE}" "${NINJA_SHA256}"
unzip -q "${DEST}/downloads/${NINJA_ARCHIVE}" -d "${DEST}/ninja"
NINJA_BIN="${DEST}/ninja/ninja"
chmod 0500 "${NINJA_BIN}"
if [[ "$("${NINJA_BIN}" --version)" != "${NINJA_VERSION}" ]]; then
  fail "installed Ninja does not report ${NINJA_VERSION}"
fi

printf 'Pinned Android native CI toolchain installed at %s\n' "${DEST}"
printf 'ANDROID_NDK_ROOT=%s\n' "${ANDROID_NDK_ROOT}"
printf 'CMAKE_BIN=%s\n' "${CMAKE_BIN}"
printf 'NINJA_BIN=%s\n' "${NINJA_BIN}"
