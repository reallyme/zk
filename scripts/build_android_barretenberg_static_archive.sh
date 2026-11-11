#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TOOLCHAIN_LOCK="${TOOLCHAIN_LOCK:-${ROOT}/circuits/toolchain-lock.json}"
case "$(uname -s)" in
  Darwin) DEFAULT_ANDROID_SDK_ROOT="${HOME}/Library/Android/sdk" ;;
  *) DEFAULT_ANDROID_SDK_ROOT="${HOME}/Android/Sdk" ;;
esac
ANDROID_SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${DEFAULT_ANDROID_SDK_ROOT}}}"
ANDROID_NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
CMAKE_BIN="${CMAKE_BIN:-cmake}"
NINJA_BIN="${NINJA_BIN:-ninja}"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"
OUTPUT_DIR="${OUTPUT_DIR:-${LOCAL_ARTIFACT_ROOT}/android-barretenberg-static/arm64-v8a}"
WORK_DIR="${WORK_DIR:-${ROOT}/target/android-barretenberg-static-install}"

fail() {
  printf 'Android Barretenberg static archive build failed: %s\n' "$1" >&2
  exit 2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command is unavailable: $1"
  fi
}

lock_value() {
  node -e '
const fs = require("fs");
const lock = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
let value = lock;
for (const part of process.argv[2].split(".")) {
  value = Array.isArray(value) ? value[Number(part)] : value[part];
  if (value === undefined) process.exit(3);
}
process.stdout.write(typeof value === "object" ? JSON.stringify(value) : String(value));
' "${TOOLCHAIN_LOCK}" "$1" || fail "missing lock value $1"
}

lock_fetch_commit() {
  node -e '
const fs = require("fs");
const lock = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const pin = lock.candidateMatchedPair.barretenberg.linkableStaticLibraries.androidArm64
  .fetchContentPins.find((entry) => entry.name === process.argv[2]);
if (!pin || !pin.commit) process.exit(3);
process.stdout.write(pin.commit);
' "${TOOLCHAIN_LOCK}" "$1" || fail "missing dependency pin $1"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

byte_size() {
  wc -c <"$1" | tr -d '[:space:]'
}

verify_file() {
  local label="$1" path="$2" expected_size="$3" expected_sha256="$4"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} is missing or not a regular file"
  [[ "$(byte_size "${path}")" == "${expected_size}" ]] ||
    fail "${label} size differs from the toolchain lock"
  [[ "$(sha256_file "${path}")" == "${expected_sha256}" ]] ||
    fail "${label} SHA-256 differs from the toolchain lock"
}

download_verified() {
  local label="$1" url="$2" path="$3" expected_size="$4" expected_sha256="$5"
  if [[ ! -f "${path}" ]] ||
    [[ "$(byte_size "${path}")" != "${expected_size}" ]] ||
    [[ "$(sha256_file "${path}")" != "${expected_sha256}" ]]; then
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --fail --silent --show-error --location --retry 3 \
      --output "${path}.download" "${url}"
    verify_file "${label} download" "${path}.download" "${expected_size}" "${expected_sha256}"
    mv "${path}.download" "${path}"
  fi
  verify_file "${label}" "${path}" "${expected_size}" "${expected_sha256}"
}

verify_checkout() {
  local name="$1" path="$2" expected actual
  expected="$(lock_fetch_commit "${name}")"
  [[ -d "${path}/.git" ]] || fail "dependency checkout ${name} is missing"
  actual="$(git -C "${path}" rev-parse HEAD)"
  [[ "${actual}" == "${expected}" ]] || fail "dependency checkout ${name} differs from the toolchain lock"
}

ndk_host_tag() {
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64 | Darwin:x86_64) printf '%s\n' 'darwin-x86_64' ;;
    Linux:x86_64) printf '%s\n' 'linux-x86_64' ;;
    *) fail "unsupported Android NDK host $(uname -s):$(uname -m)" ;;
  esac
}

[[ $# -eq 0 || ( $# -eq 1 && "$1" == '--verify-only' ) ]] || fail 'unsupported argument'
for command_name in node shasum awk wc tr; do
  require_command "${command_name}"
done

pin="candidateMatchedPair.barretenberg.linkableStaticLibraries.androidArm64"
companion="${pin}.companionStaticLibraries.0"
# NDK host executables record different BOLT/MLGO flags in ELF comments.
# Both complete archive identities are reviewed; executable bytes are equal.
archive_identity="${pin}"
if [[ "$(uname -s)" == Linux ]]; then
  archive_identity="${pin}.linuxSourceBuild"
fi
companion_identity="${archive_identity}.companionStaticLibraries.0"

# Restoring a build cache is not admission. Check the complete host-specific
# pair before linking or saving it, without requiring a compiler or network.
if [[ "${1:-}" == '--verify-only' ]]; then
  [[ -d "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] || fail 'archive directory is unavailable'
  verify_file 'libbb-external.a' "${OUTPUT_DIR}/libbb-external.a" \
    "$(lock_value "${archive_identity}.size")" "$(lock_value "${archive_identity}.sha256")"
  verify_file 'libdeflate.a' "${OUTPUT_DIR}/libdeflate.a" \
    "$(lock_value "${companion_identity}.size")" "$(lock_value "${companion_identity}.sha256")"
  exit 0
fi

for command_name in curl git tar mktemp cp mv grep sed "${CMAKE_BIN}" "${NINJA_BIN}"; do
  require_command "${command_name}"
done
ndk_version="$(lock_value "${pin}.androidNdkVersion")"
android_api="$(lock_value "${pin}.androidApiLevel")"
android_abi="$(lock_value "${pin}.androidAbi")"
android_stl="$(lock_value "${pin}.androidStl")"
expected_cmake="$(lock_value "${pin}.cmakeVersion")"
expected_ninja="$(lock_value "${pin}.ninjaVersion")"

if [[ -z "${ANDROID_NDK_ROOT}" ]]; then
  ANDROID_NDK_ROOT="${ANDROID_SDK_ROOT}/ndk/${ndk_version}"
fi
[[ -d "${ANDROID_NDK_ROOT}" ]] || fail "Android NDK ${ndk_version} is unavailable"
[[ "$(basename "${ANDROID_NDK_ROOT}")" == "${ndk_version}" ]] ||
  fail "Android NDK version differs from the toolchain lock"
[[ "$("${CMAKE_BIN}" --version | sed -n '1s/^cmake version //p')" == "${expected_cmake}" ]] ||
  fail "CMake version differs from the toolchain lock"
[[ "$("${NINJA_BIN}" --version)" == "${expected_ninja}" ]] ||
  fail "Ninja version differs from the toolchain lock"

case "${android_abi}" in
  arm64-v8a) android_target='aarch64-linux-android' ;;
  *) fail "unsupported Android ABI ${android_abi}" ;;
esac
ndk_bin="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/$(ndk_host_tag)/bin"
android_cc="${ndk_bin}/${android_target}${android_api}-clang"
android_cxx="${ndk_bin}/${android_target}${android_api}-clang++"
android_nm="${ndk_bin}/llvm-nm"
android_strip="${ndk_bin}/llvm-strip"
for executable in "${android_cc}" "${android_cxx}" "${android_nm}" "${android_strip}"; do
  [[ -x "${executable}" ]] || fail "required Android NDK tool is unavailable"
done

mkdir -p "${WORK_DIR}/downloads"
source_archive="${SOURCE_ARCHIVE:-${WORK_DIR}/downloads/$(lock_value "${pin}.sourceArchiveName")}"
if [[ -n "${SOURCE_ARCHIVE:-}" ]]; then
  verify_file \
    'caller-supplied Aztec source archive' \
    "${source_archive}" \
    "$(lock_value "${pin}.sourceArchiveSize")" \
    "$(lock_value "${pin}.sourceArchiveSha256")"
else
  download_verified \
    'Aztec source archive' \
    "$(lock_value "${pin}.sourceArchiveUrl")" \
    "${source_archive}" \
    "$(lock_value "${pin}.sourceArchiveSize")" \
    "$(lock_value "${pin}.sourceArchiveSha256")"
fi
libdeflate_source_archive="${WORK_DIR}/downloads/$(lock_value "${companion}.sourceArchiveName")"
download_verified \
  'libdeflate source archive' \
  "$(lock_value "${companion}.sourceArchiveUrl")" \
  "${libdeflate_source_archive}" \
  "$(lock_value "${companion}.sourceArchiveSize")" \
  "$(lock_value "${companion}.sourceArchiveSha256")"

build_root="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-zk-android-bb.XXXXXX")"
# macOS exposes /tmp through a symlink. Prefix maps must use the physical path
# so independent builds do not retain a machine-specific source directory.
build_root="$(cd "${build_root}" && pwd -P)"
trap 'rm -rf "${build_root}"' EXIT
tar -xzf "${source_archive}" -C "${build_root}"
tar -xzf "${libdeflate_source_archive}" -C "${build_root}"

source_root="${build_root}/$(lock_value "${pin}.sourceArchiveRootDirectory")"
upstream_cpp="${source_root}/$(lock_value "${pin}.sourceSubdirectory")"
isolated_cpp="${build_root}/cpp"
[[ -d "${upstream_cpp}" ]] || fail "Aztec source archive is missing the pinned Barretenberg source directory"

# Barretenberg generates this header from the surrounding Aztec monorepo during
# configuration. Generate it explicitly, verify it, and then isolate the C++
# tree so CMake cannot silently consume unpinned monorepo tooling.
generated_constants="${upstream_cpp}/src/barretenberg/aztec/aztec_constants.hpp"
node "${source_root}/protocol/constants-codegen/src/cli.ts" \
  --input "${source_root}/noir-projects/fnd/noir-protocol-circuits/crates/types/src/constants.nr" \
  --cpp "${generated_constants}" \
  --selection "${upstream_cpp}/scripts/constants-codegen/cpp.json"
[[ "$(sha256_file "${generated_constants}")" == "$(lock_value "${pin}.generatedConstantsSha256")" ]] ||
  fail "generated Aztec constants differ from the toolchain lock"
cp -R "${upstream_cpp}" "${isolated_cpp}"

path_map_flags="-ffile-prefix-map=${build_root}=. -fmacro-prefix-map=${build_root}=. -fdebug-prefix-map=${build_root}=."
libdeflate_build_dir="${build_root}/build"
"${CMAKE_BIN}" \
  -S "${build_root}/libdeflate-1.24" \
  -B "${libdeflate_build_dir}" \
  -G Ninja \
  -DCMAKE_MAKE_PROGRAM="${NINJA_BIN}" \
  -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK_ROOT}/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="${android_abi}" \
  -DANDROID_PLATFORM="android-${android_api}" \
  -DANDROID_STL="${android_stl}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="${path_map_flags}" \
  -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
  -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
  -DLIBDEFLATE_BUILD_GZIP=OFF \
  -DLIBDEFLATE_BUILD_TESTS=OFF
"${CMAKE_BIN}" --build "${libdeflate_build_dir}" --target libdeflate_static --config Release
staged_libdeflate="${build_root}/libdeflate.a"
cp "${libdeflate_build_dir}/libdeflate.a" "${staged_libdeflate}"
# CMake records its build-directory name in debug metadata. Reusing the
# reviewed build/ path for both independent configurations keeps the archive
# identity stable while the staged companion remains outside either tree.
rm -rf "${libdeflate_build_dir}"

build_dir="${build_root}/build"
"${CMAKE_BIN}" \
  -S "${isolated_cpp}" \
  -B "${build_dir}" \
  -G Ninja \
  -DCMAKE_MAKE_PROGRAM="${NINJA_BIN}" \
  -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK_ROOT}/build/cmake/android.toolchain.cmake" \
  -DCMAKE_C_COMPILER="${android_cc}" \
  -DCMAKE_CXX_COMPILER="${android_cxx}" \
  -DCMAKE_C_FLAGS="${path_map_flags}" \
  -DCMAKE_CXX_FLAGS="${path_map_flags}" \
  -DCMAKE_BUILD_TYPE="$(lock_value "${pin}.buildType")" \
  -DANDROID_ABI="${android_abi}" \
  -DANDROID_PLATFORM="android-${android_api}" \
  -DANDROID_STL="${android_stl}" \
  -DAVM=OFF \
  -DBB_LITE=ON \
  -DENABLE_PIC=ON

# Validate every network-populated dependency before compiling it into the
# release archive. msgpack-c is populated by its own build target, so it is
# deliberately materialized and checked first.
verify_checkout benchmark "${build_dir}/_deps/benchmark-src"
verify_checkout googletest "${build_dir}/_deps/gtest-src"
verify_checkout httplib "${build_dir}/_deps/httplib-src"
verify_checkout libdeflate "${build_dir}/_deps/libdeflate-src"
verify_checkout nlohmann_json "${build_dir}/_deps/nlohmann_json-src"
verify_checkout tracy "${build_dir}/_deps/tracy-src"
"${CMAKE_BIN}" --build "${build_dir}" --target msgpack-c --config Release
verify_checkout msgpack-c "${build_dir}/_deps/msgpack-c/src/msgpack-c"
"${CMAKE_BIN}" --build "${build_dir}" --target bb-external --config Release

raw_bb="${build_dir}/lib/libbb-external.a"
raw_libdeflate="${staged_libdeflate}"
[[ -f "${raw_bb}" ]] || fail "Barretenberg build did not produce libbb-external.a"
[[ -f "${raw_libdeflate}" ]] || fail "Barretenberg build did not produce libdeflate.a"
# Strip both archives before checking their identities. NDK header paths in
# companion debug records otherwise make the digest depend on the build host.
"${android_strip}" --strip-debug "${raw_bb}"
"${android_strip}" --strip-debug "${raw_libdeflate}"

symbols_file="${build_root}/undefined-symbols.txt"
"${android_nm}" --undefined-only --demangle "${raw_bb}" >"${symbols_file}"
if grep -Fq 'std::__1::' "${symbols_file}"; then
  fail "Barretenberg archive uses the non-Android libc++ ABI namespace"
fi
grep -Fq 'std::__ndk1::' "${symbols_file}" ||
  fail "Barretenberg archive does not expose the expected Android libc++ ABI namespace"

# Retain explicitly requested reproduction inputs separately from admitted
# output. A failed hash check still prevents publication of either archive.
if [[ -n "${REALLYME_ZK_ANDROID_REPRO_DIAGNOSTICS_DIR:-}" ]]; then
  diagnostics="${REALLYME_ZK_ANDROID_REPRO_DIAGNOSTICS_DIR}"
  [[ "${diagnostics}" == /* && ! -e "${diagnostics}" && ! -L "${diagnostics}" ]] ||\
    fail "reproduction diagnostics path must be absent and absolute"
  if [[ "${diagnostics}" == "${OUTPUT_DIR}" || "${diagnostics}" == "${OUTPUT_DIR}/"* ||
        "${OUTPUT_DIR}" == "${diagnostics}/"* ]]; then
    fail "reproduction diagnostics must remain outside the admitted output"
  fi
  mkdir -m 0700 "${diagnostics}"
  cp "${raw_bb}" "${diagnostics}/libbb-external.a"
  cp "${raw_libdeflate}" "${diagnostics}/libdeflate.a"
  {
    printf 'archive\tactual_sha256\texpected_sha256\n'
    printf 'libbb-external.a\t%s\t%s\n' "$(sha256_file "${raw_bb}")" "$(lock_value "${archive_identity}.sha256")"
    printf 'libdeflate.a\t%s\t%s\n' "$(sha256_file "${raw_libdeflate}")" "$(lock_value "${companion_identity}.sha256")"
  } >"${diagnostics}/identities.tsv"
fi

verify_file \
  'libbb-external.a' \
  "${raw_bb}" \
  "$(lock_value "${archive_identity}.size")" \
  "$(lock_value "${archive_identity}.sha256")"
verify_file \
  'libdeflate.a' \
  "${raw_libdeflate}" \
  "$(lock_value "${companion_identity}.size")" \
  "$(lock_value "${companion_identity}.sha256")"

publish_dir="${OUTPUT_DIR}.publish.$$"
backup_dir="${OUTPUT_DIR}.previous.$$"
[[ ! -e "${publish_dir}" && ! -e "${backup_dir}" ]] || fail "publish staging path already exists"
mkdir -p "$(dirname "${OUTPUT_DIR}")" "${publish_dir}"
cp "${raw_bb}" "${publish_dir}/libbb-external.a"
cp "${raw_libdeflate}" "${publish_dir}/libdeflate.a"
{
  printf 'key\tvalue\n'
  printf 'format\tandroid-barretenberg-static-v1\n'
  printf 'source_archive_sha256\t%s\n' "$(lock_value "${pin}.sourceArchiveSha256")"
  printf 'generated_constants_sha256\t%s\n' "$(lock_value "${pin}.generatedConstantsSha256")"
  printf 'barretenberg_archive_sha256\t%s\n' "$(sha256_file "${raw_bb}")"
  printf 'barretenberg_archive_size\t%s\n' "$(byte_size "${raw_bb}")"
  printf 'libdeflate_archive_sha256\t%s\n' "$(sha256_file "${raw_libdeflate}")"
  printf 'libdeflate_archive_size\t%s\n' "$(byte_size "${raw_libdeflate}")"
  printf 'android_ndk_version\t%s\n' "${ndk_version}"
  printf 'android_api_level\t%s\n' "${android_api}"
  printf 'android_abi\t%s\n' "${android_abi}"
  printf 'android_stl\t%s\n' "${android_stl}"
  printf 'cmake_version\t%s\n' "${expected_cmake}"
  printf 'ninja_version\t%s\n' "${expected_ninja}"
} >"${publish_dir}/build.tsv"

if [[ -e "${OUTPUT_DIR}" ]]; then
  [[ -d "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] || fail "output path is not a regular directory"
  mv "${OUTPUT_DIR}" "${backup_dir}"
fi
if ! mv "${publish_dir}" "${OUTPUT_DIR}"; then
  if [[ -d "${backup_dir}" && ! -e "${OUTPUT_DIR}" ]]; then
    mv "${backup_dir}" "${OUTPUT_DIR}" || true
  fi
  fail "publishing verified output failed"
fi
if [[ -d "${backup_dir}" ]]; then
  rm -rf "${backup_dir}"
fi
printf '%s\n' "${OUTPUT_DIR}"
