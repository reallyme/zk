#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOCAL_ARTIFACT_ROOT="${REALLYME_ZK_LOCAL_ARTIFACT_ROOT:-${ROOT}/build/native}"
DIAGNOSTIC_FFI_DIR="${LOCAL_ARTIFACT_ROOT}/android-platform-ffi-diagnostic/arm64-v8a"
DIAGNOSTIC_JNI_ROOT="${LOCAL_ARTIFACT_ROOT}/android-platform-jni-diagnostic"

PLATFORM_FFI_FEATURES="native,diagnostic-exact-source" \
  OUTPUT_DIR="${DIAGNOSTIC_FFI_DIR}" \
  "${ROOT}/scripts/build_android_platform_ffi_static.sh"

PLATFORM_FFI_DIR="${DIAGNOSTIC_FFI_DIR}" \
  OUTPUT_ROOT="${DIAGNOSTIC_JNI_ROOT}" \
  "${ROOT}/scripts/build_android_platform_jni.sh"
