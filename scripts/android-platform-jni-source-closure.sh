#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

(
  cd "${ROOT}"
  {
    printf '%s\n' "Cargo.lock"
    printf '%s\n' "Cargo.toml"
    find \
      crates/api \
      crates/artifacts \
      crates/backend-bb \
      crates/platform-ffi \
      crates/noir-witness-core \
      crates/proto \
      crates/proto-codec \
      packages/kotlin/native/jni \
      -type f \
      \( -name '*.rs' -o -name '*.toml' -o -name '*.h' -o -name '*.cc' -o -name '*.map' \) \
      -not -path '*/tests/*' \
      -not -name 'tests.rs' \
      -not -name '*_tests.rs' \
      -not -path '*/src/bin/*' \
      -not -path '*/target/*' \
      -print
  } | sort | while IFS= read -r source_path; do
    printf '%s  %s\n' "$(sha256_file "${ROOT}/${source_path}")" "${source_path}"
  done
)
