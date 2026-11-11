#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CXX_BIN="${CXX:-c++}"
WORK_DIR="${TMPDIR:-/tmp}/reallyme-bbapi-shim-test-$$"
mkdir -p "${WORK_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

cat >"${WORK_DIR}/fake_upstream.cc" <<'EOF'
#include <stddef.h>
#include <stdint.h>

#include <cstdlib>
#include <stdexcept>

extern "C" {
int reallyme_fake_bbapi_mode = 0;
unsigned int reallyme_fake_bbfree_calls = 0;
}

extern "C" void bbapi(
    const uint8_t *input_in,
    size_t input_len_in,
    uint8_t **output_out,
    size_t *output_len_out) {
  if (reallyme_fake_bbapi_mode == 1) {
    throw std::runtime_error("discarded upstream text");
  }
  if (reallyme_fake_bbapi_mode == 2) {
    throw 7;
  }
  if (reallyme_fake_bbapi_mode == 3) {
    *output_out = nullptr;
    *output_len_out = 9;
    return;
  }
  if (reallyme_fake_bbapi_mode == 5) {
    uint8_t *bytes = static_cast<uint8_t *>(std::malloc(3));
    if (bytes == nullptr) {
      throw std::bad_alloc();
    }
    bytes[0] = 0xD1;
    bytes[1] = 0xD2;
    bytes[2] = 0xD3;
    *output_out = bytes;
    *output_len_out = 3;
    throw std::runtime_error("discarded upstream text");
  }
  uint8_t *bytes = static_cast<uint8_t *>(std::malloc(3));
  if (bytes == nullptr) {
    throw std::bad_alloc();
  }
  bytes[0] = input_in[0];
  bytes[1] = static_cast<uint8_t>(input_len_in);
  bytes[2] = 0xA5;
  *output_out = bytes;
  *output_len_out = reallyme_fake_bbapi_mode == 4 ? 0 : 3;
}

extern "C" void bbfree(void *ptr) {
  ++reallyme_fake_bbfree_calls;
  std::free(ptr);
}
EOF

cat >"${WORK_DIR}/shim_test.cc" <<'EOF'
#include "reallyme_bbapi_shim.h"

#include <stddef.h>
#include <stdint.h>

extern "C" int reallyme_fake_bbapi_mode;
extern "C" unsigned int reallyme_fake_bbfree_calls;

namespace {

bool require(bool condition) {
  return condition;
}

bool status_rejects_null_arguments() {
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, sizeof(input), &output, nullptr) ==
                 REALLYME_BBAPI_STATUS_NULL_ARGUMENT) &&
         require(output == nullptr) &&
         require(output_len == 9);
}

bool status_rejects_empty_input() {
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, 0, &output, &output_len) ==
                 REALLYME_BBAPI_STATUS_EMPTY_INPUT) &&
         require(output == nullptr) &&
         require(output_len == 0);
}

bool status_rejects_oversized_input_before_upstream_dispatch() {
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  constexpr size_t kFirstRejectedInputLength = 67'109'569;
  return require(reallyme_bbapi_call(input, kFirstRejectedInputLength, &output,
                                    &output_len) ==
                 REALLYME_BBAPI_STATUS_INPUT_TOO_LARGE) &&
         require(output == nullptr) && require(output_len == 0);
}

bool status_passes_owned_output() {
  reallyme_fake_bbapi_mode = 0;
  uint8_t *output = nullptr;
  size_t output_len = 0;
  const uint8_t input[2] = {0x42, 0x99};
  const uint32_t status =
      reallyme_bbapi_call(input, sizeof(input), &output, &output_len);
  const bool ok = require(status == REALLYME_BBAPI_STATUS_OK) &&
                  require(output != nullptr) && require(output_len == 3) &&
                  require(output[0] == 0x42) && require(output[1] == 2) &&
                  require(output[2] == 0xA5);
  reallyme_bbapi_free(output, output_len);
  return ok && require(reallyme_fake_bbfree_calls == 1);
}

bool status_discards_standard_exception_text() {
  reallyme_fake_bbapi_mode = 1;
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, sizeof(input), &output, &output_len) ==
                 REALLYME_BBAPI_STATUS_UPSTREAM_EXCEPTION) &&
         require(output == nullptr) &&
         require(output_len == 0);
}

bool status_discards_unknown_exception() {
  reallyme_fake_bbapi_mode = 2;
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, sizeof(input), &output, &output_len) ==
                 REALLYME_BBAPI_STATUS_UPSTREAM_EXCEPTION) &&
         require(output == nullptr) &&
         require(output_len == 0);
}

bool status_cleans_output_allocated_before_exception() {
  reallyme_fake_bbapi_mode = 5;
  const unsigned int before = reallyme_fake_bbfree_calls;
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, sizeof(input), &output, &output_len) ==
                 REALLYME_BBAPI_STATUS_UPSTREAM_EXCEPTION) &&
         require(output == nullptr) &&
         require(output_len == 0) &&
         require(reallyme_fake_bbfree_calls == before + 1);
}

bool status_rejects_null_upstream_output() {
  reallyme_fake_bbapi_mode = 3;
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, sizeof(input), &output, &output_len) ==
                 REALLYME_BBAPI_STATUS_UPSTREAM_NULL_OUTPUT) &&
         require(output == nullptr) &&
         require(output_len == 0);
}

bool status_rejects_empty_upstream_output_and_frees_it() {
  reallyme_fake_bbapi_mode = 4;
  const unsigned int before = reallyme_fake_bbfree_calls;
  uint8_t *output = reinterpret_cast<uint8_t *>(1);
  size_t output_len = 9;
  const uint8_t input[1] = {0x11};
  return require(reallyme_bbapi_call(input, sizeof(input), &output, &output_len) ==
                 REALLYME_BBAPI_STATUS_UPSTREAM_EMPTY_OUTPUT) &&
         require(output == nullptr) &&
         require(output_len == 0) &&
         require(reallyme_fake_bbfree_calls == before + 1);
}

}  // namespace

int main() {
  if (!status_rejects_null_arguments()) {
    return 1;
  }
  if (!status_rejects_empty_input()) {
    return 1;
  }
  if (!status_rejects_oversized_input_before_upstream_dispatch()) {
    return 1;
  }
  if (!status_passes_owned_output()) {
    return 1;
  }
  if (!status_discards_standard_exception_text()) {
    return 1;
  }
  if (!status_discards_unknown_exception()) {
    return 1;
  }
  if (!status_cleans_output_allocated_before_exception()) {
    return 1;
  }
  if (!status_rejects_null_upstream_output()) {
    return 1;
  }
  if (!status_rejects_empty_upstream_output_and_frees_it()) {
    return 1;
  }
  return 0;
}
EOF

cat >"${WORK_DIR}/header_smoke.c" <<'EOF'
#include "reallyme_bbapi_shim.h"

typedef char reallyme_status_width[(REALLYME_BBAPI_STATUS_OK == 0U) ? 1 : -1];
EOF

"${CXX_BIN}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I "${ROOT}/crates/backend-bb/native" \
  "${ROOT}/crates/backend-bb/native/reallyme_bbapi_shim.cc" \
  "${WORK_DIR}/fake_upstream.cc" \
  "${WORK_DIR}/shim_test.cc" \
  -o "${WORK_DIR}/shim_test"

"${CC:-cc}" \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  -I "${ROOT}/crates/backend-bb/native" \
  -c "${WORK_DIR}/header_smoke.c" \
  -o "${WORK_DIR}/header_smoke.o"

"${WORK_DIR}/shim_test"
