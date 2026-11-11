// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#include "reallyme_bbapi_shim.h"

#include <exception>

#if defined(__GNUC__) || defined(__clang__)
#define REALLYME_BBAPI_DEFINITION_VISIBILITY __attribute__((visibility("hidden")))
#else
#define REALLYME_BBAPI_DEFINITION_VISIBILITY
#endif

extern "C" void bbapi(
    const uint8_t *input_in,
    size_t input_len_in,
    uint8_t **output_out,
    size_t *output_len_out);

extern "C" void bbfree(void *ptr);

namespace {

constexpr size_t kReallyMeBbapiMaxOutputBytes = 16 * 1024 * 1024;
// The largest admitted request is SrsInitSrs with the suite-wide prover G1
// prefix. Keep this defense in the C ABI itself because platform callers must
// not be able to bypass Rust-side MessagePack length validation.
constexpr size_t kReallyMeBbapiMaxInputBytes = 67'109'568;

void wipe_bytes(uint8_t *ptr, size_t len) noexcept {
  if (ptr == nullptr) {
    return;
  }
  volatile uint8_t *cursor = ptr;
  for (size_t index = 0; index < len; ++index) {
    cursor[index] = 0;
  }
}

void free_upstream_output(uint8_t *ptr, size_t len) noexcept {
  if (ptr == nullptr) {
    return;
  }
  if (len <= kReallyMeBbapiMaxOutputBytes) {
    wipe_bytes(ptr, len);
  }
  try {
    bbfree(ptr);
  } catch (...) {
  }
}

}  // namespace

REALLYME_BBAPI_DEFINITION_VISIBILITY uint32_t reallyme_bbapi_call(
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len) noexcept {
  if (output != nullptr) {
    *output = nullptr;
  }
  if (output_len != nullptr) {
    *output_len = 0;
  }
  if (input == nullptr || output == nullptr || output_len == nullptr) {
    return REALLYME_BBAPI_STATUS_NULL_ARGUMENT;
  }
  if (input_len == 0) {
    return REALLYME_BBAPI_STATUS_EMPTY_INPUT;
  }
  if (input_len > kReallyMeBbapiMaxInputBytes) {
    return REALLYME_BBAPI_STATUS_INPUT_TOO_LARGE;
  }

  uint8_t *upstream_output = nullptr;
  size_t upstream_output_len = 0;
  try {
    bbapi(input, input_len, &upstream_output, &upstream_output_len);
  } catch (const std::exception &) {
    free_upstream_output(upstream_output, upstream_output_len);
    return REALLYME_BBAPI_STATUS_UPSTREAM_EXCEPTION;
  } catch (...) {
    free_upstream_output(upstream_output, upstream_output_len);
    return REALLYME_BBAPI_STATUS_UPSTREAM_EXCEPTION;
  }

  if (upstream_output == nullptr) {
    return REALLYME_BBAPI_STATUS_UPSTREAM_NULL_OUTPUT;
  }
  if (upstream_output_len > kReallyMeBbapiMaxOutputBytes) {
    free_upstream_output(upstream_output, upstream_output_len);
    return REALLYME_BBAPI_STATUS_UPSTREAM_OUTPUT_TOO_LARGE;
  }
  if (upstream_output_len == 0) {
    free_upstream_output(upstream_output, upstream_output_len);
    return REALLYME_BBAPI_STATUS_UPSTREAM_EMPTY_OUTPUT;
  }

  *output = upstream_output;
  *output_len = upstream_output_len;
  return REALLYME_BBAPI_STATUS_OK;
}

REALLYME_BBAPI_DEFINITION_VISIBILITY void reallyme_bbapi_free(uint8_t *ptr, size_t len) noexcept {
  free_upstream_output(ptr, len);
}

#undef REALLYME_BBAPI_DEFINITION_VISIBILITY
