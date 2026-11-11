// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#ifndef REALLYME_ZK_BACKEND_BB_NATIVE_REALLYME_BBAPI_SHIM_H_
#define REALLYME_ZK_BACKEND_BB_NATIVE_REALLYME_BBAPI_SHIM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define REALLYME_BBAPI_NOEXCEPT noexcept
extern "C" {
#else
#define REALLYME_BBAPI_NOEXCEPT
#endif

#if defined(__GNUC__) || defined(__clang__)
#define REALLYME_BBAPI_INTERNAL __attribute__((visibility("hidden")))
#else
#define REALLYME_BBAPI_INTERNAL
#endif

#define REALLYME_BBAPI_STATUS_OK UINT32_C(0)
#define REALLYME_BBAPI_STATUS_NULL_ARGUMENT UINT32_C(1)
#define REALLYME_BBAPI_STATUS_EMPTY_INPUT UINT32_C(2)
#define REALLYME_BBAPI_STATUS_UPSTREAM_EXCEPTION UINT32_C(3)
#define REALLYME_BBAPI_STATUS_UPSTREAM_NULL_OUTPUT UINT32_C(4)
#define REALLYME_BBAPI_STATUS_UPSTREAM_EMPTY_OUTPUT UINT32_C(5)
#define REALLYME_BBAPI_STATUS_UPSTREAM_OUTPUT_TOO_LARGE UINT32_C(6)
#define REALLYME_BBAPI_STATUS_INPUT_TOO_LARGE UINT32_C(7)

REALLYME_BBAPI_INTERNAL uint32_t reallyme_bbapi_call(
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len) REALLYME_BBAPI_NOEXCEPT;

REALLYME_BBAPI_INTERNAL void reallyme_bbapi_free(uint8_t *ptr, size_t len) REALLYME_BBAPI_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#undef REALLYME_BBAPI_NOEXCEPT
#undef REALLYME_BBAPI_INTERNAL

#endif
