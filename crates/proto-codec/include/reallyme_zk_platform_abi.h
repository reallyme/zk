// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#ifndef REALLYME_ZK_PLATFORM_ABI_H_
#define REALLYME_ZK_PLATFORM_ABI_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REALLYME_ZK_PLATFORM_STATUS_OK 0u
#define REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT 1u
#define REALLYME_ZK_PLATFORM_STATUS_INVALID_ERROR_REASON 2u
#define REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE 3u
#define REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE 4u
#define REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC 5u
#define REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER 6u
#define REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT 7u
#define REALLYME_ZK_PLATFORM_STATUS_INVALID_MODE 8u
#define REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY 9u

#define REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY 1u
#define REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER 2u

typedef struct reallyme_zk_platform_buffer {
  uint8_t *ptr;
  size_t len;
  size_t capacity;
  size_t owner_id;
} reallyme_zk_platform_buffer_t;

typedef struct reallyme_zk_platform_status {
  uint32_t status_code;
  uint32_t error_reason_code;
} reallyme_zk_platform_status_t;

typedef struct reallyme_zk_platform_result {
  uint32_t status_code;
  uint32_t error_reason_code;
  reallyme_zk_platform_buffer_t output;
} reallyme_zk_platform_result_t;

typedef struct reallyme_zk_platform_context reallyme_zk_platform_context_t;

typedef struct reallyme_zk_platform_context_result {
  uint32_t status_code;
  uint32_t error_reason_code;
  reallyme_zk_platform_context_t *context;
} reallyme_zk_platform_context_result_t;

// Encodes a canonical reallyme.zk.v1.ZkProviderOperationResponse failure
// envelope bound to the SHA-256 of the supplied request bytes. The request may
// be malformed; the error_reason_code must be a defined ZkErrorReason value.
reallyme_zk_platform_result_t reallyme_zk_platform_encode_failure_response(
    const uint8_t *request_ptr, size_t request_len,
    uint32_t error_reason_code);

// Creates a pinned platform provider context. The artifact root is a UTF-8
// absolute path. The release index is a canonical ZkReleaseIndex protobuf and
// must match the caller's out-of-band approved SHA-256 digest. The CRS buffers
// must match the repository-pinned hashes for the selected mode.
reallyme_zk_platform_context_result_t reallyme_zk_platform_context_create(
    const uint8_t *artifact_root_ptr, size_t artifact_root_len,
    const uint8_t *release_index_ptr, size_t release_index_len,
    const uint8_t *release_index_sha256_ptr, size_t release_index_sha256_len,
    const uint8_t *crs_g1_ptr, size_t crs_g1_len, const uint8_t *crs_g2_ptr,
    size_t crs_g2_len, uint32_t crs_mode);

// Creates a pinned platform provider context from UTF-8 absolute CRS file
// paths. The native implementation opens the CRS files, enforces exact profile
// lengths, and validates repository-pinned hashes before initialization.
reallyme_zk_platform_context_result_t
reallyme_zk_platform_context_create_with_crs_files(
    const uint8_t *artifact_root_ptr, size_t artifact_root_len,
    const uint8_t *release_index_ptr, size_t release_index_len,
    const uint8_t *release_index_sha256_ptr, size_t release_index_sha256_len,
    const uint8_t *crs_g1_path_ptr, size_t crs_g1_path_len,
    const uint8_t *crs_g2_path_ptr, size_t crs_g2_path_len,
    uint32_t crs_mode);

// Dispatches one canonical ZkProviderOperationRequest through the pinned
// context and returns a canonical ZkProviderOperationResponse on success.
reallyme_zk_platform_result_t reallyme_zk_platform_dispatch(
    reallyme_zk_platform_context_t *context, const uint8_t *request_ptr,
    size_t request_len);

// Destroys a context returned by reallyme_zk_platform_context_create.
reallyme_zk_platform_status_t reallyme_zk_platform_context_destroy(
    reallyme_zk_platform_context_t *context);

// Zeroizes and releases a non-null output returned by this ABI. The buffer
// descriptor is opaque to callers and must be destroyed exactly once.
reallyme_zk_platform_status_t reallyme_zk_platform_buffer_destroy(
    reallyme_zk_platform_buffer_t buffer);

#ifdef __cplusplus
}
#endif

#endif  // REALLYME_ZK_PLATFORM_ABI_H_
