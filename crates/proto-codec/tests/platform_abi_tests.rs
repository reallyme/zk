// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, unsafe_code)]

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto_codec::{
    operation::MAX_ZK_PROTO_OPERATION_BYTES,
    platform_abi::{
        reallyme_zk_platform_buffer_destroy, reallyme_zk_platform_encode_failure_response,
        ReallyMeZkPlatformBuffer, REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_ERROR_REASON,
        REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT, REALLYME_ZK_PLATFORM_STATUS_OK,
        REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE,
    },
    result::{decode_operation_response, ZkProviderOperationOutcome},
};

#[test]
fn platform_failure_response_round_trips_through_canonical_decoder() -> Result<(), ZkError> {
    let request = b"bounded malformed request";
    // SAFETY: the request pointer is valid for the exact byte length and the
    // returned buffer is destroyed once below.
    let result = unsafe {
        reallyme_zk_platform_encode_failure_response(
            request.as_ptr(),
            request.len(),
            ZkErrorReason::BackendUnavailable.reason_code(),
        )
    };
    assert_eq!(result.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);
    assert_eq!(result.error_reason_code, 0);
    assert!(!result.output.ptr.is_null());
    assert!(result.output.len > 0);
    assert!(result.output.capacity >= result.output.len);
    assert!(result.output.owner_id > 0);

    // SAFETY: a successful ABI result returns a live allocation with the
    // reported initialized length.
    let response = unsafe { core::slice::from_raw_parts(result.output.ptr, result.output.len) };
    let decoded = decode_operation_response(response)?;
    assert_eq!(decoded.request_sha256(), Digest32::sha256(request));
    match decoded.into_outcome() {
        ZkProviderOperationOutcome::Failure(error) => {
            assert_eq!(error.reason(), ZkErrorReason::BackendUnavailable);
        }
        ZkProviderOperationOutcome::Success(_) => {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
    }

    // SAFETY: the buffer is the exact output returned by the ABI and has not
    // been destroyed before this point.
    let status = unsafe { reallyme_zk_platform_buffer_destroy(result.output) };
    assert_eq!(status.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);
    Ok(())
}

#[test]
fn platform_failure_response_rejects_invalid_inputs_without_output() {
    // SAFETY: null with non-zero length is intentionally exercised as an
    // invalid ABI input and must be rejected before dereference.
    let null_result = unsafe {
        reallyme_zk_platform_encode_failure_response(
            core::ptr::null(),
            1,
            ZkErrorReason::BackendFailure.reason_code(),
        )
    };
    assert_eq!(
        null_result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT
    );
    assert!(null_result.output.ptr.is_null());

    // SAFETY: empty request bytes do not read from the null pointer; only the
    // invalid public reason code is under test.
    let invalid_reason =
        unsafe { reallyme_zk_platform_encode_failure_response(core::ptr::null(), 0, 65_535) };
    assert_eq!(
        invalid_reason.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_ERROR_REASON
    );
    assert!(invalid_reason.output.ptr.is_null());

    // SAFETY: the length is rejected before any read from the null pointer.
    let oversized = unsafe {
        reallyme_zk_platform_encode_failure_response(
            core::ptr::null(),
            MAX_ZK_PROTO_OPERATION_BYTES.saturating_add(1),
            ZkErrorReason::MessageTooLarge.reason_code(),
        )
    };
    assert_eq!(
        oversized.status_code,
        REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE
    );
    assert!(oversized.output.ptr.is_null());
}

#[test]
fn platform_destroy_rejects_malformed_buffer_descriptor() {
    // SAFETY: null with a non-zero descriptor is rejected before ownership
    // reclamation is attempted.
    let status = unsafe {
        reallyme_zk_platform_buffer_destroy(ReallyMeZkPlatformBuffer {
            ptr: core::ptr::null_mut(),
            len: 1,
            capacity: 1,
            owner_id: 0,
        })
    };
    assert_eq!(
        status.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER
    );
}

#[test]
fn platform_destroy_rejects_copied_buffer_descriptor_after_first_destroy() {
    // SAFETY: empty request bytes do not read from the null pointer; the
    // returned buffer descriptor is intentionally copied before destruction.
    let result = unsafe {
        reallyme_zk_platform_encode_failure_response(
            core::ptr::null(),
            0,
            ZkErrorReason::BackendUnavailable.reason_code(),
        )
    };
    assert_eq!(result.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);
    let copied = result.output;

    // SAFETY: the first destroy uses the exact live descriptor returned by the
    // ABI.
    let first = unsafe { reallyme_zk_platform_buffer_destroy(result.output) };
    assert_eq!(first.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);

    // SAFETY: this stale copied descriptor must be rejected by the owner
    // registry before allocator ownership can be reclaimed again.
    let second = unsafe { reallyme_zk_platform_buffer_destroy(copied) };
    assert_eq!(
        second.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER
    );
}

#[test]
fn platform_destroy_rejects_forged_owner_without_consuming_live_buffer() {
    // SAFETY: empty request bytes do not read from the null pointer.
    let result = unsafe {
        reallyme_zk_platform_encode_failure_response(
            core::ptr::null(),
            0,
            ZkErrorReason::BackendUnavailable.reason_code(),
        )
    };
    assert_eq!(result.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);
    let mut forged = result.output;
    forged.owner_id = forged.owner_id.checked_add(1).unwrap_or(0);

    // SAFETY: the forged owner id must be rejected without touching the live
    // allocation registered under the original descriptor.
    let forged_status = unsafe { reallyme_zk_platform_buffer_destroy(forged) };
    assert_eq!(
        forged_status.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER
    );

    // SAFETY: because the forged descriptor did not consume ownership, the
    // original descriptor must still destroy successfully exactly once.
    let real_status = unsafe { reallyme_zk_platform_buffer_destroy(result.output) };
    assert_eq!(real_status.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);
}
