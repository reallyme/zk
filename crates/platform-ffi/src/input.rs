// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::slice;

use reallyme_zk_api::errors::ZkErrorReason;
use reallyme_zk_proto_codec::platform_abi::{
    REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT, REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT,
    REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE,
};

use crate::context::PlatformCrsMode;

const VERIFIER_CRS_G1_PREFIX_BYTES: usize = 64;
const VERIFIER_CRS_G2_BYTES: usize = 128;
const FULL_PROVER_CRS_G1_PREFIX_BYTES: usize = 67_108_928;

pub(crate) struct CrsLengths {
    pub(crate) g1_prefix: usize,
    pub(crate) g2: usize,
}

pub(crate) const fn crs_lengths_for_mode(mode: &PlatformCrsMode) -> CrsLengths {
    match mode {
        PlatformCrsMode::VerifierOnly => CrsLengths {
            g1_prefix: VERIFIER_CRS_G1_PREFIX_BYTES,
            g2: VERIFIER_CRS_G2_BYTES,
        },
        PlatformCrsMode::FullProver => CrsLengths {
            g1_prefix: FULL_PROVER_CRS_G1_PREFIX_BYTES,
            g2: VERIFIER_CRS_G2_BYTES,
        },
    }
}

pub(crate) struct BorrowStatus {
    pub(crate) status_code: u32,
    pub(crate) reason: ZkErrorReason,
}

pub(crate) fn borrow_required_slice<'a>(
    ptr: *const u8,
    len: usize,
    max_len: usize,
) -> Result<&'a [u8], BorrowStatus> {
    if len == 0 {
        return Err(BorrowStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT,
            reason: ZkErrorReason::EmptyInput,
        });
    }
    borrow_optional_slice(ptr, len, max_len)
}

pub(crate) fn borrow_required_exact_slice<'a>(
    ptr: *const u8,
    len: usize,
    expected_len: usize,
) -> Result<&'a [u8], BorrowStatus> {
    if len == 0 {
        return Err(BorrowStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT,
            reason: ZkErrorReason::EmptyInput,
        });
    }
    if len != expected_len {
        return Err(BorrowStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
            reason: ZkErrorReason::ArtifactMismatch,
        });
    }
    if ptr.is_null() {
        return Err(BorrowStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT,
            reason: ZkErrorReason::MalformedProtobuf,
        });
    }
    // SAFETY: the ABI caller retains ownership of a non-null, initialized
    // buffer with exactly `len` bytes for this call's lifetime. This function
    // creates only an immutable borrow, so it does not alias mutable Rust state.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

pub(crate) fn borrow_optional_slice<'a>(
    ptr: *const u8,
    len: usize,
    max_len: usize,
) -> Result<&'a [u8], BorrowStatus> {
    if len > max_len {
        return Err(BorrowStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE,
            reason: ZkErrorReason::MessageTooLarge,
        });
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(BorrowStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT,
            reason: ZkErrorReason::MalformedProtobuf,
        });
    }
    // SAFETY: the ABI caller retains ownership of a non-null, initialized
    // buffer with `len` bytes for this call's lifetime. `len` has been bounded
    // by `max_len`, and this function creates only an immutable borrow.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}
