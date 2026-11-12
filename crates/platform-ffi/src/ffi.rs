// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(not(feature = "native"))]
use std::ptr;
#[cfg(feature = "native")]
use std::{panic, ptr};

use reallyme_zk_api::errors::ZkErrorReason;
#[cfg(feature = "native")]
use reallyme_zk_proto_codec::operation::MAX_ZK_PROTO_OPERATION_BYTES;
#[cfg(feature = "native")]
use reallyme_zk_proto_codec::platform_abi::owned_buffer_from_vec;
use reallyme_zk_proto_codec::platform_abi::{
    ReallyMeZkPlatformBuffer, ReallyMeZkPlatformResult, ReallyMeZkPlatformStatus,
    REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT, REALLYME_ZK_PLATFORM_STATUS_OK,
};
#[cfg(feature = "native")]
use reallyme_zk_proto_codec::platform_abi::{
    REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY, REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE,
    REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
};
#[cfg(feature = "native")]
use zeroize::Zeroizing;

#[cfg(feature = "native")]
use crate::{
    dispatch::dispatch_operation,
    handle::{destroy_context, get_context},
    input::{borrow_optional_slice, BorrowStatus},
};

#[cfg(feature = "native")]
mod context_create;
#[cfg(all(test, not(feature = "native")))]
mod unsupported_tests;

#[cfg(feature = "native")]
pub use context_create::{
    reallyme_zk_platform_context_create, reallyme_zk_platform_context_create_with_crs_files,
};

/// Initializes only the verifier CRS prefix and G2 point.
pub const REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY: u32 = 1;
/// Initializes the full prover CRS prefix and G2 point.
pub const REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER: u32 = 2;

/// Opaque native platform context returned to Swift, Kotlin, and Java callers.
#[cfg(feature = "native")]
#[repr(C)]
pub struct ReallyMeZkPlatformContext {
    _private: [u8; 0],
}

/// Opaque unavailable context marker for non-native builds.
#[cfg(not(feature = "native"))]
#[repr(C)]
pub struct ReallyMeZkPlatformContext {
    _private: [u8; 0],
}

/// C-compatible result for context creation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReallyMeZkPlatformContextResult {
    /// ABI status code from `REALLYME_ZK_PLATFORM_STATUS_*`.
    pub status_code: u32,
    /// Stable `reallyme.zk.v1.ZkErrorReason` code for failure statuses.
    pub error_reason_code: u32,
    /// Owned provider context when `status_code` is OK.
    pub context: *mut ReallyMeZkPlatformContext,
}

impl ReallyMeZkPlatformContextResult {
    #[cfg(feature = "native")]
    const fn ok(context: *mut ReallyMeZkPlatformContext) -> Self {
        Self {
            status_code: REALLYME_ZK_PLATFORM_STATUS_OK,
            error_reason_code: 0,
            context,
        }
    }

    const fn failed(status_code: u32, reason: ZkErrorReason) -> Self {
        Self {
            status_code,
            error_reason_code: reason.reason_code(),
            context: ptr::null_mut(),
        }
    }
}

/// Dispatches one canonical provider operation through a pinned context.
///
/// In unwind-capable builds, including the reviewed mobile release profile,
/// unexpected Rust panics are caught and reported as
/// `REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC`. Workspace release builds that
/// use `panic = "abort"` remain fail-stop before this function can return a
/// status.
///
/// # Safety
///
/// `context` must be a live context returned by
/// `reallyme_zk_platform_context_create`. If `request_len` is non-zero,
/// `request_ptr` must reference at least `request_len` initialized bytes.
#[cfg(feature = "native")]
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_dispatch(
    context: *mut ReallyMeZkPlatformContext,
    request_ptr: *const u8,
    request_len: usize,
) -> ReallyMeZkPlatformResult {
    match panic::catch_unwind(panic::AssertUnwindSafe(|| {
        dispatch_impl(context, request_ptr, request_len)
    })) {
        Ok(result) => result,
        Err(_) => result_failed(
            REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
            ZkErrorReason::BackendFailure,
        ),
    }
}

/// Destroys a context returned by `reallyme_zk_platform_context_create`.
///
/// In unwind-capable builds, including the reviewed mobile release profile,
/// unexpected Rust panics are caught and reported as
/// `REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC`. Workspace release builds that
/// use `panic = "abort"` remain fail-stop before this function can return a
/// status.
///
/// # Safety
///
/// `context` must be null or an undestroyed context pointer returned by this
/// ABI. Passing any other pointer is outside the ABI ownership contract.
#[cfg(feature = "native")]
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_context_destroy(
    context: *mut ReallyMeZkPlatformContext,
) -> ReallyMeZkPlatformStatus {
    match panic::catch_unwind(panic::AssertUnwindSafe(|| destroy_context(context))) {
        Ok(status) => status,
        Err(_) => status_failed(
            REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
            ZkErrorReason::BackendFailure,
        ),
    }
}

/// Fails closed when the native linked Barretenberg provider is not compiled.
///
/// # Safety
///
/// This stub does not read any pointer arguments.
#[cfg(not(feature = "native"))]
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_context_create(
    _artifact_root_ptr: *const u8,
    _artifact_root_len: usize,
    _release_index_ptr: *const u8,
    _release_index_len: usize,
    _release_index_sha256_ptr: *const u8,
    _release_index_sha256_len: usize,
    _crs_g1_ptr: *const u8,
    _crs_g1_len: usize,
    _crs_g2_ptr: *const u8,
    _crs_g2_len: usize,
    _crs_mode: u32,
) -> ReallyMeZkPlatformContextResult {
    ReallyMeZkPlatformContextResult::failed(
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
        ZkErrorReason::BackendUnavailable,
    )
}

/// Fails closed when the native linked Barretenberg provider is not compiled.
///
/// # Safety
///
/// This stub does not read any pointer arguments.
#[cfg(not(feature = "native"))]
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_context_create_with_crs_files(
    _artifact_root_ptr: *const u8,
    _artifact_root_len: usize,
    _release_index_ptr: *const u8,
    _release_index_len: usize,
    _release_index_sha256_ptr: *const u8,
    _release_index_sha256_len: usize,
    _crs_g1_path_ptr: *const u8,
    _crs_g1_path_len: usize,
    _crs_g2_path_ptr: *const u8,
    _crs_g2_path_len: usize,
    _crs_mode: u32,
) -> ReallyMeZkPlatformContextResult {
    ReallyMeZkPlatformContextResult::failed(
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
        ZkErrorReason::BackendUnavailable,
    )
}

/// Fails closed when the native linked Barretenberg provider is not compiled.
///
/// # Safety
///
/// This stub does not dereference the context or request pointer.
#[cfg(not(feature = "native"))]
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_dispatch(
    _context: *mut ReallyMeZkPlatformContext,
    _request_ptr: *const u8,
    _request_len: usize,
) -> ReallyMeZkPlatformResult {
    result_failed(
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
        ZkErrorReason::BackendUnavailable,
    )
}

/// Destroys a non-native unavailable context marker.
///
/// # Safety
///
/// Non-null pointers are rejected because non-native builds never create a
/// live context.
#[cfg(not(feature = "native"))]
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_context_destroy(
    context: *mut ReallyMeZkPlatformContext,
) -> ReallyMeZkPlatformStatus {
    if context.is_null() {
        status_ok()
    } else {
        status_failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
            ZkErrorReason::BackendUnavailable,
        )
    }
}

#[cfg(feature = "native")]
fn dispatch_impl(
    context: *mut ReallyMeZkPlatformContext,
    request_ptr: *const u8,
    request_len: usize,
) -> ReallyMeZkPlatformResult {
    let entry = match get_context(context) {
        Ok(entry) => entry,
        Err(error) => {
            return result_failed(REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT, error.reason());
        }
    };
    let request =
        match borrow_optional_slice(request_ptr, request_len, MAX_ZK_PROTO_OPERATION_BYTES) {
            Ok(bytes) => bytes,
            Err(status) => return status.into_result(),
        };
    match dispatch_operation(entry.inner(), request) {
        Ok(encoded) => match buffer_from_zeroizing(encoded) {
            Ok(buffer) => result_ok(buffer),
            Err(error) => result_failed(REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE, error.reason()),
        },
        Err(error) => result_failed(dispatch_failure_status(error.reason()), error.reason()),
    }
}

#[cfg(feature = "native")]
const fn dispatch_failure_status(reason: ZkErrorReason) -> u32 {
    // BackendUnavailable cannot arise from operation dispatch here: those errors
    // are returned inside the canonical response. A top-level occurrence means
    // the context's single dispatch lease was already held.
    match reason {
        ZkErrorReason::BackendUnavailable => REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY,
        _ => REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE,
    }
}

#[cfg(test)]
#[path = "ffi/tests.rs"]
mod tests;

#[cfg(feature = "native")]
impl BorrowStatus {
    const fn into_result(self) -> ReallyMeZkPlatformResult {
        result_failed(self.status_code, self.reason)
    }

    const fn into_context_result(self) -> ReallyMeZkPlatformContextResult {
        ReallyMeZkPlatformContextResult::failed(self.status_code, self.reason)
    }
}

#[cfg(feature = "native")]
fn buffer_from_zeroizing(
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<ReallyMeZkPlatformBuffer, reallyme_zk_api::errors::ZkError> {
    let mut owned = Vec::new();
    core::mem::swap(&mut *bytes, &mut owned);
    owned_buffer_from_vec(owned)
}

#[cfg(feature = "native")]
const fn result_ok(output: ReallyMeZkPlatformBuffer) -> ReallyMeZkPlatformResult {
    ReallyMeZkPlatformResult {
        status_code: REALLYME_ZK_PLATFORM_STATUS_OK,
        error_reason_code: 0,
        output,
    }
}

const fn result_failed(status_code: u32, reason: ZkErrorReason) -> ReallyMeZkPlatformResult {
    ReallyMeZkPlatformResult {
        status_code,
        error_reason_code: reason.reason_code(),
        output: ReallyMeZkPlatformBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            capacity: 0,
            owner_id: 0,
        },
    }
}

#[cfg(not(feature = "native"))]
const fn status_ok() -> ReallyMeZkPlatformStatus {
    ReallyMeZkPlatformStatus {
        status_code: REALLYME_ZK_PLATFORM_STATUS_OK,
        error_reason_code: 0,
    }
}

const fn status_failed(status_code: u32, reason: ZkErrorReason) -> ReallyMeZkPlatformStatus {
    ReallyMeZkPlatformStatus {
        status_code,
        error_reason_code: reason.reason_code(),
    }
}
