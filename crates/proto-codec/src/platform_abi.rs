// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! C ABI primitives for canonical platform provider exchanges.
//!
//! This module exposes only strict `reallyme.zk.v1.ZkProviderOperation*`
//! protobuf exchange helpers and typed numeric statuses. Proving backends stay
//! injected behind the API/backend boundary; raw upstream BBAPI MessagePack
//! never crosses this ABI.

#![allow(unsafe_code)]

use std::{
    collections::HashMap,
    panic, ptr, slice,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use zeroize::Zeroize;

use crate::{operation::MAX_ZK_PROTO_OPERATION_BYTES, result::encode_operation_failure_response};

/// Operation completed and any returned buffer is owned by the caller.
pub const REALLYME_ZK_PLATFORM_STATUS_OK: u32 = 0;
/// A non-empty input buffer used a null pointer.
pub const REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT: u32 = 1;
/// The supplied public `ZkErrorReason` numeric value is not defined.
pub const REALLYME_ZK_PLATFORM_STATUS_INVALID_ERROR_REASON: u32 = 2;
/// The supplied request exceeded the canonical provider-operation bound.
pub const REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE: u32 = 3;
/// The canonical response could not be encoded without exceeding policy.
pub const REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE: u32 = 4;
/// A panic was contained before it could cross the C ABI.
///
/// This status is observable only in unwind-capable builds. The reviewed
/// mobile package profile enables unwinding at the FFI boundary; workspace
/// `release` builds use `panic = "abort"` and remain fail-stop.
pub const REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC: u32 = 5;
/// The caller supplied an invalid owned-buffer descriptor to destroy.
pub const REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER: u32 = 6;
/// The caller supplied a null or invalid provider context.
pub const REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT: u32 = 7;
/// The caller supplied an undefined CRS mode.
pub const REALLYME_ZK_PLATFORM_STATUS_INVALID_MODE: u32 = 8;
/// Another operation currently owns this context's single dispatch lease.
pub const REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY: u32 = 9;

/// C-compatible owned byte buffer returned by the ReallyMe platform ABI.
///
/// Callers must treat all fields as opaque and release a non-null buffer
/// exactly once with `reallyme_zk_platform_buffer_destroy`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReallyMeZkPlatformBuffer {
    /// Pointer to the first byte of the allocation, or null for no buffer.
    pub ptr: *mut u8,
    /// Number of initialized bytes.
    pub len: usize,
    /// Rust allocation capacity required for exact destruction.
    pub capacity: usize,
    /// Opaque registered owner id required for exact destruction.
    pub owner_id: usize,
}

impl ReallyMeZkPlatformBuffer {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            capacity: 0,
            owner_id: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct BufferEntry {
    ptr_addr: usize,
    len: usize,
    capacity: usize,
}

#[derive(Default)]
struct BufferRegistry {
    entries: HashMap<usize, BufferEntry>,
}

static BUFFER_REGISTRY: OnceLock<Mutex<BufferRegistry>> = OnceLock::new();
static NEXT_BUFFER_ID: AtomicUsize = AtomicUsize::new(1);

/// C-compatible status without an output payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReallyMeZkPlatformStatus {
    /// ABI status code from `REALLYME_ZK_PLATFORM_STATUS_*`.
    pub status_code: u32,
    /// Stable `reallyme.zk.v1.ZkErrorReason` code for failure statuses.
    pub error_reason_code: u32,
}

impl ReallyMeZkPlatformStatus {
    const fn ok() -> Self {
        Self {
            status_code: REALLYME_ZK_PLATFORM_STATUS_OK,
            error_reason_code: 0,
        }
    }

    const fn failed(status_code: u32, reason: ZkErrorReason) -> Self {
        Self {
            status_code,
            error_reason_code: reason.reason_code(),
        }
    }
}

/// C-compatible result that may carry one owned output buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReallyMeZkPlatformResult {
    /// ABI status code from `REALLYME_ZK_PLATFORM_STATUS_*`.
    pub status_code: u32,
    /// Stable `reallyme.zk.v1.ZkErrorReason` code for failure statuses.
    pub error_reason_code: u32,
    /// Owned output bytes when `status_code` is OK.
    pub output: ReallyMeZkPlatformBuffer,
}

impl ReallyMeZkPlatformResult {
    const fn ok(output: ReallyMeZkPlatformBuffer) -> Self {
        Self {
            status_code: REALLYME_ZK_PLATFORM_STATUS_OK,
            error_reason_code: 0,
            output,
        }
    }

    const fn failed(status_code: u32, reason: ZkErrorReason) -> Self {
        Self {
            status_code,
            error_reason_code: reason.reason_code(),
            output: ReallyMeZkPlatformBuffer::empty(),
        }
    }
}

/// Encodes a canonical typed provider failure response for platform callers.
///
/// # Safety
///
/// If `request_len` is non-zero, `request_ptr` must reference at least
/// `request_len` initialized bytes for the duration of the call. Returned
/// non-null buffers must be released exactly once with
/// `reallyme_zk_platform_buffer_destroy`.
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_encode_failure_response(
    request_ptr: *const u8,
    request_len: usize,
    error_reason_code: u32,
) -> ReallyMeZkPlatformResult {
    match panic::catch_unwind(|| {
        encode_failure_response_impl(request_ptr, request_len, error_reason_code)
    }) {
        Ok(result) => result,
        Err(_) => ReallyMeZkPlatformResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
            ZkErrorReason::BackendFailure,
        ),
    }
}

fn encode_failure_response_impl(
    request_ptr: *const u8,
    request_len: usize,
    error_reason_code: u32,
) -> ReallyMeZkPlatformResult {
    if request_len > MAX_ZK_PROTO_OPERATION_BYTES {
        return ReallyMeZkPlatformResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE,
            ZkErrorReason::MessageTooLarge,
        );
    }
    let request = if request_len == 0 {
        &[]
    } else if request_ptr.is_null() {
        return ReallyMeZkPlatformResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_NULL_ARGUMENT,
            ZkErrorReason::MalformedProtobuf,
        );
    } else {
        // SAFETY: the public ABI contract requires `request_ptr` to reference
        // `request_len` initialized bytes. The length has already been checked
        // against the fixed protobuf operation bound before creating a slice.
        unsafe { slice::from_raw_parts(request_ptr, request_len) }
    };

    let reason = match ZkErrorReason::from_reason_code(error_reason_code) {
        Ok(reason) => reason,
        Err(_) => {
            return ReallyMeZkPlatformResult::failed(
                REALLYME_ZK_PLATFORM_STATUS_INVALID_ERROR_REASON,
                ZkErrorReason::MalformedProtobuf,
            );
        }
    };

    match encode_operation_failure_response(request, ZkError::new(reason)) {
        Ok(mut encoded) => {
            let mut bytes = Vec::new();
            core::mem::swap(&mut *encoded, &mut bytes);
            match owned_buffer_from_vec(bytes) {
                Ok(buffer) => ReallyMeZkPlatformResult::ok(buffer),
                Err(error) => ReallyMeZkPlatformResult::failed(
                    REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE,
                    error.reason(),
                ),
            }
        }
        Err(error) => ReallyMeZkPlatformResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE,
            error.reason(),
        ),
    }
}

/// Registers a Rust-owned vector for exact C ABI destruction.
///
/// The returned descriptor may be copied by C callers, so ownership is tracked
/// by an opaque id in this module rather than trusting `ptr/len/capacity`
/// alone when the buffer is destroyed.
pub fn owned_buffer_from_vec(bytes: Vec<u8>) -> Result<ReallyMeZkPlatformBuffer, ZkError> {
    let mut bytes = zeroize::Zeroizing::new(bytes);
    if bytes.is_empty() {
        return Ok(ReallyMeZkPlatformBuffer::empty());
    }

    let owner_id = next_buffer_id()?;
    let output = ReallyMeZkPlatformBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        capacity: bytes.capacity(),
        owner_id,
    };
    insert_buffer(output)?;
    let mut owned = Vec::new();
    core::mem::swap(&mut *bytes, &mut owned);
    core::mem::forget(bytes);
    core::mem::forget(owned);
    Ok(output)
}

fn insert_buffer(buffer: ReallyMeZkPlatformBuffer) -> Result<(), ZkError> {
    let mut registry = buffer_registry()
        .lock()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    registry
        .entries
        .try_reserve(1)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let entry = BufferEntry {
        ptr_addr: buffer.ptr as usize,
        len: buffer.len,
        capacity: buffer.capacity,
    };
    if registry.entries.contains_key(&buffer.owner_id) {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    registry.entries.insert(buffer.owner_id, entry);
    Ok(())
}

fn buffer_registry() -> &'static Mutex<BufferRegistry> {
    BUFFER_REGISTRY.get_or_init(|| Mutex::new(BufferRegistry::default()))
}

fn next_buffer_id() -> Result<usize, ZkError> {
    loop {
        let current = NEXT_BUFFER_ID.load(Ordering::Relaxed);
        if current == 0 {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        let next = current
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::ResourceExhausted))?;
        if NEXT_BUFFER_ID
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(current);
        }
    }
}

/// Zeroizes and releases a buffer returned by the ReallyMe platform ABI.
///
/// # Safety
///
/// Non-null buffers must be values returned by this ABI and must not have been
/// destroyed previously. Passing arbitrary pointers, mismatched lengths, or
/// mismatched capacities is outside the C ABI ownership contract.
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_buffer_destroy(
    buffer: ReallyMeZkPlatformBuffer,
) -> ReallyMeZkPlatformStatus {
    match panic::catch_unwind(|| destroy_buffer_impl(buffer)) {
        Ok(status) => status,
        Err(_) => ReallyMeZkPlatformStatus::failed(
            REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
            ZkErrorReason::BackendFailure,
        ),
    }
}

fn destroy_buffer_impl(buffer: ReallyMeZkPlatformBuffer) -> ReallyMeZkPlatformStatus {
    if buffer.ptr.is_null() {
        if buffer.len == 0 && buffer.capacity == 0 && buffer.owner_id == 0 {
            return ReallyMeZkPlatformStatus::ok();
        }
        return ReallyMeZkPlatformStatus::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
            ZkErrorReason::BackendFailure,
        );
    }
    if buffer.len > buffer.capacity {
        return ReallyMeZkPlatformStatus::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
            ZkErrorReason::BackendFailure,
        );
    }
    if buffer.owner_id == 0 {
        return ReallyMeZkPlatformStatus::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
            ZkErrorReason::BackendFailure,
        );
    }
    let registry = match buffer_registry().lock() {
        Ok(registry) => registry,
        Err(_) => {
            return ReallyMeZkPlatformStatus::failed(
                REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
                ZkErrorReason::BackendFailure,
            );
        }
    };
    let mut registry = registry;
    let entry = match registry.entries.get(&buffer.owner_id) {
        Some(entry) => *entry,
        None => {
            return ReallyMeZkPlatformStatus::failed(
                REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
                ZkErrorReason::BackendFailure,
            );
        }
    };
    if entry.ptr_addr != buffer.ptr as usize
        || entry.len != buffer.len
        || entry.capacity != buffer.capacity
    {
        return ReallyMeZkPlatformStatus::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER,
            ZkErrorReason::BackendFailure,
        );
    }
    let _removed = registry.entries.remove(&buffer.owner_id);

    // SAFETY: ownership is reclaimed only after the opaque owner id and the
    // full descriptor match one live registry entry, which prevents stale,
    // copied, or forged descriptors from reaching the allocator.
    let mut bytes = unsafe { Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.capacity) };
    bytes.zeroize();
    ReallyMeZkPlatformStatus::ok()
}
