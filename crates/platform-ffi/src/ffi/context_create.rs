// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::panic;

use reallyme_zk_api::errors::ZkErrorReason;
use reallyme_zk_proto_codec::platform_abi::{
    REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC, REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
    REALLYME_ZK_PLATFORM_STATUS_INVALID_MODE,
};

use crate::{
    context::{
        PlatformContext, PlatformCrsMode, MAX_PLATFORM_PATH_BYTES, RELEASE_INDEX_SHA256_BYTES,
    },
    handle::insert_context,
    input::{borrow_required_exact_slice, borrow_required_slice, crs_lengths_for_mode},
};

use super::{
    ReallyMeZkPlatformContextResult, REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER,
    REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
};

/// Creates a pinned native platform provider context.
///
/// In unwind-capable builds, including the reviewed mobile release profile,
/// unexpected Rust panics are caught and reported as
/// `REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC`. Workspace release builds that
/// use `panic = "abort"` remain fail-stop before this function can return a
/// status.
///
/// # Safety
///
/// Every non-empty pointer/length pair must reference initialized bytes for
/// the duration of the call. The returned context must be destroyed exactly
/// once with `reallyme_zk_platform_context_destroy`.
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_context_create(
    artifact_root_ptr: *const u8,
    artifact_root_len: usize,
    release_index_ptr: *const u8,
    release_index_len: usize,
    release_index_sha256_ptr: *const u8,
    release_index_sha256_len: usize,
    crs_g1_ptr: *const u8,
    crs_g1_len: usize,
    crs_g2_ptr: *const u8,
    crs_g2_len: usize,
    crs_mode: u32,
) -> ReallyMeZkPlatformContextResult {
    match panic::catch_unwind(|| {
        create_context_impl(CreateContextInputs {
            artifact_root_ptr,
            artifact_root_len,
            release_index_ptr,
            release_index_len,
            release_index_sha256_ptr,
            release_index_sha256_len,
            crs_g1_ptr,
            crs_g1_len,
            crs_g2_ptr,
            crs_g2_len,
            crs_mode,
        })
    }) {
        Ok(result) => result,
        Err(_) => ReallyMeZkPlatformContextResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
            ZkErrorReason::BackendFailure,
        ),
    }
}

/// Creates a pinned native platform provider context from CRS file paths.
///
/// The caller still supplies the artifact root and release-index bytes, but the
/// CRS inputs are UTF-8 absolute paths. The native side opens the files,
/// enforces exact profile lengths, and validates repository-pinned CRS hashes
/// before initializing Barretenberg.
///
/// # Safety
///
/// Every non-empty pointer/length pair must reference initialized bytes for
/// the duration of the call. The returned context must be destroyed exactly
/// once with `reallyme_zk_platform_context_destroy`.
#[no_mangle]
pub unsafe extern "C" fn reallyme_zk_platform_context_create_with_crs_files(
    artifact_root_ptr: *const u8,
    artifact_root_len: usize,
    release_index_ptr: *const u8,
    release_index_len: usize,
    release_index_sha256_ptr: *const u8,
    release_index_sha256_len: usize,
    crs_g1_path_ptr: *const u8,
    crs_g1_path_len: usize,
    crs_g2_path_ptr: *const u8,
    crs_g2_path_len: usize,
    crs_mode: u32,
) -> ReallyMeZkPlatformContextResult {
    match panic::catch_unwind(|| {
        create_context_with_crs_files_impl(CreateContextWithCrsFilesInputs {
            artifact_root_ptr,
            artifact_root_len,
            release_index_ptr,
            release_index_len,
            release_index_sha256_ptr,
            release_index_sha256_len,
            crs_g1_path_ptr,
            crs_g1_path_len,
            crs_g2_path_ptr,
            crs_g2_path_len,
            crs_mode,
        })
    }) {
        Ok(result) => result,
        Err(_) => ReallyMeZkPlatformContextResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INTERNAL_PANIC,
            ZkErrorReason::BackendFailure,
        ),
    }
}

struct CreateContextInputs {
    artifact_root_ptr: *const u8,
    artifact_root_len: usize,
    release_index_ptr: *const u8,
    release_index_len: usize,
    release_index_sha256_ptr: *const u8,
    release_index_sha256_len: usize,
    crs_g1_ptr: *const u8,
    crs_g1_len: usize,
    crs_g2_ptr: *const u8,
    crs_g2_len: usize,
    crs_mode: u32,
}

struct CreateContextWithCrsFilesInputs {
    artifact_root_ptr: *const u8,
    artifact_root_len: usize,
    release_index_ptr: *const u8,
    release_index_len: usize,
    release_index_sha256_ptr: *const u8,
    release_index_sha256_len: usize,
    crs_g1_path_ptr: *const u8,
    crs_g1_path_len: usize,
    crs_g2_path_ptr: *const u8,
    crs_g2_path_len: usize,
    crs_mode: u32,
}

fn create_context_impl(inputs: CreateContextInputs) -> ReallyMeZkPlatformContextResult {
    let artifact_root = match borrow_required_slice(
        inputs.artifact_root_ptr,
        inputs.artifact_root_len,
        MAX_PLATFORM_PATH_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let release_index = match borrow_required_slice(
        inputs.release_index_ptr,
        inputs.release_index_len,
        reallyme_zk_proto_codec::release::MAX_ZK_RELEASE_INDEX_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let release_index_sha256 = match borrow_required_exact_slice(
        inputs.release_index_sha256_ptr,
        inputs.release_index_sha256_len,
        RELEASE_INDEX_SHA256_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let mode = match platform_crs_mode(inputs.crs_mode) {
        Ok(mode) => mode,
        Err(result) => return result,
    };
    let crs_lengths = crs_lengths_for_mode(&mode);
    let crs_g1 = match borrow_required_exact_slice(
        inputs.crs_g1_ptr,
        inputs.crs_g1_len,
        crs_lengths.g1_prefix,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let crs_g2 =
        match borrow_required_exact_slice(inputs.crs_g2_ptr, inputs.crs_g2_len, crs_lengths.g2) {
            Ok(bytes) => bytes,
            Err(status) => return status.into_context_result(),
        };

    match PlatformContext::try_new(
        artifact_root,
        release_index,
        release_index_sha256,
        crs_g1,
        crs_g2,
        mode,
    ) {
        Ok(inner) => insert_context_result(inner),
        Err(error) => ReallyMeZkPlatformContextResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
            error.reason(),
        ),
    }
}

fn create_context_with_crs_files_impl(
    inputs: CreateContextWithCrsFilesInputs,
) -> ReallyMeZkPlatformContextResult {
    let artifact_root = match borrow_required_slice(
        inputs.artifact_root_ptr,
        inputs.artifact_root_len,
        MAX_PLATFORM_PATH_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let release_index = match borrow_required_slice(
        inputs.release_index_ptr,
        inputs.release_index_len,
        reallyme_zk_proto_codec::release::MAX_ZK_RELEASE_INDEX_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let release_index_sha256 = match borrow_required_exact_slice(
        inputs.release_index_sha256_ptr,
        inputs.release_index_sha256_len,
        RELEASE_INDEX_SHA256_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let mode = match platform_crs_mode(inputs.crs_mode) {
        Ok(mode) => mode,
        Err(result) => return result,
    };
    let crs_g1_path = match borrow_required_slice(
        inputs.crs_g1_path_ptr,
        inputs.crs_g1_path_len,
        MAX_PLATFORM_PATH_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };
    let crs_g2_path = match borrow_required_slice(
        inputs.crs_g2_path_ptr,
        inputs.crs_g2_path_len,
        MAX_PLATFORM_PATH_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(status) => return status.into_context_result(),
    };

    match PlatformContext::try_new_from_crs_files(
        artifact_root,
        release_index,
        release_index_sha256,
        crs_g1_path,
        crs_g2_path,
        mode,
    ) {
        Ok(inner) => insert_context_result(inner),
        Err(error) => ReallyMeZkPlatformContextResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
            error.reason(),
        ),
    }
}

fn insert_context_result(inner: PlatformContext) -> ReallyMeZkPlatformContextResult {
    match insert_context(inner) {
        Ok(context) => ReallyMeZkPlatformContextResult::ok(context),
        Err(error) => ReallyMeZkPlatformContextResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
            error.reason(),
        ),
    }
}

fn platform_crs_mode(crs_mode: u32) -> Result<PlatformCrsMode, ReallyMeZkPlatformContextResult> {
    match crs_mode {
        REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY => Ok(PlatformCrsMode::VerifierOnly),
        REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER => Ok(PlatformCrsMode::FullProver),
        _ => Err(ReallyMeZkPlatformContextResult::failed(
            REALLYME_ZK_PLATFORM_STATUS_INVALID_MODE,
            ZkErrorReason::ArtifactMismatch,
        )),
    }
}
