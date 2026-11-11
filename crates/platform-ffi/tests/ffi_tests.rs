// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, unsafe_code)]

use reallyme_zk_api::errors::ZkErrorReason;
#[cfg(feature = "native")]
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::ZkError,
    proofs::ZkProofSuite,
};
#[cfg(feature = "native")]
use reallyme_zk_artifacts::{ArtifactToolchain, ArtifactVersion, Digest32};
#[cfg(feature = "native")]
use reallyme_zk_platform_ffi::reallyme_zk_platform_context_create_with_crs_files;
#[cfg(feature = "native")]
use reallyme_zk_platform_ffi::ReallyMeZkPlatformContext;
#[cfg(not(feature = "native"))]
use reallyme_zk_platform_ffi::REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY;
use reallyme_zk_platform_ffi::{
    reallyme_zk_platform_context_create, reallyme_zk_platform_context_destroy,
    reallyme_zk_platform_dispatch,
};
#[cfg(feature = "native")]
use reallyme_zk_proto_codec::platform_abi::REALLYME_ZK_PLATFORM_STATUS_INVALID_MODE;
use reallyme_zk_proto_codec::platform_abi::{
    REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT, REALLYME_ZK_PLATFORM_STATUS_OK,
};
#[cfg(feature = "native")]
use reallyme_zk_proto_codec::{
    capability_registry::build_capability_registry,
    release::{
        encode_release_index, ReleaseArtifactPin, ReleaseIndex, ReleaseVerificationVectorPin,
        RELEASE_ARTIFACT_MANIFEST_COUNT, RELEASE_VERIFICATION_VECTOR_SET_COUNT,
    },
};

#[cfg(feature = "native")]
const VERIFIER_CRS_G1_PREFIX_BYTES: usize = 64;
#[cfg(feature = "native")]
const VERIFIER_CRS_G2_BYTES: usize = 128;

#[test]
fn dispatch_rejects_null_context_without_reading_request() {
    // SAFETY: this intentionally supplies a null context. The function must
    // reject it before inspecting the request pointer.
    let result =
        unsafe { reallyme_zk_platform_dispatch(core::ptr::null_mut(), core::ptr::null(), 1) };
    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert_eq!(
        result.error_reason_code,
        ZkErrorReason::BackendUnavailable.reason_code()
    );
    assert!(result.output.ptr.is_null());
}

#[cfg(feature = "native")]
#[test]
fn native_context_create_rejects_unknown_crs_mode_before_backend_init() {
    let root = b"/tmp";
    let release = b"not decoded for invalid mode";
    let release_sha256 = [0_u8; 32];
    let g1 = b"g1";
    let g2 = b"g2";
    // SAFETY: every pointer references the exact initialized byte length.
    let result = unsafe {
        reallyme_zk_platform_context_create(
            root.as_ptr(),
            root.len(),
            release.as_ptr(),
            release.len(),
            release_sha256.as_ptr(),
            release_sha256.len(),
            g1.as_ptr(),
            g1.len(),
            g2.as_ptr(),
            g2.len(),
            65_535,
        )
    };
    assert_eq!(result.status_code, REALLYME_ZK_PLATFORM_STATUS_INVALID_MODE);
    assert!(result.context.is_null());
}

#[cfg(feature = "native")]
#[test]
fn native_context_create_rejects_wrong_crs_length_before_slice_construction() {
    let root = b"/tmp";
    let release = b"not decoded for invalid crs length";
    let release_sha256 = [0_u8; 32];
    let dangling = core::ptr::NonNull::<u8>::dangling().as_ptr();
    let g2 = [0_u8; 128];
    // SAFETY: this intentionally uses a dangling G1 pointer with a rejected
    // length. The ABI must reject the length before constructing a slice.
    let result = unsafe {
        reallyme_zk_platform_context_create(
            root.as_ptr(),
            root.len(),
            release.as_ptr(),
            release.len(),
            release_sha256.as_ptr(),
            release_sha256.len(),
            dangling,
            usize::MAX,
            g2.as_ptr(),
            g2.len(),
            reallyme_zk_platform_ffi::REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
        )
    };
    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert!(result.context.is_null());
}

#[cfg(feature = "native")]
#[test]
fn native_context_create_with_crs_files_rejects_missing_crs_path() {
    let root = b"/tmp";
    let release = b"not decoded for missing crs path";
    let release_sha256 = [0_u8; 32];
    let missing_g1 = b"/tmp/reallyme-zk-missing-g1";
    let missing_g2 = b"/tmp/reallyme-zk-missing-g2";
    // SAFETY: every pointer references the exact initialized byte length.
    let result = unsafe {
        reallyme_zk_platform_context_create_with_crs_files(
            root.as_ptr(),
            root.len(),
            release.as_ptr(),
            release.len(),
            release_sha256.as_ptr(),
            release_sha256.len(),
            missing_g1.as_ptr(),
            missing_g1.len(),
            missing_g2.as_ptr(),
            missing_g2.len(),
            reallyme_zk_platform_ffi::REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
        )
    };
    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert!(result.context.is_null());
}

#[cfg(feature = "native")]
#[test]
fn native_context_create_with_crs_files_rejects_wrong_crs_length() -> Result<(), ZkError> {
    let root = temp_test_root("reallyme-zk-platform-ffi-crs-file-length");
    std::fs::create_dir_all(&root).map_err(io_error_from_zk)?;
    let g1 = root.join("g1.bin");
    let g2 = root.join("g2.bin");
    std::fs::write(&g1, [0_u8; VERIFIER_CRS_G1_PREFIX_BYTES - 1]).map_err(io_error_from_zk)?;
    std::fs::write(&g2, [0_u8; VERIFIER_CRS_G2_BYTES]).map_err(io_error_from_zk)?;
    let release = valid_release_index_bytes()?;

    let result = create_context_with_crs_file_paths(&root, release, &g1, &g2)?;

    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert_eq!(
        result.error_reason_code,
        ZkErrorReason::ArtifactMismatch.reason_code()
    );
    assert!(result.context.is_null());
    std::fs::remove_dir_all(&root).map_err(io_error_from_zk)?;
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn native_context_create_with_crs_files_rejects_exact_length_wrong_crs_hash() -> Result<(), ZkError>
{
    let root = temp_test_root("reallyme-zk-platform-ffi-crs-file-hash");
    std::fs::create_dir_all(&root).map_err(io_error_from_zk)?;
    let g1 = root.join("g1.bin");
    let g2 = root.join("g2.bin");
    std::fs::write(&g1, [0_u8; VERIFIER_CRS_G1_PREFIX_BYTES]).map_err(io_error_from_zk)?;
    std::fs::write(&g2, [0_u8; VERIFIER_CRS_G2_BYTES]).map_err(io_error_from_zk)?;
    let release = valid_release_index_bytes()?;

    let result = create_context_with_crs_file_paths(&root, release, &g1, &g2)?;

    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert_eq!(
        result.error_reason_code,
        ZkErrorReason::ArtifactMismatch.reason_code()
    );
    assert!(result.context.is_null());
    std::fs::remove_dir_all(&root).map_err(io_error_from_zk)?;
    Ok(())
}

#[cfg(all(feature = "native", unix))]
#[test]
fn native_context_create_with_crs_files_rejects_symlink_crs_path() -> Result<(), ZkError> {
    let root = temp_test_root("reallyme-zk-platform-ffi-crs-file-symlink");
    std::fs::create_dir_all(&root).map_err(io_error_from_zk)?;
    let target = root.join("target-g1.bin");
    let g1 = root.join("g1.bin");
    let g2 = root.join("g2.bin");
    std::fs::write(&target, [0_u8; VERIFIER_CRS_G1_PREFIX_BYTES]).map_err(io_error_from_zk)?;
    std::os::unix::fs::symlink(&target, &g1).map_err(io_error_from_zk)?;
    std::fs::write(&g2, [0_u8; VERIFIER_CRS_G2_BYTES]).map_err(io_error_from_zk)?;
    let release = valid_release_index_bytes()?;

    let result = create_context_with_crs_file_paths(&root, release, &g1, &g2)?;

    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert_eq!(
        result.error_reason_code,
        ZkErrorReason::ArtifactMismatch.reason_code()
    );
    assert!(result.context.is_null());
    std::fs::remove_dir_all(&root).map_err(io_error_from_zk)?;
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn native_context_create_with_crs_files_rejects_relative_crs_path() -> Result<(), ZkError> {
    let root = b"/tmp";
    let g1 = b"relative-g1.bin";
    let g2 = b"/tmp/reallyme-zk-unused-g2.bin";
    let release = valid_release_index_bytes()?;

    let result = unsafe {
        reallyme_zk_platform_context_create_with_crs_files(
            root.as_ptr(),
            root.len(),
            release.bytes.as_ptr(),
            release.bytes.len(),
            release.sha256.as_bytes().as_ptr(),
            release.sha256.as_bytes().len(),
            g1.as_ptr(),
            g1.len(),
            g2.as_ptr(),
            g2.len(),
            reallyme_zk_platform_ffi::REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
        )
    };

    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert_eq!(
        result.error_reason_code,
        ZkErrorReason::ArtifactMismatch.reason_code()
    );
    assert!(result.context.is_null());
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn native_context_destroy_rejects_unknown_nonzero_handle() {
    let unknown = core::ptr::NonNull::<ReallyMeZkPlatformContext>::dangling().as_ptr();
    // SAFETY: this supplies an unknown non-null opaque handle. The registry
    // must reject it without dereferencing the value.
    let status = unsafe { reallyme_zk_platform_context_destroy(unknown) };
    assert_eq!(
        status.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
}

#[cfg(not(feature = "native"))]
#[test]
fn non_native_context_create_fails_closed() {
    // SAFETY: the non-native stub does not dereference pointer arguments.
    let result = unsafe {
        reallyme_zk_platform_context_create(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
        )
    };
    assert_eq!(
        result.status_code,
        REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
    );
    assert!(result.context.is_null());
}

#[test]
fn destroy_null_context_is_idempotent_noop() {
    // SAFETY: null context destruction is explicitly permitted.
    let status = unsafe { reallyme_zk_platform_context_destroy(core::ptr::null_mut()) };
    assert_eq!(status.status_code, REALLYME_ZK_PLATFORM_STATUS_OK);
}

#[cfg(feature = "native")]
struct ValidReleaseIndexBytes {
    bytes: Vec<u8>,
    sha256: Digest32,
}

#[cfg(feature = "native")]
fn create_context_with_crs_file_paths(
    artifact_root: &std::path::Path,
    release: ValidReleaseIndexBytes,
    crs_g1: &std::path::Path,
    crs_g2: &std::path::Path,
) -> Result<reallyme_zk_platform_ffi::ReallyMeZkPlatformContextResult, ZkError> {
    let artifact_root = platform_path_bytes(artifact_root)?;
    let crs_g1 = platform_path_bytes(crs_g1)?;
    let crs_g2 = platform_path_bytes(crs_g2)?;
    // SAFETY: every pointer references the exact initialized byte length for
    // the duration of this synchronous FFI call.
    Ok(unsafe {
        reallyme_zk_platform_context_create_with_crs_files(
            artifact_root.as_ptr(),
            artifact_root.len(),
            release.bytes.as_ptr(),
            release.bytes.len(),
            release.sha256.as_bytes().as_ptr(),
            release.sha256.as_bytes().len(),
            crs_g1.as_ptr(),
            crs_g1.len(),
            crs_g2.as_ptr(),
            crs_g2.len(),
            reallyme_zk_platform_ffi::REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
        )
    })
}

#[cfg(feature = "native")]
fn valid_release_index_bytes() -> Result<ValidReleaseIndexBytes, ZkError> {
    let index = ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        ZkProofSuite::PRODUCTION,
        build_capability_registry()?.sha256(),
        release_artifact_pins()?,
        release_vector_pins()?,
    )?;
    let bytes = encode_release_index(&index)?;
    let sha256 = Digest32::sha256(bytes.as_slice());
    Ok(ValidReleaseIndexBytes { bytes, sha256 })
}

#[cfg(feature = "native")]
fn release_artifact_pins() -> Result<Vec<ReleaseArtifactPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_ARTIFACT_MANIFEST_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut marker = 1_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                pins.push(ReleaseArtifactPin::try_new(
                    *bundle_kind,
                    *stage,
                    bundle_kind.source_ref(*credential_hash_algorithm, *stage),
                    ZkArtifactManifestDigest::from_bytes([marker; 32]),
                )?);
                marker = marker
                    .checked_add(1)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            }
        }
    }
    Ok(pins)
}

#[cfg(feature = "native")]
fn release_vector_pins() -> Result<Vec<ReleaseVerificationVectorPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_VERIFICATION_VECTOR_SET_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut marker = 101_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            pins.push(ReleaseVerificationVectorPin::try_new(
                *bundle_kind,
                *credential_hash_algorithm,
                ZkProofSuite::PRODUCTION,
                Digest32::from_bytes([marker; 32]),
                12,
            )?);
            marker = marker
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(pins)
}

#[cfg(feature = "native")]
fn temp_test_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

#[cfg(feature = "native")]
fn platform_path_bytes(path: &std::path::Path) -> Result<String, ZkError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))
}

#[cfg(feature = "native")]
fn io_error_from_zk(_error: std::io::Error) -> ZkError {
    ZkError::new(ZkErrorReason::BackendFailure)
}
