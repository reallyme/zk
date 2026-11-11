// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{ArtifactToolchain, ArtifactVersion, Digest32};
use reallyme_zk_proto_codec::{
    capability_registry::build_capability_registry,
    release::{
        encode_release_index, ReleaseArtifactPin, ReleaseIndex, ReleaseVerificationVectorPin,
        RELEASE_ARTIFACT_MANIFEST_COUNT, RELEASE_VERIFICATION_VECTOR_SET_COUNT,
    },
};

use super::common_credential_root::common_credential_root_release_manifest_pin;
use crate::retained_witness::{RetainedStageWitnessStore, MAX_RETAINED_STAGE_WITNESSES};

#[cfg(feature = "diagnostic-exact-source")]
use super::exact_source::{
    collect_source_files, source_closure_digest_from_lock, trusted_claim_bundle4_artifact_identity,
    SourceTraversalBudget, TRUSTED_EXACT_SOURCE_LOCK_SHA256,
};
use super::{
    coordinates_for_circuit_ref, decode_pinned_release_index, read_exact_regular_file,
    read_manifest_bytes, DispatchLease, PlatformContext, PlatformCrsMode,
};

#[test]
fn production_coordinate_mapping_rejects_every_imported_bundle_stage() {
    let mut bundle_count = 0;
    for circuit_ref in ZkCircuitRef::ALL {
        if circuit_ref.stage != ZkCircuitStage::ClaimBundle4 {
            continue;
        }
        bundle_count += 1;
        let error = coordinates_for_circuit_ref(*circuit_ref)
            .err()
            .map(|failure| failure.reason());
        assert_eq!(error, Some(ZkErrorReason::UnsupportedCircuit));
    }
    assert_eq!(bundle_count, 4);
}

#[cfg(feature = "diagnostic-exact-source")]
#[test]
fn diagnostic_exact_source_trust_root_pins_claim_bundle4_only() -> Result<(), ZkError> {
    let mut admitted = 0_usize;
    for circuit_ref in ZkCircuitRef::ALL {
        if circuit_ref.stage != ZkCircuitStage::ClaimBundle4 {
            continue;
        }
        let identity = trusted_claim_bundle4_artifact_identity(*circuit_ref)?;
        assert!(!identity.is_zero());
        admitted = admitted
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    assert_eq!(admitted, 4);

    let production_stage = ZkClaimProofBundleKind::CredentialSubjectClaimV1.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Claim,
    );
    let rejected = trusted_claim_bundle4_artifact_identity(production_stage)
        .err()
        .map(|error| error.reason());
    assert_eq!(rejected, Some(ZkErrorReason::UnsupportedCircuit));
    Ok(())
}

#[cfg(feature = "diagnostic-exact-source")]
#[test]
fn diagnostic_exact_source_rejects_rewritten_source_lock() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-source-lock-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    let lock = root.join("modern-circuit-source-lock.tsv");
    std::fs::write(
        &lock,
        b"circuit\tpackage\tsource_closure_sha256\nsha256/families/credential_subject_claim_v1/claim_bundle_4\tcredential_credential_subject_claim_v1_claim_bundle_4\t0000000000000000000000000000000000000000000000000000000000000000\n",
    )?;

    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        reallyme_zk_api::circuits::ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::ClaimBundle4,
    );
    let error = source_closure_digest_from_lock(&lock, circuit_ref)
        .err()
        .map(|failure| failure.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    assert_ne!(
        Digest32::sha256(std::fs::read(&lock)?.as_slice()).as_bytes(),
        &TRUSTED_EXACT_SOURCE_LOCK_SHA256
    );
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[cfg(all(feature = "diagnostic-exact-source", unix))]
#[test]
fn diagnostic_exact_source_rejects_symlinked_vendor_traversal() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-vendor-symlink-test-{}",
        std::process::id()
    ));
    let outside = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-vendor-symlink-target-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&outside)?;
    std::os::unix::fs::symlink(&outside, root.join("vendor"))?;

    let mut budget = SourceTraversalBudget::new();
    let mut source_paths = Vec::new();
    let error = collect_source_files(&root, "vendor", 0, &mut budget, &mut source_paths)
        .err()
        .map(|failure| failure.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    std::fs::remove_dir_all(&root)?;
    std::fs::remove_dir_all(&outside)?;
    Ok(())
}

#[test]
fn concurrent_dispatch_rejects_second_lease_and_recovers_after_release() -> Result<(), ZkError> {
    let active = std::sync::atomic::AtomicBool::new(false);
    let first = DispatchLease::try_acquire(&active)?;
    let second_reason = DispatchLease::try_acquire(&active)
        .err()
        .map(|error| error.reason());

    assert_eq!(second_reason, Some(ZkErrorReason::BackendUnavailable));
    drop(first);

    let recovered = DispatchLease::try_acquire(&active)?;
    drop(recovered);
    Ok(())
}

#[test]
fn release_index_digest_mismatch_rejects_substituted_index_before_decode() {
    let substituted = b"substituted release index";
    let approved = Digest32::sha256(b"approved release index");

    let error = decode_pinned_release_index(substituted, approved.as_bytes())
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
}

#[test]
fn release_index_substitution_with_matching_digest_is_low_level_caller_trust() -> Result<(), ZkError>
{
    let substituted = substituted_release_index()?;
    let encoded = encode_release_index(&substituted)?;
    let substituted_digest = Digest32::sha256(encoded.as_slice());

    let decoded = decode_pinned_release_index(encoded.as_slice(), substituted_digest.as_bytes())?;

    assert_eq!(
        decoded.artifact_manifests()[0].manifest_sha256(),
        ZkArtifactManifestDigest::from_bytes([1; 32])
    );
    Ok(())
}

#[test]
fn matching_index_digest_cannot_admit_a_retired_capability_registry() -> Result<(), ZkError> {
    let retired = ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        ZkProofSuite::PRODUCTION,
        Digest32::from_bytes([0x53; 32]),
        release_artifact_pins()?,
        release_vector_pins()?,
    )?;
    let encoded = encode_release_index(&retired)?;
    let digest = Digest32::sha256(encoded.as_slice());

    let reason = decode_pinned_release_index(encoded.as_slice(), digest.as_bytes())
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    Ok(())
}

#[test]
fn current_release_index_rejects_unpromoted_common_credential_root_refs() -> Result<(), ZkError> {
    let release_index = substituted_release_index()?;
    let common_credential_root_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    );
    let session_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::Session,
    );

    let common_credential_root_error = common_credential_root_release_manifest_pin(
        &release_index,
        common_credential_root_ref,
        ZkProofSuite::PRODUCTION,
    )
    .err()
    .map(|error| error.reason());
    let session_pin = common_credential_root_release_manifest_pin(
        &release_index,
        session_ref,
        ZkProofSuite::PRODUCTION,
    )?;

    assert_eq!(
        common_credential_root_error,
        Some(ZkErrorReason::ArtifactMismatch)
    );
    assert!(!session_pin.is_zero());
    Ok(())
}

#[cfg(unix)]
#[test]
fn manifest_reader_rejects_symlink_manifest() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-symlink-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let package_dir = root.join("v1/sha256/private_persona_claim_v1/session/00");
    std::fs::create_dir_all(&package_dir)?;
    let target = root.join("target-manifest.pb");
    std::fs::write(&target, b"not a valid manifest")?;
    let manifest = package_dir.join("manifest.pb");
    std::os::unix::fs::symlink(&target, &manifest)?;

    let error = read_manifest_bytes(&root, &manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn manifest_reader_rejects_fifo_manifest_without_waiting_for_writer() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-fifo-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let package_dir = root.join("v1/sha256/private_persona_claim_v1/session/00");
    std::fs::create_dir_all(&package_dir)?;
    let manifest = package_dir.join("manifest.pb");
    let status = std::process::Command::new("mkfifo")
        .arg(&manifest)
        .status()?;
    assert!(status.success());

    let error = read_manifest_bytes(&root, &manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn exact_file_reader_accepts_exact_regular_file() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-crs-exact-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    let path = root.join("crs.bin");
    std::fs::write(&path, [1_u8, 2, 3, 4])?;

    let bytes = read_exact_regular_file(&path, 4).map_err(io_error_from_zk)?;

    assert_eq!(bytes.as_slice(), &[1_u8, 2, 3, 4]);
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn exact_file_reader_rejects_wrong_length() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-crs-length-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    let path = root.join("crs.bin");
    std::fs::write(&path, [1_u8, 2, 3, 4])?;

    let error = read_exact_regular_file(&path, 5)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn exact_file_reader_rejects_symlink() -> std::io::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-crs-symlink-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    let target = root.join("target.bin");
    std::fs::write(&target, [1_u8, 2, 3, 4])?;
    let path = root.join("crs.bin");
    std::os::unix::fs::symlink(&target, &path)?;

    let error = read_exact_regular_file(&path, 4)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn file_backed_context_rejects_exact_length_wrong_crs_hash() -> Result<(), ZkError> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-platform-ffi-crs-hash-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let g1_path = root.join("g1.bin");
    let g2_path = root.join("g2.bin");
    std::fs::write(&g1_path, [0_u8; 64])
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    std::fs::write(&g2_path, [0_u8; 128])
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let release_index = substituted_release_index()?;
    let release_index_bytes = encode_release_index(&release_index)?;
    let release_index_digest = Digest32::sha256(release_index_bytes.as_slice());
    let root_bytes = platform_path_bytes(&root)?;
    let g1_path_bytes = platform_path_bytes(&g1_path)?;
    let g2_path_bytes = platform_path_bytes(&g2_path)?;

    let error = PlatformContext::try_new_from_crs_files(
        root_bytes.as_bytes(),
        release_index_bytes.as_slice(),
        release_index_digest.as_bytes(),
        g1_path_bytes.as_bytes(),
        g2_path_bytes.as_bytes(),
        PlatformCrsMode::VerifierOnly,
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::ArtifactMismatch));
    std::fs::remove_dir_all(&root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[test]
fn retained_witness_release_is_single_use() -> Result<(), ZkError> {
    let store = RetainedStageWitnessStore::new();
    let circuit_ref = retained_witness_circuit_ref();
    let handle = store.retain(circuit_ref, retained_witness(circuit_ref, 1)?)?;

    store.release(handle, circuit_ref)?;

    let release_error = store
        .release(handle, circuit_ref)
        .err()
        .map(|error| error.reason());
    let take_error = store
        .take(handle, circuit_ref)
        .err()
        .map(|error| error.reason());

    assert_eq!(release_error, Some(ZkErrorReason::MissingStage));
    assert_eq!(take_error, Some(ZkErrorReason::MissingStage));
    Ok(())
}

#[test]
fn retained_witness_capacity_fails_closed_and_recovers_after_release() -> Result<(), ZkError> {
    let store = RetainedStageWitnessStore::new();
    let circuit_ref = retained_witness_circuit_ref();
    let mut handles = Vec::new();
    handles
        .try_reserve_exact(MAX_RETAINED_STAGE_WITNESSES)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for _ in 0..MAX_RETAINED_STAGE_WITNESSES {
        handles.push(store.retain(circuit_ref, retained_witness(circuit_ref, 1)?)?);
    }

    let full_error = store
        .retain(circuit_ref, retained_witness(circuit_ref, 2)?)
        .err()
        .map(|error| error.reason());
    assert_eq!(full_error, Some(ZkErrorReason::ResourceExhausted));

    let released = handles
        .pop()
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    store.release(released, circuit_ref)?;
    let replacement = store.retain(circuit_ref, retained_witness(circuit_ref, 3)?)?;
    let replacement_witness = store.take(replacement, circuit_ref)?;
    assert_eq!(replacement_witness.expose_bytes(), &[3]);
    for handle in handles {
        store.release(handle, circuit_ref)?;
    }
    Ok(())
}

#[test]
fn retained_witness_handles_are_process_wide_not_context_local() -> Result<(), ZkError> {
    let first_context = RetainedStageWitnessStore::new();
    let second_context = RetainedStageWitnessStore::new();
    let circuit_ref = retained_witness_circuit_ref();
    let first_handle = first_context.retain(circuit_ref, retained_witness(circuit_ref, 1)?)?;
    let second_handle = second_context.retain(circuit_ref, retained_witness(circuit_ref, 2)?)?;

    let cross_context_error = second_context
        .take(first_handle, circuit_ref)
        .err()
        .map(|error| error.reason());

    assert_ne!(first_handle, second_handle);
    assert_eq!(cross_context_error, Some(ZkErrorReason::MissingStage));
    let _second_witness = second_context.take(second_handle, circuit_ref)?;
    let _first_witness = first_context.take(first_handle, circuit_ref)?;
    Ok(())
}

#[test]
fn retained_witness_ordered_take_is_all_or_nothing() -> Result<(), ZkError> {
    let store = RetainedStageWitnessStore::new();
    let stage_refs = retained_witness_stage_refs();
    let first_handle = store.retain(stage_refs[0], retained_witness(stage_refs[0], 1)?)?;
    let second_handle = store.retain(stage_refs[1], retained_witness(stage_refs[1], 2)?)?;
    let third_handle = store.retain(stage_refs[2], retained_witness(stage_refs[2], 3)?)?;
    let missing_handle = first_handle
        .checked_add(10_000)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let invalid_request = [
        (first_handle, stage_refs[0]),
        (second_handle, stage_refs[1]),
        (third_handle, stage_refs[2]),
        (missing_handle, stage_refs[3]),
    ];

    let error = store
        .take_ordered(&invalid_request)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::MissingStage));
    let retained_first = store.take(first_handle, stage_refs[0])?;
    assert_eq!(retained_first.expose_bytes(), &[1]);
    let retained_second = store.take(second_handle, stage_refs[1])?;
    assert_eq!(retained_second.expose_bytes(), &[2]);
    let retained_third = store.take(third_handle, stage_refs[2])?;
    assert_eq!(retained_third.expose_bytes(), &[3]);
    Ok(())
}

#[test]
fn retained_witness_ordered_take_or_release_consumes_present_handles_on_missing_stage(
) -> Result<(), ZkError> {
    let store = RetainedStageWitnessStore::new();
    let stage_refs = retained_witness_stage_refs();
    let first_handle = store.retain(stage_refs[0], retained_witness(stage_refs[0], 1)?)?;
    let second_handle = store.retain(stage_refs[1], retained_witness(stage_refs[1], 2)?)?;
    let third_handle = store.retain(stage_refs[2], retained_witness(stage_refs[2], 3)?)?;
    let missing_handle = first_handle
        .checked_add(10_000)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let invalid_request = [
        (first_handle, stage_refs[0]),
        (second_handle, stage_refs[1]),
        (third_handle, stage_refs[2]),
        (missing_handle, stage_refs[3]),
    ];

    let error = store
        .take_ordered_or_release_present(&invalid_request)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::MissingStage));
    assert_eq!(
        store
            .take(first_handle, stage_refs[0])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    assert_eq!(
        store
            .take(second_handle, stage_refs[1])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    assert_eq!(
        store
            .take(third_handle, stage_refs[2])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    Ok(())
}

#[test]
fn retained_witness_ordered_take_or_release_consumes_duplicate_handle_request(
) -> Result<(), ZkError> {
    let store = RetainedStageWitnessStore::new();
    let stage_refs = retained_witness_stage_refs();
    let first_handle = store.retain(stage_refs[0], retained_witness(stage_refs[0], 1)?)?;
    let second_handle = store.retain(stage_refs[1], retained_witness(stage_refs[1], 2)?)?;
    let invalid_request = [
        (first_handle, stage_refs[0]),
        (first_handle, stage_refs[1]),
        (second_handle, stage_refs[1]),
    ];

    let error = store
        .take_ordered_or_release_present(&invalid_request)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::DuplicateStage));
    assert_eq!(
        store
            .take(first_handle, stage_refs[0])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    assert_eq!(
        store
            .take(second_handle, stage_refs[1])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    Ok(())
}

#[test]
fn retained_witness_ordered_take_returns_canonical_order() -> Result<(), ZkError> {
    let store = RetainedStageWitnessStore::new();
    let stage_refs = retained_witness_stage_refs();
    let session_handle = store.retain(stage_refs[0], retained_witness(stage_refs[0], 1)?)?;
    let envelope_handle = store.retain(stage_refs[1], retained_witness(stage_refs[1], 2)?)?;
    let root_handle = store.retain(stage_refs[2], retained_witness(stage_refs[2], 3)?)?;
    let claim_handle = store.retain(stage_refs[3], retained_witness(stage_refs[3], 4)?)?;
    let request = [
        (session_handle, stage_refs[0]),
        (envelope_handle, stage_refs[1]),
        (root_handle, stage_refs[2]),
        (claim_handle, stage_refs[3]),
    ];

    let witnesses = store.take_ordered(&request)?;

    assert_eq!(witnesses[0].expose_bytes(), &[1]);
    assert_eq!(witnesses[1].expose_bytes(), &[2]);
    assert_eq!(witnesses[2].expose_bytes(), &[3]);
    assert_eq!(witnesses[3].expose_bytes(), &[4]);
    assert_eq!(
        store
            .take(session_handle, stage_refs[0])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    Ok(())
}

fn substituted_release_index() -> Result<ReleaseIndex, ZkError> {
    ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        ZkProofSuite::PRODUCTION,
        build_capability_registry()?.sha256(),
        release_artifact_pins()?,
        release_vector_pins()?,
    )
}

fn retained_witness_circuit_ref() -> reallyme_zk_api::circuits::ZkCircuitRef {
    ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Session,
    )
}

fn retained_witness_stage_refs() -> [reallyme_zk_api::circuits::ZkCircuitRef; 4] {
    [
        ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Session,
        ),
        ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::CredentialEnvelope,
        ),
        ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::CredentialRoot,
        ),
        ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Claim,
        ),
    ]
}

fn retained_witness(
    circuit_ref: reallyme_zk_api::circuits::ZkCircuitRef,
    marker: u8,
) -> Result<reallyme_zk_api::proofs::ZkWitness, ZkError> {
    reallyme_zk_api::proofs::ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![marker])
}

fn io_error_from_zk(_error: ZkError) -> std::io::Error {
    std::io::Error::other("typed zk error")
}

fn platform_path_bytes(path: &std::path::Path) -> Result<String, ZkError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))
}

fn release_artifact_pins() -> Result<Vec<ReleaseArtifactPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_ARTIFACT_MANIFEST_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut marker = 1_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for profile in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                pins.push(ReleaseArtifactPin::try_new(
                    *profile,
                    *stage,
                    profile.source_ref(*credential_hash_algorithm, *stage),
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

fn release_vector_pins() -> Result<Vec<ReleaseVerificationVectorPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_VERIFICATION_VECTOR_SET_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut marker = 101_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for profile in ZkClaimProofBundleKind::ALL {
            pins.push(ReleaseVerificationVectorPin::try_new(
                *profile,
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
