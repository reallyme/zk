// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::sync::atomic::{AtomicU64, Ordering};
use std::{fs, path::PathBuf};

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactPackageLayout, ArtifactToolchain,
    Digest32, ProductionArtifactManifest, ProductionBundleManifest, MAX_ACIR_BYTECODE_BYTES,
};

use crate::{
    BarretenbergArtifactResolver, BarretenbergArtifactStore, ManifestBackedArtifactResolver,
    NativeFilesystemArtifactStore,
};

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_root() -> Result<PathBuf, ZkError> {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "reallyme-zk-native-artifacts-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&path).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(path)
}

fn bytes_for(stage: ZkClaimProofBundleStage) -> Result<(Vec<u8>, Vec<u8>), ZkError> {
    let marker = stage
        .index()
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    Ok((
        vec![marker; 3],
        vec![
            marker
                .checked_add(32)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow),)?;
            4
        ],
    ))
}

fn manifest_for(
    stage: ZkClaimProofBundleStage,
    bytecode: &[u8],
    verification_key: &[u8],
) -> Result<ProductionArtifactManifest, ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(
            ZkProofSuite::PRODUCTION,
            ZkArtifactManifestDigest::from_bytes(
                [stage
                    .index()
                    .checked_add(1)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?; 32],
            ),
        )?,
        ArtifactToolchain::try_from_versions("1.0.0-beta.9", "0.87.0")?,
        circuit_ref_capabilities(circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([7; 32]),
            bytecode_sha256: Digest32::sha256(bytecode),
            verification_key_sha256: Digest32::sha256(verification_key),
            capability_registry_sha256: Digest32::from_bytes([8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([9; 32])],
        },
    )
}

fn complete_fixture(root: &std::path::Path) -> Result<Vec<ProductionArtifactManifest>, ZkError> {
    let mut manifests = Vec::new();
    manifests
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    for stage in ZkClaimProofBundleStage::ALL {
        let (bytecode, verification_key) = bytes_for(*stage)?;
        let manifest = manifest_for(*stage, &bytecode, &verification_key)?;
        let layout = ArtifactPackageLayout::try_new(
            root,
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            *stage,
            manifest.manifest_sha256(),
        )?;
        fs::create_dir_all(layout.directory())
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        fs::write(layout.program(), bytecode)
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        fs::write(layout.verification_key(), verification_key)
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        manifests.push(manifest);
    }
    Ok(manifests)
}

#[test]
fn filesystem_store_and_resolver_admit_exact_package_bytes() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let manifests = complete_fixture(&root)?;
    let bundle = ProductionBundleManifest::try_from_stage_manifests(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkCredentialHashAlgorithm::Sha256,
        manifests,
    )?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(bundle, store);
    let circuit_ref = ZkClaimProofBundleKind::CredentialSubjectClaimV1.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Session,
    );
    let artifacts = resolver.resolve_stage_artifacts(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
    )?;

    assert_eq!(artifacts.bytecode().as_bytes(), &[1; 3]);
    assert_eq!(artifacts.verification_key().as_bytes(), &[33; 4]);
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[test]
fn resolver_rejects_tampered_filesystem_artifact() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let manifests = complete_fixture(&root)?;
    let session_manifest_sha256 = manifests
        .first()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?
        .manifest_sha256();
    let bundle = ProductionBundleManifest::try_from_stage_manifests(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkCredentialHashAlgorithm::Sha256,
        manifests,
    )?;
    let layout = ArtifactPackageLayout::try_new(
        &root,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        session_manifest_sha256,
    )?;
    fs::write(layout.program(), [0xa5; 3])
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(
        bundle,
        NativeFilesystemArtifactStore::try_new(&root)?,
    );
    let circuit_ref = ZkClaimProofBundleKind::CredentialSubjectClaimV1.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Session,
    );
    let reason = resolver
        .resolve_stage_artifacts(
            ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            ZkClaimProofBundleStage::Session,
            circuit_ref,
            ZkProofSuite::PRODUCTION,
        )
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[test]
fn oversized_file_is_rejected_before_allocation() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let (bytecode, verification_key) = bytes_for(ZkClaimProofBundleStage::Session)?;
    let manifest = manifest_for(
        ZkClaimProofBundleStage::Session,
        &bytecode,
        &verification_key,
    )?;
    let layout = ArtifactPackageLayout::try_new(
        &root,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        manifest.manifest_sha256(),
    )?;
    fs::create_dir_all(layout.directory())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let file = fs::File::create(layout.program())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let oversized = u64::try_from(MAX_ACIR_BYTECODE_BYTES)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    file.set_len(oversized)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let reason = store
        .bytecode_bytes(&manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactTooLarge));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[test]
fn empty_artifact_file_is_rejected() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let (bytecode, verification_key) = bytes_for(ZkClaimProofBundleStage::Session)?;
    let manifest = manifest_for(
        ZkClaimProofBundleStage::Session,
        &bytecode,
        &verification_key,
    )?;
    let layout = ArtifactPackageLayout::try_new(
        &root,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        manifest.manifest_sha256(),
    )?;
    fs::create_dir_all(layout.directory())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    fs::write(layout.program(), []).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let reason = store
        .bytecode_bytes(&manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::EmptyInput));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[test]
fn absent_typed_coordinate_fails_closed() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let (bytecode, verification_key) = bytes_for(ZkClaimProofBundleStage::Session)?;
    let manifest = manifest_for(
        ZkClaimProofBundleStage::Session,
        &bytecode,
        &verification_key,
    )?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let reason = store
        .bytecode_bytes(&manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_artifact_file_is_rejected() -> Result<(), ZkError> {
    use std::os::unix::fs::symlink;

    let root = temporary_root()?;
    let (bytecode, verification_key) = bytes_for(ZkClaimProofBundleStage::Session)?;
    let manifest = manifest_for(
        ZkClaimProofBundleStage::Session,
        &bytecode,
        &verification_key,
    )?;
    let layout = ArtifactPackageLayout::try_new(
        &root,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        manifest.manifest_sha256(),
    )?;
    fs::create_dir_all(layout.directory())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let external = root.join("external-program");
    fs::write(&external, bytecode).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    symlink(&external, layout.program())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let reason = store
        .bytecode_bytes(&manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[cfg(unix)]
#[test]
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn fifo_artifact_file_is_rejected_without_waiting_for_a_writer() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let (bytecode, verification_key) = bytes_for(ZkClaimProofBundleStage::Session)?;
    let manifest = manifest_for(
        ZkClaimProofBundleStage::Session,
        &bytecode,
        &verification_key,
    )?;
    let layout = ArtifactPackageLayout::try_new(
        &root,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        manifest.manifest_sha256(),
    )?;
    fs::create_dir_all(layout.directory())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let created = std::process::Command::new("mkfifo")
        .arg(layout.program())
        .status()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    if !created.success() {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let reason = store
        .bytecode_bytes(&manifest)
        .err()
        .map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_package_directory_is_rejected() -> Result<(), ZkError> {
    use std::os::unix::fs::symlink;

    let root = temporary_root()?;
    let (bytecode, verification_key) = bytes_for(ZkClaimProofBundleStage::Session)?;
    let manifest = manifest_for(
        ZkClaimProofBundleStage::Session,
        &bytecode,
        &verification_key,
    )?;
    let layout = ArtifactPackageLayout::try_new(
        &root,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        manifest.manifest_sha256(),
    )?;
    let external = root.join("external-package");
    fs::create_dir(&external).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    fs::write(external.join("program.json"), bytecode)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let parent = layout
        .directory()
        .parent()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    fs::create_dir_all(parent).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    symlink(&external, layout.directory())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let reason = store
        .bytecode_bytes(&manifest)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    fs::remove_dir_all(root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn admitted_root_descriptor_survives_path_replacement() -> Result<(), ZkError> {
    let root = temporary_root()?;
    let manifests = complete_fixture(&root)?;
    let manifest = manifests
        .first()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let store = NativeFilesystemArtifactStore::try_new(&root)?;
    let admitted_root = root.with_extension("admitted");

    fs::rename(&root, &admitted_root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    fs::create_dir(&root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;

    let loaded = store.bytecode_bytes(manifest);
    fs::remove_dir_all(&root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    fs::remove_dir_all(&admitted_root).map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(loaded?.as_bytes(), &[1; 3]);
    Ok(())
}

#[test]
fn store_rejects_relative_root() {
    let reason = NativeFilesystemArtifactStore::try_new(std::path::Path::new("artifacts"))
        .err()
        .map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
}

#[test]
fn artifact_kind_limits_remain_independent() {
    assert!(ArtifactKind::AcirBytecode.max_bytes() > ArtifactKind::VerificationKey.max_bytes());
}
