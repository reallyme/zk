// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::assembly::circuit_directory;
use crate::source_attestation::validate_manifest_source_digest;
use crate::source_tree::SourceTree;
use crate::{ReleaseAssemblyError, ReleaseAssemblyErrorReason};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifact_package::{noir_source_tree_sha256, ArtifactPackageErrorReason};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactManifestPin, ArtifactToolchain, Digest32, ProductionArtifactManifest,
};
use reallyme_zk_proto_codec::capability_registry::build_capability_registry;

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn source_attestation_rejects_stale_manifest_source_digest() -> Result<(), ReleaseAssemblyError> {
    let root = temporary_root()?;
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stage = ZkClaimProofBundleStage::Session;
    let circuit_directory = circuit_directory(&root, bundle_kind, credential_hash_algorithm, stage);
    write_minimal_circuit(&circuit_directory)?;
    let source_tree = SourceTree::load(&root, &circuit_directory)?;
    let source_digest = noir_source_tree_sha256(&source_tree.borrowed_files()?)?;
    let manifest = manifest(bundle_kind, credential_hash_algorithm, stage, source_digest)?;

    validate_manifest_source_digest(&root, &manifest)?;

    fs::write(circuit_directory.join("src/main.nr"), b"fn main() { 1 }\n")?;
    assert_eq!(
        validate_manifest_source_digest(&root, &manifest)
            .err()
            .map(|error| error.reason()),
        Some(ReleaseAssemblyErrorReason::ArtifactPackage(
            ArtifactPackageErrorReason::PackageMismatch,
        ))
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

fn temporary_root() -> Result<PathBuf, ReleaseAssemblyError> {
    let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "reallyme-zk-source-attestation-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn write_minimal_circuit(directory: &Path) -> Result<(), ReleaseAssemblyError> {
    fs::create_dir_all(directory.join("src"))?;
    fs::write(
        directory.join("Nargo.toml"),
        b"[package]\nname = 'credential_credential_subject_claim_v1_session'\n",
    )?;
    fs::write(directory.join("src/main.nr"), b"fn main() {}\n")?;
    Ok(())
}

fn manifest(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
    source_digest: Digest32,
) -> Result<ProductionArtifactManifest, ReleaseAssemblyError> {
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    Ok(ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(
            ZkProofSuite::PRODUCTION,
            ZkArtifactManifestDigest::from_bytes([1; 32]),
        )?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: source_digest,
            bytecode_sha256: Digest32::from_bytes([2; 32]),
            verification_key_sha256: Digest32::from_bytes([3; 32]),
            capability_registry_sha256: build_capability_registry()?.sha256(),
            vector_set_sha256: vec![Digest32::from_bytes([4; 32])],
        },
    )?)
}
