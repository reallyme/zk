// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    artifact_bytes, binding, claim_proof_bundle_witness, production_manifest,
    provider_with_resolver, stage_manifest, ArtifactKind, BarretenbergArtifactResolver,
    BbStageArtifacts, ManifestBackedArtifactResolver, StaticArtifactResolver, TestArtifactStore,
    VerifiedArtifactBytes, ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest,
    ZkClaimProofBundleProver, ZkClaimProofBundleStage, ZkCredentialHashAlgorithm, ZkError,
    ZkErrorReason, ZkProofSuite,
};

#[test]
fn manifest_backed_resolver_accepts_matching_store_bytes() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(
        production_manifest(bundle_kind, credential_hash_algorithm)?,
        TestArtifactStore::matching(),
    );
    let stage = ZkClaimProofBundleStage::CredentialRoot;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);

    let artifacts = resolver.resolve_stage_artifacts(
        bundle_kind,
        stage,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
    )?;

    assert_eq!(artifacts.manifest().circuit_ref(), circuit_ref);
    assert!(artifacts
        .bytecode()
        .digest()
        .matches_sha256(artifacts.bytecode().as_bytes()));
    Ok(())
}

#[test]
fn stage_artifacts_reject_digest_valid_bytes_with_wrong_kind() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let stage = ZkClaimProofBundleStage::Claim;
    let manifest = stage_manifest(bundle_kind, ZkCredentialHashAlgorithm::Sha256, stage)?;
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        artifact_bytes(bundle_kind, stage, 40)?,
        manifest.digests().bytecode_sha256,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        artifact_bytes(bundle_kind, stage, 80)?,
        manifest.digests().verification_key_sha256,
    )?;
    let error = BbStageArtifacts::try_new(manifest, bytecode, verification_key)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn manifest_backed_resolver_rejects_wrong_profile() -> Result<(), ZkError> {
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(
        production_manifest(
            ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            ZkCredentialHashAlgorithm::Sha256,
        )?,
        TestArtifactStore::matching(),
    );
    let err = resolver
        .resolve_stage_artifacts(
            ZkClaimProofBundleKind::PrivatePersonaClaimV1,
            ZkClaimProofBundleStage::Claim,
            ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
                ZkCredentialHashAlgorithm::Sha256,
                ZkClaimProofBundleStage::Claim,
            ),
            ZkProofSuite::PRODUCTION,
        )
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn manifest_backed_resolver_rejects_wrong_hash_lane() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(
        production_manifest(bundle_kind, ZkCredentialHashAlgorithm::Poseidon2)?,
        TestArtifactStore::matching(),
    );
    let err = resolver
        .resolve_stage_artifacts(
            bundle_kind,
            ZkClaimProofBundleStage::Session,
            bundle_kind.source_ref(
                ZkCredentialHashAlgorithm::Sha256,
                ZkClaimProofBundleStage::Session,
            ),
            ZkProofSuite::PRODUCTION,
        )
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn manifest_backed_resolver_rejects_bad_store_bytes() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let resolver = ManifestBackedArtifactResolver::from_configured_trust_root(
        production_manifest(bundle_kind, credential_hash_algorithm)?,
        TestArtifactStore::bad_bytecode_bytes(),
    );
    let err = resolver
        .resolve_stage_artifacts(
            bundle_kind,
            ZkClaimProofBundleStage::CredentialEnvelope,
            bundle_kind.source_ref(
                credential_hash_algorithm,
                ZkClaimProofBundleStage::CredentialEnvelope,
            ),
            ZkProofSuite::PRODUCTION,
        )
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prove_claim_proof_bundle_rejects_resolver_manifest_mismatch() -> Result<(), ZkError> {
    let provider = provider_with_resolver(StaticArtifactResolver::wrong_manifest_profile());
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let witness_bundle = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;
    let err = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &witness_bundle,
            binding(3),
        )?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prove_claim_proof_bundle_rejects_resolver_digest_mismatch() -> Result<(), ZkError> {
    let provider = provider_with_resolver(StaticArtifactResolver::bad_bytecode_digest());
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Poseidon2;
    let witness_bundle = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;
    let err = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &witness_bundle,
            binding(4),
        )?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}
