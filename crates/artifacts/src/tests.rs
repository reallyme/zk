// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, ArtifactVersion,
    Digest32, ProductionArtifactManifest, ProductionBundleManifest, VerifiedArtifactBytes,
    MAX_ARTIFACT_VERSION_BYTES, MAX_VECTOR_SET_DIGESTS, MAX_VERIFICATION_KEY_BYTES,
};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::{circuit_ref_capabilities, presentation_capabilities, ZkSemanticGuarantee},
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkCompatibilitySuiteAcknowledgement,
    },
    proofs::ZkProofSuite,
};

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([8_u8; 32])
}

fn manifest_pin() -> Result<ArtifactManifestPin, reallyme_zk_api::errors::ZkError> {
    ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest())
}

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn digests() -> ArtifactDigests {
    ArtifactDigests {
        noir_source_sha256: digest(1),
        bytecode_sha256: digest(2),
        verification_key_sha256: digest(3),
        capability_registry_sha256: digest(4),
        vector_set_sha256: vec![digest(5), digest(6)],
    }
}

fn toolchain() -> Result<ArtifactToolchain, reallyme_zk_api::errors::ZkError> {
    ArtifactToolchain::try_from_versions("1.0.0-beta.9", "0.82.2")
}

#[test]
fn artifact_version_retains_bounded_ascii_token() -> Result<(), reallyme_zk_api::errors::ZkError> {
    let version = ArtifactVersion::try_from_token("1.0.0-beta.9")?;

    assert_eq!(version.as_bytes(), b"1.0.0-beta.9");
    Ok(())
}

#[test]
fn artifact_version_rejects_empty_oversized_and_non_ascii_tokens() {
    for value in [
        String::new(),
        "x".repeat(MAX_ARTIFACT_VERSION_BYTES.saturating_add(1)),
        "1.0.0-β".to_owned(),
        "1.0.0/../../bin".to_owned(),
    ] {
        let error = ArtifactVersion::try_from_token(value.as_str())
            .err()
            .unwrap_or(reallyme_zk_api::errors::ZkError::new(
                reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
            ));
        assert_eq!(
            error.reason(),
            reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
        );
    }
}

#[test]
fn artifact_manifest_pin_rejects_zero_digest() {
    let error = ArtifactManifestPin::try_new(
        ZkProofSuite::PRODUCTION,
        ZkArtifactManifestDigest::from_bytes([0_u8; 32]),
    )
    .err()
    .unwrap_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ));

    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
}

#[test]
fn artifact_manifest_pin_rejects_compatibility_suite_without_acknowledgement() {
    let error = ArtifactManifestPin::try_new(
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
        manifest_digest(),
    )
    .err()
    .unwrap_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ));

    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::UnsupportedProofSuite
    );
}

#[test]
fn artifact_manifest_pin_accepts_acknowledged_compatibility_suite(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let proof_suite = ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa;
    let pin = ArtifactManifestPin::try_new_compatibility(
        proof_suite,
        manifest_digest(),
        ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
    )?;

    assert_eq!(pin.proof_suite(), proof_suite);
    assert_eq!(pin.manifest_sha256(), manifest_digest());
    Ok(())
}

#[test]
fn production_manifest_rejects_excess_vector_digests(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let mut excessive_digests = digests();
    excessive_digests.vector_set_sha256 = vec![digest(9); MAX_VECTOR_SET_DIGESTS.saturating_add(1)];
    let error = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        manifest_pin()?,
        toolchain()?,
        capabilities,
        excessive_digests,
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
    Ok(())
}

#[test]
fn production_manifest_rejects_zero_artifact_digests(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let mut zero_bytecode = digests();
    zero_bytecode.bytecode_sha256 = Digest32::from_bytes([0_u8; 32]);
    let mut zero_vector = digests();
    zero_vector.vector_set_sha256 = vec![Digest32::from_bytes([0_u8; 32])];

    for candidate in [zero_bytecode, zero_vector] {
        let error = ProductionArtifactManifest::try_new(
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin()?,
            toolchain()?,
            capabilities,
            candidate,
        )
        .err()
        .ok_or(reallyme_zk_api::errors::ZkError::new(
            reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
        ))?;

        assert_eq!(
            error.reason(),
            reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
        );
    }
    Ok(())
}

#[test]
fn digest_sha256_matches_known_empty_hash() {
    let digest = Digest32::sha256(&[]);
    assert_eq!(
        digest.as_bytes(),
        &[
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );
}

#[test]
fn verified_artifact_bytes_accept_matching_digest() -> Result<(), reallyme_zk_api::errors::ZkError>
{
    let bytes = vec![1_u8, 2, 3, 4];
    let digest = Digest32::sha256(bytes.as_slice());
    let artifact =
        VerifiedArtifactBytes::try_from_bytes(ArtifactKind::AcirBytecode, bytes, digest)?;

    assert_eq!(artifact.digest(), digest);
    assert_eq!(artifact.kind(), ArtifactKind::AcirBytecode);
    assert_eq!(artifact.as_bytes(), &[1_u8, 2, 3, 4]);
    Ok(())
}

#[test]
fn verified_artifact_bytes_reject_mismatched_digest() -> Result<(), reallyme_zk_api::errors::ZkError>
{
    let err = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        vec![1_u8, 2, 3, 4],
        digest(9),
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
    Ok(())
}

#[test]
fn artifact_kind_rejects_declared_oversize_before_allocation(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let oversized =
        MAX_VERIFICATION_KEY_BYTES
            .checked_add(1)
            .ok_or(reallyme_zk_api::errors::ZkError::new(
                reallyme_zk_api::errors::ZkErrorReason::LengthOverflow,
            ))?;
    let error = ArtifactKind::VerificationKey
        .validate_length(oversized)
        .err()
        .ok_or(reallyme_zk_api::errors::ZkError::new(
            reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
        ))?;

    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactTooLarge
    );
    Ok(())
}

#[test]
fn artifact_kind_limits_are_distinct_and_reject_empty_input() {
    assert!(ArtifactKind::AcirBytecode.max_bytes() > ArtifactKind::VerificationKey.max_bytes());
    let error = ArtifactKind::AcirBytecode
        .validate_length(0)
        .err()
        .unwrap_or(reallyme_zk_api::errors::ZkError::new(
            reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
        ));
    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::EmptyInput
    );
}

#[test]
fn verified_artifact_debug_redacts_payload() -> Result<(), reallyme_zk_api::errors::ZkError> {
    let sentinel = b"artifact-payload-sentinel";
    let digest = Digest32::sha256(sentinel);
    let artifact = VerifiedArtifactBytes::try_copy_from_slice(
        ArtifactKind::VerificationKey,
        sentinel,
        digest,
    )?;
    let debug = format!("{artifact:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("artifact-payload-sentinel"));
    Ok(())
}

fn stage_manifest(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
) -> Result<ProductionArtifactManifest, reallyme_zk_api::errors::ZkError> {
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        manifest_pin()?,
        toolchain()?,
        capabilities,
        digests(),
    )
}

fn complete_stage_manifests(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<Vec<ProductionArtifactManifest>, reallyme_zk_api::errors::ZkError> {
    let mut manifests = Vec::new();
    for stage in ZkClaimProofBundleStage::ALL {
        manifests.push(stage_manifest(
            bundle_kind,
            credential_hash_algorithm,
            *stage,
        )?);
    }
    Ok(manifests)
}

#[test]
fn production_manifest_accepts_matching_source_ref() -> Result<(), reallyme_zk_api::errors::ZkError>
{
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let manifest = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        manifest_pin()?,
        toolchain()?,
        capabilities,
        digests(),
    )?;

    assert_eq!(manifest.bundle_kind(), bundle_kind);
    assert_eq!(manifest.stage(), stage);
    assert_eq!(manifest.circuit_ref(), circuit_ref);
    assert!(manifest
        .semantic_guarantees()
        .contains(&ZkSemanticGuarantee::PrivatePersonaBinding));
    Ok(())
}

#[test]
fn production_manifest_rejects_compatibility_suite_without_acknowledgement(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let proof_suite = ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa;
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let pin = ArtifactManifestPin::try_new_compatibility(
        proof_suite,
        manifest_digest(),
        ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
    )?;
    let error = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        pin,
        toolchain()?,
        capabilities,
        digests(),
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::UnsupportedProofSuite
    );
    Ok(())
}

#[test]
fn production_manifest_accepts_acknowledged_compatibility_suite(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let proof_suite = ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa;
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let manifest = ProductionArtifactManifest::try_new_compatibility(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new_compatibility(
            proof_suite,
            manifest_digest(),
            ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )?,
        toolchain()?,
        capabilities,
        digests(),
        ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
    )?;

    assert_eq!(manifest.proof_suite(), proof_suite);
    assert_eq!(manifest.bundle_kind(), bundle_kind);
    assert_eq!(manifest.stage(), stage);
    Ok(())
}

#[test]
fn production_manifest_rejects_wrong_stage_ref() -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let circuit_ref = bundle_kind.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkClaimProofBundleStage::Claim,
    );
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    let err = ProductionArtifactManifest::try_new(
        bundle_kind,
        ZkClaimProofBundleStage::Session,
        circuit_ref,
        manifest_pin()?,
        toolchain()?,
        capabilities,
        digests(),
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::StageMismatch
    );
    Ok(())
}

#[test]
fn production_manifest_rejects_bundle_guarantees_on_session_stage(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stage = ZkClaimProofBundleStage::Session;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let err = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        manifest_pin()?,
        toolchain()?,
        presentation_capabilities(bundle_kind.family()),
        digests(),
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
    Ok(())
}

#[test]
fn production_manifest_rejects_different_stage_capabilities(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let stage = ZkClaimProofBundleStage::CredentialEnvelope;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Poseidon2, stage);
    let session_capabilities = circuit_ref_capabilities(bundle_kind.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkClaimProofBundleStage::Session,
    ))?;
    let err = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        manifest_pin()?,
        toolchain()?,
        session_capabilities,
        digests(),
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
    Ok(())
}

#[test]
fn production_bundle_manifest_accepts_complete_profile(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Poseidon2;
    let manifests = complete_stage_manifests(bundle_kind, credential_hash_algorithm)?;
    let bundle_manifest = ProductionBundleManifest::try_from_stage_manifests(
        bundle_kind,
        credential_hash_algorithm,
        manifests,
    )?;

    assert_eq!(bundle_manifest.bundle_kind(), bundle_kind);
    assert_eq!(
        bundle_manifest.credential_hash_algorithm(),
        credential_hash_algorithm
    );
    assert_eq!(
        bundle_manifest.stage_manifests().len(),
        ZkClaimProofBundleStage::ALL.len()
    );
    assert_eq!(
        bundle_manifest
            .stage_manifest(ZkClaimProofBundleStage::CredentialRoot)?
            .stage(),
        ZkClaimProofBundleStage::CredentialRoot
    );
    Ok(())
}

#[test]
fn production_bundle_manifest_rejects_missing_stage() -> Result<(), reallyme_zk_api::errors::ZkError>
{
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let manifests = vec![stage_manifest(
        bundle_kind,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Session,
    )?];
    let err = ProductionBundleManifest::try_from_stage_manifests(
        bundle_kind,
        ZkCredentialHashAlgorithm::Sha256,
        manifests,
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::MissingStage
    );
    Ok(())
}

#[test]
fn production_bundle_manifest_rejects_duplicate_stage(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let manifests = vec![
        stage_manifest(
            bundle_kind,
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Session,
        )?,
        stage_manifest(
            bundle_kind,
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Session,
        )?,
        stage_manifest(
            bundle_kind,
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::CredentialRoot,
        )?,
        stage_manifest(
            bundle_kind,
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Claim,
        )?,
    ];
    let err = ProductionBundleManifest::try_from_stage_manifests(
        bundle_kind,
        ZkCredentialHashAlgorithm::Sha256,
        manifests,
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::DuplicateStage
    );
    Ok(())
}

#[test]
fn production_bundle_manifest_rejects_mixed_hash_lanes(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let mut manifests = complete_stage_manifests(bundle_kind, ZkCredentialHashAlgorithm::Sha256)?;
    let poseidon2_claim = stage_manifest(
        bundle_kind,
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkClaimProofBundleStage::Claim,
    )?;
    let last = manifests
        .last_mut()
        .ok_or(reallyme_zk_api::errors::ZkError::new(
            reallyme_zk_api::errors::ZkErrorReason::MissingStage,
        ))?;
    *last = poseidon2_claim;

    let err = ProductionBundleManifest::try_from_stage_manifests(
        bundle_kind,
        ZkCredentialHashAlgorithm::Sha256,
        manifests,
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        err.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
    Ok(())
}

#[test]
fn production_bundle_manifest_rejects_mixed_toolchains(
) -> Result<(), reallyme_zk_api::errors::ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let mut manifests = complete_stage_manifests(bundle_kind, credential_hash_algorithm)?;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let replacement = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        manifest_pin()?,
        ArtifactToolchain::try_from_versions("1.0.0-beta.9", "0.83.0")?,
        circuit_ref_capabilities(circuit_ref)?,
        digests(),
    )?;
    let last = manifests
        .last_mut()
        .ok_or(reallyme_zk_api::errors::ZkError::new(
            reallyme_zk_api::errors::ZkErrorReason::MissingStage,
        ))?;
    *last = replacement;

    let error = ProductionBundleManifest::try_from_stage_manifests(
        bundle_kind,
        credential_hash_algorithm,
        manifests,
    )
    .err()
    .ok_or(reallyme_zk_api::errors::ZkError::new(
        reallyme_zk_api::errors::ZkErrorReason::BackendFailure,
    ))?;

    assert_eq!(
        error.reason(),
        reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch
    );
    Ok(())
}
