// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    exact_source_artifact_identity, ArtifactToolchain, ArtifactVersion, Digest32,
};
use reallyme_zk_proto_codec::release::{
    decode_release_index, encode_release_index, ReleaseArtifactPin,
    ReleaseCommonCredentialRootArtifactPin, ReleaseIndex,
    ReleasePersonaCredentialEvidenceArtifactPin, ReleaseVerificationVectorPin,
    MAX_RELEASE_VERIFICATION_VECTORS, RELEASE_ARTIFACT_MANIFEST_COUNT,
    RELEASE_VERIFICATION_VECTOR_SET_COUNT,
};

fn artifact_pins() -> Result<Vec<ReleaseArtifactPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_ARTIFACT_MANIFEST_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
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

fn common_credential_root_pins() -> Result<Vec<ReleaseCommonCredentialRootArtifactPin>, ZkError> {
    let stages = [
        ZkCircuitStage::RootAttestation,
        ZkCircuitStage::RootStatus,
        ZkCircuitStage::Lineage,
        ZkCircuitStage::IssuerCredentialStatus,
        ZkCircuitStage::PrivatePersonaClaim,
        ZkCircuitStage::PublicPersonaClaim,
        ZkCircuitStage::PublicSession,
    ];
    let mut pins = Vec::new();
    let mut marker = 1_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for stage in stages {
            let circuit_ref = ZkCircuitRef::new(
                *credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                stage,
            );
            let source_closure = Digest32::from_bytes([marker; 32]);
            let bytecode = Digest32::from_bytes(
                [marker
                    .checked_add(10)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?; 32],
            );
            let key = Digest32::from_bytes(
                [marker
                    .checked_add(20)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?; 32],
            );
            pins.push(ReleaseCommonCredentialRootArtifactPin::try_new(
                circuit_ref,
                Digest32::from_bytes([99; 32]),
                source_closure,
                bytecode,
                key,
                exact_source_artifact_identity(circuit_ref, source_closure, bytecode, key)?,
            )?);
            marker = marker
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(pins)
}

fn persona_credential_evidence_pins(
) -> Result<Vec<ReleasePersonaCredentialEvidenceArtifactPin>, ZkError> {
    let stages = [
        ZkCircuitStage::EvidenceIssuerEnvelope,
        ZkCircuitStage::EvidenceClaimRoot,
        ZkCircuitStage::EvidenceSignedValidity,
        ZkCircuitStage::EvidencePublicClaim,
        ZkCircuitStage::EvidencePrivateClaim,
        ZkCircuitStage::EvidenceCurrentState,
    ];
    let mut pins = Vec::new();
    let mut marker = 30_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for stage in stages {
            let circuit_ref = ZkCircuitRef::new(
                *credential_hash_algorithm,
                ZkCircuitFamily::PersonaCredentialEvidenceV1,
                stage,
            );
            let source_closure = Digest32::from_bytes([marker; 32]);
            let bytecode = Digest32::from_bytes([marker + 10; 32]);
            let key = Digest32::from_bytes([marker + 20; 32]);
            pins.push(ReleasePersonaCredentialEvidenceArtifactPin::try_new(
                circuit_ref,
                Digest32::from_bytes([99; 32]),
                source_closure,
                bytecode,
                key,
                exact_source_artifact_identity(circuit_ref, source_closure, bytecode, key)?,
            )?);
            marker = marker
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(pins)
}

#[test]
fn persona_credential_evidence_release_pins_reject_invalid_sets() -> Result<(), ZkError> {
    let base = valid_index()?;
    let pins = persona_credential_evidence_pins()?;
    let build = |persona_credential_evidence| {
        ReleaseIndex::try_new_with_exact_sources(
            base.release_version(),
            base.toolchain(),
            base.proof_suite(),
            base.capability_registry_sha256(),
            base.artifact_manifests().to_vec(),
            base.verification_vectors().to_vec(),
            Vec::new(),
            persona_credential_evidence,
        )
    };
    let index = build(pins.clone())?;
    assert_eq!(decode_release_index(&encode_release_index(&index)?)?, index);
    assert_eq!(index.persona_credential_evidence_artifacts().len(), 12);
    let partial_len = pins
        .len()
        .checked_sub(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut reordered = pins.clone();
    reordered.swap(0, 1);
    for invalid in [pins[..partial_len].to_vec(), reordered] {
        assert_eq!(
            build(invalid).err().map(|error| error.reason()),
            Some(ZkErrorReason::ArtifactMismatch)
        );
    }
    let first = pins
        .first()
        .copied()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    assert_eq!(
        ReleasePersonaCredentialEvidenceArtifactPin::try_new(
            first.circuit_ref(),
            first.source_lock_sha256(),
            first.source_closure_sha256(),
            first.bytecode_sha256(),
            first.verification_key_sha256(),
            reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
                *(ZkArtifactManifestDigest::from_bytes([7; 32])).as_bytes()
            ),
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    Ok(())
}

#[test]
fn exact_source_families_require_one_reviewed_source_lock() -> Result<(), ZkError> {
    let base = valid_index()?;
    let common = common_credential_root_pins()?;
    let persona_credential_evidence = persona_credential_evidence_pins()?;
    let accepted = ReleaseIndex::try_new_with_exact_sources(
        base.release_version(),
        base.toolchain(),
        base.proof_suite(),
        base.capability_registry_sha256(),
        base.artifact_manifests().to_vec(),
        base.verification_vectors().to_vec(),
        common.clone(),
        persona_credential_evidence.clone(),
    )?;
    assert_eq!(accepted.persona_credential_evidence_artifacts().len(), 12);
    let mut wrong_lock = Vec::new();
    for pin in persona_credential_evidence {
        wrong_lock.push(ReleasePersonaCredentialEvidenceArtifactPin::try_new(
            pin.circuit_ref(),
            Digest32::from_bytes([98; 32]),
            pin.source_closure_sha256(),
            pin.bytecode_sha256(),
            pin.verification_key_sha256(),
            pin.artifact_identity_sha256(),
        )?);
    }
    let reason = ReleaseIndex::try_new_with_exact_sources(
        base.release_version(),
        base.toolchain(),
        base.proof_suite(),
        base.capability_registry_sha256(),
        base.artifact_manifests().to_vec(),
        base.verification_vectors().to_vec(),
        common,
        wrong_lock,
    )
    .err()
    .map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    Ok(())
}

#[test]
fn common_credential_root_release_pins_round_trip_and_reject_partial_or_reordered_sets(
) -> Result<(), ZkError> {
    let legacy = valid_index()?;
    let pins = common_credential_root_pins()?;
    let index = ReleaseIndex::try_new_with_common_credential_root(
        legacy.release_version(),
        legacy.toolchain(),
        legacy.proof_suite(),
        legacy.capability_registry_sha256(),
        legacy.artifact_manifests().to_vec(),
        legacy.verification_vectors().to_vec(),
        pins.clone(),
    )?;
    assert_eq!(decode_release_index(&encode_release_index(&index)?)?, index);
    let partial_len = pins
        .len()
        .checked_sub(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    for mut invalid in [pins[..partial_len].to_vec(), pins] {
        if invalid.len() == partial_len + 1 {
            invalid.swap(0, 1);
        }
        let reason = ReleaseIndex::try_new_with_common_credential_root(
            legacy.release_version(),
            legacy.toolchain(),
            legacy.proof_suite(),
            legacy.capability_registry_sha256(),
            legacy.artifact_manifests().to_vec(),
            legacy.verification_vectors().to_vec(),
            invalid,
        )
        .err()
        .map(|error| error.reason());
        assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}

#[test]
fn common_credential_root_pin_rejects_stale_proof_identity() -> Result<(), ZkError> {
    let pin = common_credential_root_pins()?
        .first()
        .copied()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let reason = ReleaseCommonCredentialRootArtifactPin::try_new(
        pin.circuit_ref(),
        pin.source_lock_sha256(),
        pin.source_closure_sha256(),
        pin.bytecode_sha256(),
        pin.verification_key_sha256(),
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([7; 32])).as_bytes(),
        ),
    )
    .err()
    .map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    Ok(())
}

fn vector_pins() -> Result<Vec<ReleaseVerificationVectorPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_VERIFICATION_VECTOR_SET_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
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

fn valid_index() -> Result<ReleaseIndex, ZkError> {
    ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        ZkProofSuite::PRODUCTION,
        Digest32::from_bytes([91; 32]),
        artifact_pins()?,
        vector_pins()?,
    )
}

#[test]
fn canonical_release_index_round_trips_exact_matrix() -> Result<(), ZkError> {
    let index = valid_index()?;
    let encoded = encode_release_index(&index)?;
    let decoded = decode_release_index(&encoded)?;

    assert_eq!(decoded, index);
    assert_eq!(
        decoded.artifact_manifests().len(),
        RELEASE_ARTIFACT_MANIFEST_COUNT
    );
    assert_eq!(
        decoded.verification_vectors().len(),
        RELEASE_VERIFICATION_VECTOR_SET_COUNT
    );
    Ok(())
}

#[test]
fn release_index_rejects_noncanonical_manifest_order() -> Result<(), ZkError> {
    let mut artifacts = artifact_pins()?;
    artifacts.swap(0, 1);
    let reason = ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        ZkProofSuite::PRODUCTION,
        Digest32::from_bytes([91; 32]),
        artifacts,
        vector_pins()?,
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    Ok(())
}

#[test]
fn release_index_rejects_reused_manifest_identity() -> Result<(), ZkError> {
    let mut artifacts = Vec::new();
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                artifacts.push(ReleaseArtifactPin::try_new(
                    *bundle_kind,
                    *stage,
                    bundle_kind.source_ref(*credential_hash_algorithm, *stage),
                    ZkArtifactManifestDigest::from_bytes([1; 32]),
                )?);
            }
        }
    }
    let reason = ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        ZkProofSuite::PRODUCTION,
        Digest32::from_bytes([91; 32]),
        artifacts,
        vector_pins()?,
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    Ok(())
}

#[test]
fn release_vector_pin_rejects_empty_and_excess_counts() {
    for count in [0, MAX_RELEASE_VERIFICATION_VECTORS + 1] {
        let reason = ReleaseVerificationVectorPin::try_new(
            ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            ZkCredentialHashAlgorithm::Sha256,
            ZkProofSuite::PRODUCTION,
            Digest32::from_bytes([1; 32]),
            count,
        )
        .err()
        .map(|error| error.reason());
        assert_eq!(reason, Some(ZkErrorReason::ArtifactMismatch));
    }
}

#[test]
fn duplicate_release_index_wire_field_is_rejected() -> Result<(), ZkError> {
    let mut encoded = encode_release_index(&valid_index()?)?;
    encoded.extend_from_slice(&[0x08, 0x01]);
    let reason = decode_release_index(&encoded)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ZkErrorReason::MalformedProtobuf));
    Ok(())
}
