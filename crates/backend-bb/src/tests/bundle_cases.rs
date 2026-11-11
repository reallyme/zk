// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkClaimProofBundle, ZkClaimProofBundleKind,
        ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver, ZkClaimProofBundleStage,
        ZkPresentationBoundClaimBundleVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};

use super::{
    binding, bundle_with_hashes, claim_proof_bundle_witness, manifest_digest, provider,
    stage_proof_with_manifest_digest, transaction_binding, trusted_issuer,
};

#[test]
fn prove_claim_proof_bundle_emits_all_stage_refs() -> Result<(), ZkError> {
    let provider = provider();
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Poseidon2;
    let witness_bundle = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;
    let request = ZkClaimProofBundleProveRequest::try_new(
        bundle_kind,
        credential_hash_algorithm,
        ZkProofSuite::PRODUCTION,
        &witness_bundle,
        binding(1),
    )?;

    let bundle = provider.prove_claim_proof_bundle(request)?;

    assert_eq!(bundle.bundle_kind(), bundle_kind);
    assert_eq!(
        bundle.stage_proofs().len(),
        ZkClaimProofBundleStage::ALL.len()
    );
    for stage_proof in bundle.stage_proofs() {
        assert_eq!(
            stage_proof.proof().circuit_ref(),
            bundle_kind.source_ref(ZkCredentialHashAlgorithm::Poseidon2, stage_proof.stage())
        );
    }
    Ok(())
}

#[test]
fn verify_claim_proof_bundle_accepts_exact_consistent_hash_lane() -> Result<(), ZkError> {
    let provider = provider();
    let bundle = bundle_with_hashes(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        &[
            Some(ZkCredentialHashAlgorithm::Sha256),
            Some(ZkCredentialHashAlgorithm::Sha256),
            Some(ZkCredentialHashAlgorithm::Sha256),
            Some(ZkCredentialHashAlgorithm::Sha256),
        ],
    )?;

    let verification = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &bundle,
            ZkProofSuite::PRODUCTION,
            binding(7),
            &[trusted_issuer()],
            41,
        )?,
    )?;

    assert_eq!(
        verification.bundle_kind(),
        ZkClaimProofBundleKind::CredentialSubjectClaimV1
    );
    assert_eq!(verification.proof_suite(), ZkProofSuite::PRODUCTION);
    assert_eq!(
        verification.verified_stage_count(),
        u8::try_from(ZkClaimProofBundleStage::ALL.len())
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
    );
    // This result carries presentation evidence only; compile-fail API tests
    // enforce that neither it nor its statement can enter credential acceptance.
    let _: &reallyme_zk_api::claim_bundle::ZkPresentationBoundClaimStatement =
        verification.statement();
    Ok(())
}

#[test]
fn verify_claim_proof_bundle_rejects_proof_manifest_digest_mismatch() -> Result<(), ZkError> {
    let provider = provider();
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut proofs = Vec::with_capacity(ZkClaimProofBundleStage::ALL.len());
    for stage in ZkClaimProofBundleStage::ALL {
        let digest = if *stage == ZkClaimProofBundleStage::Claim {
            ZkArtifactManifestDigest::from_bytes([9_u8; 32])
        } else {
            manifest_digest()
        };
        proofs.push(stage_proof_with_manifest_digest(
            bundle_kind,
            Some(ZkCredentialHashAlgorithm::Sha256),
            *stage,
            digest,
        )?);
    }
    let bundle = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(7), proofs)?;

    let error = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &bundle,
            ZkProofSuite::PRODUCTION,
            binding(7),
            &[trusted_issuer()],
            41,
        )?,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn verify_claim_proof_bundle_rejects_session_binding_mismatch() -> Result<(), ZkError> {
    let bundle = bundle_with_hashes(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        &[
            Some(ZkCredentialHashAlgorithm::Poseidon2),
            Some(ZkCredentialHashAlgorithm::Poseidon2),
            Some(ZkCredentialHashAlgorithm::Poseidon2),
            Some(ZkCredentialHashAlgorithm::Poseidon2),
        ],
    )?;

    let err = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        ZkProofSuite::PRODUCTION,
        binding(9),
        &[trusted_issuer()],
        41,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn bundle_rejects_missing_exact_refs() -> Result<(), ZkError> {
    let err = bundle_with_hashes(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        &[None, None, None, None],
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prove_claim_proof_bundle_accepts_transaction_bound_session() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let witness_bundle = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;
    let session_binding = transaction_binding(1);
    let bundle = provider().prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
        bundle_kind,
        credential_hash_algorithm,
        ZkProofSuite::PRODUCTION,
        &witness_bundle,
        session_binding,
    )?)?;

    assert_eq!(bundle.session_binding(), session_binding);
    for stage_proof in bundle.stage_proofs() {
        session_binding.decode_and_validate(
            stage_proof.proof().circuit_ref(),
            stage_proof.proof().public_inputs(),
        )?;
    }
    Ok(())
}

#[test]
fn bundle_construction_rejects_mixed_hash_lanes() -> Result<(), ZkError> {
    let err = bundle_with_hashes(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        &[
            Some(ZkCredentialHashAlgorithm::Sha256),
            Some(ZkCredentialHashAlgorithm::Sha256),
            Some(ZkCredentialHashAlgorithm::Sha256),
            Some(ZkCredentialHashAlgorithm::Poseidon2),
        ],
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}
