// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::Ordering;

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRawPublicInputs,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::{ZkProofBytes, ZkProofSuite, ZkWitness},
};
use reallyme_zk_artifacts::{ArtifactKind, Digest32, VerifiedArtifactBytes};

use super::{
    binding, bundle_kind, circuit_ref, lock_process_state_test, proof, stage,
    verification_artifacts, BarretenbergVerifierCrsIdentity, ErrorTransport,
    NativeBarretenbergBackend, StaticTransport, SRS_INIT_CALL_COUNT,
};
use crate::{
    BbExactCircuitArtifacts, BbPersonaCredentialEvidenceStageProveRequest, BbStageVerifyRequest,
    LinkedBarretenbergBackend,
};

const FALSE_VERIFY_RESPONSE: &[u8] = &[
    0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f', b'y', b'R',
    b'e', b's', b'p', b'o', b'n', b's', b'e', 0x81, 0xa8, b'v', b'e', b'r', b'i', b'f', b'i', b'e',
    b'd', 0xc2,
];

/// Pinned production proof length of the SHA-256 private-claim stage.
const PRIVATE_CLAIM_PROOF_BYTES: usize = 9_536;

fn prepared_proof() -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    prepared_proof_with_len(PRIVATE_CLAIM_PROOF_BYTES)
}

fn prepared_proof_with_len(
    proof_len: usize,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let circuit_ref = ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        .source_ref(ZkCredentialHashAlgorithm::Sha256);
    let mut fields = vec![0_u8; 291 * 32];
    for (field, value) in [(0, 1), (32, 2), (64, 3), (96, 4), (128, 5), (162, 6)] {
        fields[field * 32 + 31] = value;
    }
    fields[160 * 32 + 31] = 100;
    fields[161 * 32 + 31] = 200;
    fields[194 * 32 + 31] = 1;
    fields[195 * 32 + 31] = 18;
    fields[259 * 32 + 31] = 7;
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes([11; 32]),
        ZkProofBytes::try_from_bytes(vec![42; proof_len])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(circuit_ref, fields)?,
    )
}

fn persona_credential_evidence_artifacts(
    identity: [u8; 32],
) -> Result<BbExactCircuitArtifacts, ZkError> {
    let bytecode = vec![17; 4];
    let verification_key = vec![19; 4];
    BbExactCircuitArtifacts::try_new(
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
            .source_ref(ZkCredentialHashAlgorithm::Sha256),
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(identity),
        VerifiedArtifactBytes::try_from_bytes(
            ArtifactKind::AcirBytecode,
            bytecode.clone(),
            Digest32::sha256(&bytecode),
        )?,
        VerifiedArtifactBytes::try_from_bytes(
            ArtifactKind::VerificationKey,
            verification_key.clone(),
            Digest32::sha256(&verification_key),
        )?,
    )
}

#[test]
fn prepared_prover_rejects_wrong_profile_before_backend_dispatch() -> Result<(), ZkError> {
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: FALSE_VERIFY_RESPONSE,
        required_command: b"CircuitProve",
        call_count: None,
    });
    let circuit_ref = ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        .source_ref(ZkCredentialHashAlgorithm::Sha256);
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![1])?;
    let artifacts = persona_credential_evidence_artifacts([11; 32])?;
    let reason = backend
        .prove_persona_credential_evidence_stage_exact_circuit(
            BbPersonaCredentialEvidenceStageProveRequest {
                mode: ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
                circuit_ref,
                proof_suite: ZkProofSuite::PRODUCTION,
                artifact_identity: (ZkArtifactManifestDigest::from_bytes([11; 32])).into(),
                artifacts: &artifacts,
                witness: &witness,
            },
        )
        .err()
        .map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::StageMismatch));
    Ok(())
}

#[test]
fn prepared_verifier_rejects_wrong_proof_length_before_backend_dispatch() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: FALSE_VERIFY_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: None,
    });
    for wrong_len in [
        32,
        PRIVATE_CLAIM_PROOF_BYTES - 32,
        PRIVATE_CLAIM_PROOF_BYTES + 32,
    ] {
        assert_eq!(
            backend
                .verify_persona_credential_evidence_stage_exact_circuit(
                    &prepared_proof_with_len(wrong_len)?,
                    &persona_credential_evidence_artifacts([11; 32])?
                )
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    Ok(())
}

#[test]
fn prepared_verifier_uses_linked_verify_and_pinned_artifact_identity() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: FALSE_VERIFY_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: None,
    });
    let proof = prepared_proof()?;
    assert_eq!(
        backend
            .verify_persona_credential_evidence_stage_exact_circuit(
                &proof,
                &persona_credential_evidence_artifacts([12; 32])?
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    assert_eq!(
        backend
            .verify_persona_credential_evidence_stage_exact_circuit(
                &proof,
                &persona_credential_evidence_artifacts([11; 32])?
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProof)
    );
    Ok(())
}

#[test]
fn verifier_backend_maps_structured_false_verify_to_invalid_proof() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: FALSE_VERIFY_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: None,
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    let error = backend
        .verify_stage(BbStageVerifyRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            proof: &proof,
            expected_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProof);
    Ok(())
}

#[test]
fn verifier_backend_preserves_transport_backend_failure() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(ErrorTransport {
        required_command: b"CircuitVerify",
        call_count: &SRS_INIT_CALL_COUNT,
        reason: ZkErrorReason::BackendFailure,
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    let error = backend
        .verify_stage(BbStageVerifyRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            proof: &proof,
            expected_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProof))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}
