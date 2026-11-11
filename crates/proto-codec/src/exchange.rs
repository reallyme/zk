// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical provider exchange validation shared by runtime adapters.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

use crate::operation::{decode_operation_request, ZkProviderOperation};
use crate::result::{
    decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult,
};
use reallyme_zk_artifacts::Digest32;
#[cfg(any(feature = "native", feature = "wasm"))]
use subtle::ConstantTimeEq;

#[cfg(any(feature = "native", feature = "wasm"))]
use crate::persona_credential_evidence_presentation::{
    build_persona_credential_evidence_presentation_with_signature,
    persona_credential_evidence_signing_digest, ZkPersonaCredentialEvidenceProofSetRef,
};

/// Discriminant for one validated canonical provider operation.
///
/// This closed enum is derived from the canonical protobuf oneof after strict
/// domain conversion. Runtime adapters use it only to correlate a provider's
/// success result with its request; it is not a second operation registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProviderOperationKind {
    /// Complete four-stage proof generation.
    ProveClaimProofBundle,
    /// Complete four-stage proof generation from native-retained witnesses.
    ProveRetainedClaimProofBundle,
    /// Complete four-stage proof verification.
    VerifyClaimProofBundle,
    /// Five-proof verification against the current issuer status list.
    VerifyStatusQualifiedClaimProofBundle,
    /// One exact-stage proof generation.
    ProveStage,
    /// One exact-stage proof verification.
    VerifyStage,
    /// Exact artifact-manifest lookup.
    GetArtifactManifest,
    /// Native-owned exact-stage witness generation.
    WitnessStage,
    /// Native-owned exact-stage witness release.
    ReleaseStageWitness,
    /// Complete nine-proof common-credential-root verification.
    VerifyCommonCredentialRoot,
    /// One common-credential-root source-stage proof generation.
    ProveCommonCredentialRootStage,
    /// Complete nine-proof common-credential-root presentation generation.
    ProveCommonCredentialRootPresentation,
    /// One exact prepared proof verification; not presentation acceptance.
    VerifyPersonaCredentialEvidenceStage,
    /// One exact prepared source-stage proof generation.
    ProvePersonaCredentialEvidenceStage,
    /// Typed prepared current-status proof generation.
    ProvePersonaCredentialEvidenceCurrentState,
    /// Typed issuer-envelope prepared proof generation.
    ProvePersonaCredentialEvidenceIssuerEnvelope,
    /// Typed issuer-signed claim-root prepared proof generation.
    ProvePersonaCredentialEvidenceClaimRoot,
    /// Typed issuer-signed validity and status-pointer proof generation.
    ProvePersonaCredentialEvidenceSignedValidity,
    /// Typed selected-claim and persona-authorization proof generation.
    ProvePersonaCredentialEvidenceSelectedClaim,
    /// Canonical digest for a protected platform key.
    PreparePersonaCredentialEvidencePresentationSigning,
    /// Complete holder-signed prepared transport package.
    AssemblePersonaCredentialEvidencePresentation,
}

/// Strictly decodes a request and returns only its validated operation kind.
///
/// Proving requests are fully decoded so witness encoding, size, circuit, and
/// binding checks run before any provider callback. The secret-bearing domain
/// operation is dropped—and therefore zeroized—before this function returns.
pub fn decode_operation_request_kind(
    request_bytes: &[u8],
) -> Result<ZkProviderOperationKind, ZkError> {
    let operation = decode_operation_request(request_bytes)?;
    Ok(operation_kind(&operation))
}

/// Strictly validates one complete canonical provider exchange.
pub fn validate_operation_exchange(
    request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<(), ZkError> {
    let request = decode_operation_request(request_bytes)?;
    let response = decode_operation_response(response_bytes)?;
    if response.request_sha256() != Digest32::sha256(request_bytes) {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    match response.into_outcome() {
        ZkProviderOperationOutcome::Failure(_) => Ok(()),
        ZkProviderOperationOutcome::Success(result)
            if result_matches_request(&request, result.as_ref())? =>
        {
            Ok(())
        }
        ZkProviderOperationOutcome::Success(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

fn result_matches_request(
    request: &ZkProviderOperation,
    result: &ZkProviderOperationResult,
) -> Result<bool, ZkError> {
    let matches = match (request, result) {
        (
            ZkProviderOperation::ProveClaimProofBundle {
                bundle_kind: profile,
                credential_hash_algorithm,
                proof_suite,
                session_binding,
                ..
            }
            | ZkProviderOperation::ProveRetainedClaimProofBundle {
                bundle_kind: profile,
                credential_hash_algorithm,
                proof_suite,
                session_binding,
                ..
            },
            ZkProviderOperationResult::ClaimProofBundle(bundle),
        ) => {
            let hash_matches = bundle.stage_proofs().iter().all(|stage| {
                stage.proof().circuit_ref().credential_hash_algorithm == *credential_hash_algorithm
            });
            bundle.bundle_kind() == *profile
                && bundle.proof_suite() == *proof_suite
                && bundle.session_binding() == *session_binding
                && hash_matches
        }
        (
            ZkProviderOperation::VerifyClaimProofBundle {
                claim_proof_bundle, ..
            },
            ZkProviderOperationResult::ClaimProofBundleVerification(verification),
        ) => {
            verification.bundle_kind == claim_proof_bundle.bundle_kind()
                && verification.proof_suite == claim_proof_bundle.proof_suite()
                && verification.statement == claim_proof_bundle.decode_claimed_statement()?
        }
        (
            ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle {
                status_qualified_claim_proof_bundle,
                current_issuer_status,
                ..
            },
            ZkProviderOperationResult::StatusQualifiedClaimProofBundleVerification(verification),
        ) => {
            let claim_proof_bundle = status_qualified_claim_proof_bundle.claim_proof_bundle();
            verification.bundle_kind == claim_proof_bundle.bundle_kind()
                && verification.proof_suite == claim_proof_bundle.proof_suite()
                && verification.status_purpose == current_issuer_status.purpose
                && verification.statement == claim_proof_bundle.decode_claimed_statement()?
                && verification.session_link_commitment
                    == claim_proof_bundle.session_link_commitment()?
        }
        (
            ZkProviderOperation::ProveStage {
                circuit_ref,
                proof_suite,
                public_inputs,
                ..
            },
            ZkProviderOperationResult::StageProof(proof),
        ) => {
            proof.circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
                && proof.public_inputs() == public_inputs
        }
        (
            ZkProviderOperation::VerifyStage { proof, .. },
            ZkProviderOperationResult::StageVerification(verification),
        ) => {
            verification.circuit_ref == Some(proof.circuit_ref())
                && verification.proof_suite == proof.proof_suite()
        }
        (
            ZkProviderOperation::GetArtifactManifest {
                circuit_ref,
                proof_suite,
            },
            ZkProviderOperationResult::ArtifactManifest(manifest),
        ) => manifest.circuit_ref() == *circuit_ref && manifest.proof_suite() == *proof_suite,
        (
            ZkProviderOperation::WitnessStage {
                circuit_ref, input, ..
            },
            ZkProviderOperationResult::StageWitness(witness),
        ) => {
            let expected_binding = input.expected_session_binding()?;
            expected_binding.validate_for_circuit(*circuit_ref)?;
            witness.witness_handle.circuit_ref == *circuit_ref
                && witness.session_binding == expected_binding
        }
        (
            ZkProviderOperation::ReleaseStageWitness { witness_handle },
            ZkProviderOperationResult::StageWitnessRelease(release),
        ) => release.circuit_ref == witness_handle.circuit_ref,
        (
            ZkProviderOperation::VerifyCommonCredentialRoot {
                presentation,
                expected_proof_suite,
                ..
            },
            ZkProviderOperationResult::CommonCredentialRootVerification(verification),
        ) => {
            verification.persona_mode == presentation.persona_mode()
                && verification.proof_suite == *expected_proof_suite
                && usize::from(verification.verified_proof_count)
                    == reallyme_zk_api::common_root::COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT
        }
        (
            ZkProviderOperation::ProveCommonCredentialRootStage {
                plan, proof_suite, ..
            },
            ZkProviderOperationResult::CommonCredentialRootStageProof(proof),
        ) => {
            proof.persona_mode() == plan.persona_mode()
                && proof.slot() == plan.slot()
                && proof.proof_suite() == *proof_suite
                && proof.public_inputs().circuit_ref() == plan.circuit_ref()
        }
        (
            ZkProviderOperation::ProveCommonCredentialRootPresentation {
                persona_mode: profile,
                credential_hash_algorithm,
                proof_suite,
                expected_binding,
                stages,
            },
            ZkProviderOperationResult::CommonCredentialRootPresentation(presentation),
        ) => {
            presentation.persona_mode() == *profile
                && presentation.credential_hash_algorithm() == *credential_hash_algorithm
                && presentation.proof_suite() == *proof_suite
                && presentation.session_binding() == *expected_binding
                && presentation.proofs().len() == stages.len()
                && presentation
                    .proofs()
                    .iter()
                    .zip(stages.iter())
                    .all(|(proof, stage)| {
                        proof.persona_mode() == stage.plan.persona_mode()
                            && proof.slot() == stage.plan.slot()
                            && proof.proof_suite() == stage.proof_suite
                            && proof.public_inputs().circuit_ref() == stage.plan.circuit_ref()
                    })
        }
        (
            ZkProviderOperation::VerifyPersonaCredentialEvidenceStage { proof },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageVerification(verification),
        ) => {
            verification.mode == proof.mode()
                && verification.stage == proof.public_inputs().stage()
                && verification.circuit_ref == proof.public_inputs().circuit_ref()
                && verification.proof_suite == proof.proof_suite()
        }
        (
            ZkProviderOperation::ProvePersonaCredentialEvidenceStage {
                mode: profile,
                circuit_ref,
                proof_suite,
                ..
            },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof),
        ) => {
            proof.mode() == *profile
                && proof.public_inputs().circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
        }
        (
            ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState {
                mode: profile,
                circuit_ref,
                proof_suite,
                ..
            },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof),
        ) => {
            proof.mode() == *profile
                && proof.public_inputs().circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
        }
        (
            ZkProviderOperation::ProvePersonaCredentialEvidenceIssuerEnvelope {
                mode: profile,
                circuit_ref,
                proof_suite,
                input,
            },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof),
        ) => {
            proof.mode() == *profile
                && proof.public_inputs().circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
                && input.matches_proof(proof)?
        }
        (
            ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot {
                mode: profile,
                circuit_ref,
                proof_suite,
                input,
            },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof),
        ) => {
            proof.mode() == *profile
                && proof.public_inputs().circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
                && input.matches_proof(proof)?
        }
        (
            ZkProviderOperation::ProvePersonaCredentialEvidenceSignedValidity {
                mode: profile,
                circuit_ref,
                proof_suite,
                input,
            },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof),
        ) => {
            proof.mode() == *profile
                && proof.public_inputs().circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
                && input.matches_proof(proof)?
        }
        (
            ZkProviderOperation::ProvePersonaCredentialEvidenceSelectedClaim {
                mode: profile,
                circuit_ref,
                proof_suite,
                input,
            },
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof),
        ) => {
            proof.mode() == *profile
                && proof.public_inputs().circuit_ref() == *circuit_ref
                && proof.proof_suite() == *proof_suite
                && input.matches_proof(proof)?
        }
        #[cfg(any(feature = "native", feature = "wasm"))]
        (
            ZkProviderOperation::PreparePersonaCredentialEvidencePresentationSigning { input },
            ZkProviderOperationResult::PersonaCredentialEvidencePresentationSigningChallenge(
                digest,
            ),
        ) => {
            let expected = persona_credential_evidence_signing_digest(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: input.evidence.issuer_envelope(),
                    claim_root: input.evidence.claim_root(),
                    signed_validity: input.evidence.signed_validity(),
                    selected_claim: input.evidence.selected_claim(),
                },
                &input.current_state,
                &input.request,
                input.now_unix,
            )
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
            bool::from(expected.ct_eq(digest.as_ref()))
        }
        #[cfg(any(feature = "native", feature = "wasm"))]
        (
            ZkProviderOperation::AssemblePersonaCredentialEvidencePresentation { input, signature },
            ZkProviderOperationResult::PersonaCredentialEvidencePresentation(presentation),
        ) => {
            let expected = build_persona_credential_evidence_presentation_with_signature(
                ZkPersonaCredentialEvidenceProofSetRef {
                    issuer_envelope: input.evidence.issuer_envelope(),
                    claim_root: input.evidence.claim_root(),
                    signed_validity: input.evidence.signed_validity(),
                    selected_claim: input.evidence.selected_claim(),
                },
                &input.current_state,
                &input.request,
                input.now_unix,
                **signature,
            )
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
            bool::from(expected.as_slice().ct_eq(presentation.as_slice()))
        }
        _ => false,
    };
    Ok(matches)
}

fn operation_kind(operation: &ZkProviderOperation) -> ZkProviderOperationKind {
    match operation {
        ZkProviderOperation::ProveClaimProofBundle { .. } => {
            ZkProviderOperationKind::ProveClaimProofBundle
        }
        ZkProviderOperation::ProveRetainedClaimProofBundle { .. } => {
            ZkProviderOperationKind::ProveRetainedClaimProofBundle
        }
        ZkProviderOperation::VerifyClaimProofBundle { .. } => {
            ZkProviderOperationKind::VerifyClaimProofBundle
        }
        ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle { .. } => {
            ZkProviderOperationKind::VerifyStatusQualifiedClaimProofBundle
        }
        ZkProviderOperation::ProveStage { .. } => ZkProviderOperationKind::ProveStage,
        ZkProviderOperation::VerifyStage { .. } => ZkProviderOperationKind::VerifyStage,
        ZkProviderOperation::GetArtifactManifest { .. } => {
            ZkProviderOperationKind::GetArtifactManifest
        }
        ZkProviderOperation::WitnessStage { .. } => ZkProviderOperationKind::WitnessStage,
        ZkProviderOperation::ReleaseStageWitness { .. } => {
            ZkProviderOperationKind::ReleaseStageWitness
        }
        ZkProviderOperation::VerifyCommonCredentialRoot { .. } => {
            ZkProviderOperationKind::VerifyCommonCredentialRoot
        }
        ZkProviderOperation::ProveCommonCredentialRootStage { .. } => {
            ZkProviderOperationKind::ProveCommonCredentialRootStage
        }
        ZkProviderOperation::ProveCommonCredentialRootPresentation { .. } => {
            ZkProviderOperationKind::ProveCommonCredentialRootPresentation
        }
        ZkProviderOperation::VerifyPersonaCredentialEvidenceStage { .. } => {
            ZkProviderOperationKind::VerifyPersonaCredentialEvidenceStage
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceStage { .. } => {
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceStage
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState { .. } => {
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceCurrentState
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceIssuerEnvelope { .. } => {
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceIssuerEnvelope
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot { .. } => {
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceClaimRoot
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceSignedValidity { .. } => {
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceSignedValidity
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceSelectedClaim { .. } => {
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceSelectedClaim
        }
        ZkProviderOperation::PreparePersonaCredentialEvidencePresentationSigning { .. } => {
            ZkProviderOperationKind::PreparePersonaCredentialEvidencePresentationSigning
        }
        ZkProviderOperation::AssemblePersonaCredentialEvidencePresentation { .. } => {
            ZkProviderOperationKind::AssemblePersonaCredentialEvidencePresentation
        }
    }
}
