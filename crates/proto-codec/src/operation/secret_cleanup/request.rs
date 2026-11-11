// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Zeroization routing for every admitted provider-operation variant.

use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::{
    zeroize_claim_proof_bundle_prove_operation_proto,
    zeroize_common_credential_root_presentation_prove_operation_proto,
    zeroize_common_credential_root_stage_prove_operation_proto,
    zeroize_common_credential_root_verify_operation_proto,
    zeroize_prepared_assemble_operation_proto, zeroize_prepared_claim_root_prove_operation_proto,
    zeroize_prepared_current_state_prove_operation_proto,
    zeroize_prepared_issuer_envelope_prove_operation_proto,
    zeroize_prepared_selected_claim_prove_operation_proto,
    zeroize_prepared_signed_validity_prove_operation_proto,
    zeroize_prepared_signing_operation_proto,
    zeroize_retained_claim_proof_bundle_prove_operation_proto, zeroize_stage_prove_operation_proto,
    zeroize_stage_witness_operation_proto, zeroize_witness_proto,
};

pub(in crate::operation) fn zeroize_operation_request_proto(
    request: &mut pb::ZkProviderOperationRequest,
) {
    use pb::zk_provider_operation_request::Operation;

    match request.operation.as_mut() {
        Some(Operation::ProveClaimProofBundle(operation)) => {
            zeroize_claim_proof_bundle_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProveRetainedClaimProofBundle(operation)) => {
            zeroize_retained_claim_proof_bundle_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProveStage(operation)) => {
            zeroize_stage_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProvePersonaCredentialEvidenceStage(operation)) => {
            if let Some(mut witness) = operation.witness.take() {
                zeroize_witness_proto(&mut witness);
            }
        }
        Some(Operation::ProvePersonaCredentialEvidenceCurrentState(operation)) => {
            zeroize_prepared_current_state_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(operation)) => {
            zeroize_prepared_issuer_envelope_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProvePersonaCredentialEvidenceClaimRoot(operation)) => {
            zeroize_prepared_claim_root_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProvePersonaCredentialEvidenceSignedValidity(operation)) => {
            zeroize_prepared_signed_validity_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProvePersonaCredentialEvidenceSelectedClaim(operation)) => {
            zeroize_prepared_selected_claim_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::PreparePersonaCredentialEvidencePresentationSigning(operation)) => {
            zeroize_prepared_signing_operation_proto(operation.as_mut());
        }
        Some(Operation::AssemblePersonaCredentialEvidencePresentation(operation)) => {
            zeroize_prepared_assemble_operation_proto(operation.as_mut());
        }
        Some(Operation::WitnessStage(operation)) => {
            zeroize_stage_witness_operation_proto(operation.as_mut());
        }
        Some(Operation::VerifyCommonCredentialRoot(operation)) => {
            zeroize_common_credential_root_verify_operation_proto(operation.as_mut());
        }
        Some(Operation::ProveCommonCredentialRootStage(operation)) => {
            zeroize_common_credential_root_stage_prove_operation_proto(operation.as_mut());
        }
        Some(Operation::ProveCommonCredentialRootPresentation(operation)) => {
            zeroize_common_credential_root_presentation_prove_operation_proto(operation.as_mut());
        }
        Some(
            Operation::VerifyClaimProofBundle(_)
            | Operation::VerifyStatusQualifiedClaimProofBundle(_)
            | Operation::VerifyStage(_)
            | Operation::VerifyPersonaCredentialEvidenceStage(_)
            | Operation::GetArtifactManifest(_)
            | Operation::ReleaseStageWitness(_),
        )
        | None => {}
    }
}
