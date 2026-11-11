// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceStageProof},
    proofs::{ZkProofSuite, ZkWitness},
};
use reallyme_zk_backend_bb::BarretenbergPersonaCredentialEvidenceArtifactResolver;
use reallyme_zk_backend_bb::BbPersonaCredentialEvidenceStageProveRequest;
use reallyme_zk_proto_codec::operation::ZkPersonaCredentialEvidencePresentationInput;
use reallyme_zk_proto_codec::operation::{
    ZkPersonaCredentialEvidenceClaimRootProveRequest,
    ZkPersonaCredentialEvidenceCurrentStateProveRequest,
    ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
    ZkPersonaCredentialEvidenceSelectedClaimProveRequest,
    ZkPersonaCredentialEvidenceSignedValidityProveRequest,
};
use reallyme_zk_proto_codec::persona_credential_evidence_presentation::{
    build_persona_credential_evidence_presentation_with_signature,
    persona_credential_evidence_signing_digest, ZkPersonaCredentialEvidencePresentationReason,
    ZkPersonaCredentialEvidenceProofSetRef,
};
use reallyme_zk_proto_codec::result::{
    encode_persona_credential_evidence_presentation_response,
    encode_persona_credential_evidence_presentation_signing_challenge_response,
    encode_persona_credential_evidence_stage_proof_response,
    encode_persona_credential_evidence_stage_verification_response,
};
use zeroize::Zeroizing;

use crate::context::{PlatformContext, PlatformCrsMode};
use crate::witness::{
    generate_persona_credential_evidence_claim_root_witness,
    generate_persona_credential_evidence_current_state_witness,
    generate_persona_credential_evidence_issuer_envelope_witness,
    generate_persona_credential_evidence_selected_claim_witness,
    generate_persona_credential_evidence_signed_validity_witness,
};

pub(super) fn prove_persona_credential_evidence_selected_claim(
    context: &PlatformContext,
    request_bytes: &[u8],
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: &ZkPersonaCredentialEvidenceSelectedClaimProveRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let artifacts =
        context.resolve_persona_credential_evidence_artifacts(circuit_ref, proof_suite)?;
    let witness = generate_persona_credential_evidence_selected_claim_witness(
        circuit_ref,
        &artifacts,
        mode,
        input,
    )?;
    prove_persona_credential_evidence_stage(
        context,
        request_bytes,
        mode,
        circuit_ref,
        proof_suite,
        &witness,
    )
}

pub(super) fn prove_persona_credential_evidence_claim_root(
    context: &PlatformContext,
    request_bytes: &[u8],
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: &ZkPersonaCredentialEvidenceClaimRootProveRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let artifacts =
        context.resolve_persona_credential_evidence_artifacts(circuit_ref, proof_suite)?;
    let witness =
        generate_persona_credential_evidence_claim_root_witness(circuit_ref, &artifacts, input)?;
    prove_persona_credential_evidence_stage(
        context,
        request_bytes,
        mode,
        circuit_ref,
        proof_suite,
        &witness,
    )
}

pub(super) fn prove_persona_credential_evidence_signed_validity(
    context: &PlatformContext,
    request_bytes: &[u8],
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: &ZkPersonaCredentialEvidenceSignedValidityProveRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let artifacts =
        context.resolve_persona_credential_evidence_artifacts(circuit_ref, proof_suite)?;
    let witness = generate_persona_credential_evidence_signed_validity_witness(
        circuit_ref,
        &artifacts,
        input,
    )?;
    prove_persona_credential_evidence_stage(
        context,
        request_bytes,
        mode,
        circuit_ref,
        proof_suite,
        &witness,
    )
}

fn presentation_evidence(
    input: &ZkPersonaCredentialEvidencePresentationInput,
) -> ZkPersonaCredentialEvidenceProofSetRef<'_> {
    ZkPersonaCredentialEvidenceProofSetRef {
        issuer_envelope: input.evidence.issuer_envelope(),
        claim_root: input.evidence.claim_root(),
        signed_validity: input.evidence.signed_validity(),
        selected_claim: input.evidence.selected_claim(),
    }
}

fn presentation_error(reason: ZkPersonaCredentialEvidencePresentationReason) -> ZkError {
    let mapped = match reason {
        ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding => {
            ZkErrorReason::MalformedProtobuf
        }
        ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch
        | ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected
        | ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed => {
            ZkErrorReason::BindingMismatch
        }
        ZkPersonaCredentialEvidencePresentationReason::RequestRejected => {
            ZkErrorReason::PresentationExpired
        }
        ZkPersonaCredentialEvidencePresentationReason::HolderSigningFailed
        | ZkPersonaCredentialEvidencePresentationReason::ReplayStoreUnavailable => {
            ZkErrorReason::BackendUnavailable
        }
        ZkPersonaCredentialEvidencePresentationReason::NonceReplay => {
            ZkErrorReason::BindingMismatch
        }
    };
    ZkError::new(mapped)
}

pub(super) fn prepare_persona_credential_evidence_presentation_signing(
    request_bytes: &[u8],
    input: &ZkPersonaCredentialEvidencePresentationInput,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let digest = persona_credential_evidence_signing_digest(
        presentation_evidence(input),
        &input.current_state,
        &input.request,
        input.now_unix,
    )
    .map_err(|error| presentation_error(error.reason()))?;
    encode_persona_credential_evidence_presentation_signing_challenge_response(
        request_bytes,
        digest,
    )
}

pub(super) fn assemble_persona_credential_evidence_presentation(
    request_bytes: &[u8],
    input: &ZkPersonaCredentialEvidencePresentationInput,
    signature: &[u8; 64],
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let presentation = build_persona_credential_evidence_presentation_with_signature(
        presentation_evidence(input),
        &input.current_state,
        &input.request,
        input.now_unix,
        *signature,
    )
    .map_err(|error| presentation_error(error.reason()))?;
    encode_persona_credential_evidence_presentation_response(request_bytes, &presentation)
}

pub(super) fn prove_persona_credential_evidence_current_state(
    context: &PlatformContext,
    request_bytes: &[u8],
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: &ZkPersonaCredentialEvidenceCurrentStateProveRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if input.evidence.mode() != mode {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let artifacts =
        context.resolve_persona_credential_evidence_artifacts(circuit_ref, proof_suite)?;
    let witness = generate_persona_credential_evidence_current_state_witness(
        circuit_ref,
        proof_suite,
        &artifacts,
        input,
    )?;
    prove_persona_credential_evidence_stage(
        context,
        request_bytes,
        mode,
        circuit_ref,
        proof_suite,
        &witness,
    )
}

pub(super) fn prove_persona_credential_evidence_issuer_envelope(
    context: &PlatformContext,
    request_bytes: &[u8],
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: &ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let artifacts =
        context.resolve_persona_credential_evidence_artifacts(circuit_ref, proof_suite)?;
    let witness = generate_persona_credential_evidence_issuer_envelope_witness(
        circuit_ref,
        &artifacts,
        input,
    )?;
    prove_persona_credential_evidence_stage(
        context,
        request_bytes,
        mode,
        circuit_ref,
        proof_suite,
        &witness,
    )
}

pub(super) fn prove_persona_credential_evidence_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    witness: &ZkWitness,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    proof_suite.require_production()?;
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let artifacts =
        context.resolve_persona_credential_evidence_artifacts(circuit_ref, proof_suite)?;
    let proof = context
        .backend()
        .prove_persona_credential_evidence_stage_exact_circuit(
            BbPersonaCredentialEvidenceStageProveRequest {
                mode,
                circuit_ref,
                proof_suite,
                artifact_identity: artifacts.artifact_identity(),
                artifacts: &artifacts,
                witness,
            },
        )?;
    encode_persona_credential_evidence_stage_proof_response(request_bytes, &proof)
}

pub(super) fn verify_persona_credential_evidence_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    proof: &ZkPersonaCredentialEvidenceStageProof,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let artifacts = context.resolve_persona_credential_evidence_artifacts(
        proof.public_inputs().circuit_ref(),
        proof.proof_suite(),
    )?;
    context
        .backend()
        .verify_persona_credential_evidence_stage_exact_circuit(proof, &artifacts)?;
    encode_persona_credential_evidence_stage_verification_response(request_bytes, proof)
}
