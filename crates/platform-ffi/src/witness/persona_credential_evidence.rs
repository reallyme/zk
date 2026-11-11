// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceSubjectPublicKey, ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::ZkWitness,
};
use reallyme_zk_backend_bb::BbExactCircuitArtifacts;
use reallyme_zk_noir_witness_core::{
    circuits::{
        persona_credential_evidence_v1_claim_root::{
            generate_witness_from_artifact_json as generate_claim_root_witness,
            PersonaCredentialEvidenceV1ClaimRootInputs,
            PersonaCredentialEvidenceV1ClaimRootPrivateInputs,
            PersonaCredentialEvidenceV1ClaimRootPublicInputs,
        },
        persona_credential_evidence_v1_issuer_envelope::{
            generate_witness_from_artifact_json as generate_issuer_envelope_witness,
            PersonaCredentialEvidenceV1IssuerEnvelopeInputs,
            PersonaCredentialEvidenceV1IssuerEnvelopePrivateInputs,
            PersonaCredentialEvidenceV1IssuerEnvelopePublicInputs,
        },
        persona_credential_evidence_v1_signed_validity::{
            generate_witness_from_artifact_json as generate_signed_validity_witness,
            PersonaCredentialEvidenceV1SignedValidityInputs,
            PersonaCredentialEvidenceV1SignedValidityPrivateInputs,
            PersonaCredentialEvidenceV1SignedValidityPublicInputs,
        },
    },
    CompiledProgramArtifactJson, SecretInputs,
};
use reallyme_zk_proto_codec::operation::{
    ZkPersonaCredentialEvidenceClaimRootProveRequest,
    ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
    ZkPersonaCredentialEvidenceSignedValidityProveRequest,
};

use super::{
    input::{bytes32, bytes64, p256_public_key},
    map_witness_error,
};

#[path = "persona_credential_evidence/current_state.rs"]
mod current_state;
#[path = "persona_credential_evidence/selected_claim.rs"]
mod selected_claim;
pub(crate) use current_state::generate_persona_credential_evidence_current_state_witness;
pub(crate) use selected_claim::generate_persona_credential_evidence_selected_claim_witness;

pub(crate) fn generate_persona_credential_evidence_signed_validity_witness(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
    input: &ZkPersonaCredentialEvidenceSignedValidityProveRequest,
) -> Result<ZkWitness, ZkError> {
    if circuit_ref
        != ZkPersonaCredentialEvidenceSourceStage::SignedValidity
            .source_ref(circuit_ref.credential_hash_algorithm)
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let operation = &input.operation;
    let issuer = p256_public_key(&operation.issuer_public_key)?;
    let holder = p256_public_key(&operation.holder_public_key)?;
    let subject = p256_public_key(&operation.subject_public_key)?;
    let nonce = bytes32(&operation.token_nonce)?;
    let envelope_hash = bytes32(&operation.envelope_hash)?;
    let claims_root = bytes32(&operation.claims_root)?;
    let binding = bytes32(&operation.credential_binding)?;
    let proof_window = ZkPersonaCredentialEvidenceValidityWindow::try_new(
        operation.evidence_valid_from_unix,
        operation.evidence_valid_until_unix,
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    proof_window
        .validate_issuer_bounds(operation.valid_from_unix, operation.valid_until_unix)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let derived = derive_persona_credential_evidence_binding(
        circuit_ref.credential_hash_algorithm,
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: ZkIssuerPublicKey {
                x: *issuer.x.as_bytes(),
                y: *issuer.y.as_bytes(),
            },
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: *subject.x.as_bytes(),
                y: *subject.y.as_bytes(),
            },
            holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
                x: *holder.x.as_bytes(),
                y: *holder.y.as_bytes(),
            },
            token_nonce: *nonce,
            proof_window,
        },
    )?;
    if derived != *binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let status_purpose =
        reallyme_zk_proto_codec::issuer_status::purpose_from_proto(operation.status_purpose)?
            .wire_value();
    // Convert every fallible field, in request order, before the private
    // struct literal so an early return can only drop zeroizing owners, never
    // bare witness arrays.
    let status_list_id = bytes32(&operation.status_list_id)?;
    let status_url_hash = bytes32(&operation.status_url_hash)?;
    let issuer_validity_status_signature = bytes64(&operation.issuer_validity_status_signature)?;
    let inputs = PersonaCredentialEvidenceV1SignedValidityInputs {
        public_inputs: PersonaCredentialEvidenceV1SignedValidityPublicInputs {
            issuer_x: *issuer.x.as_bytes(),
            issuer_y: *issuer.y.as_bytes(),
            holder_x: *holder.x.as_bytes(),
            holder_y: *holder.y.as_bytes(),
            token_nonce: *nonce,
            prepared_from: operation.evidence_valid_from_unix,
            prepared_until: operation.evidence_valid_until_unix,
            credential_binding: *binding,
            status_list_id: *status_list_id,
            status_url_hash: *status_url_hash,
            status_purpose,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1SignedValidityPrivateInputs {
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            subject_x: *subject.x.as_bytes(),
            subject_y: *subject.y.as_bytes(),
            issuer_validity_status_signature: *issuer_validity_status_signature,
            valid_from: operation.valid_from_unix,
            valid_until: operation.valid_until_unix,
            status_index: operation.status_index,
        }),
    };
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(map_witness_error)?;
    let witness =
        generate_signed_validity_witness(artifact_json, &inputs).map_err(map_witness_error)?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness.into_zeroizing_bytes())
}

pub(crate) fn generate_persona_credential_evidence_claim_root_witness(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
    input: &ZkPersonaCredentialEvidenceClaimRootProveRequest,
) -> Result<ZkWitness, ZkError> {
    if circuit_ref
        != ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
            .source_ref(circuit_ref.credential_hash_algorithm)
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let operation = &input.operation;
    let issuer = p256_public_key(&operation.issuer_public_key)?;
    let holder = p256_public_key(&operation.holder_public_key)?;
    let subject = p256_public_key(&operation.subject_public_key)?;
    let nonce = bytes32(&operation.token_nonce)?;
    let envelope_hash = bytes32(&operation.envelope_hash)?;
    let claims_root = bytes32(&operation.claims_root)?;
    let binding = bytes32(&operation.credential_binding)?;
    let proof_window = ZkPersonaCredentialEvidenceValidityWindow::try_new(
        operation.evidence_valid_from_unix,
        operation.evidence_valid_until_unix,
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let derived = derive_persona_credential_evidence_binding(
        circuit_ref.credential_hash_algorithm,
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: ZkIssuerPublicKey {
                x: *issuer.x.as_bytes(),
                y: *issuer.y.as_bytes(),
            },
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: *subject.x.as_bytes(),
                y: *subject.y.as_bytes(),
            },
            holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
                x: *holder.x.as_bytes(),
                y: *holder.y.as_bytes(),
            },
            token_nonce: *nonce,
            proof_window,
        },
    )?;
    if derived != *binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    // Convert the fallible field before the private struct literal so an
    // early return can only drop zeroizing owners, never bare witness arrays.
    let issuer_root_binding_signature = bytes64(&operation.issuer_root_binding_signature)?;
    let inputs = PersonaCredentialEvidenceV1ClaimRootInputs {
        public_inputs: PersonaCredentialEvidenceV1ClaimRootPublicInputs {
            issuer_x: *issuer.x.as_bytes(),
            issuer_y: *issuer.y.as_bytes(),
            holder_x: *holder.x.as_bytes(),
            holder_y: *holder.y.as_bytes(),
            token_nonce: *nonce,
            prepared_from: operation.evidence_valid_from_unix,
            prepared_until: operation.evidence_valid_until_unix,
            credential_binding: *binding,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1ClaimRootPrivateInputs {
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            subject_x: *subject.x.as_bytes(),
            subject_y: *subject.y.as_bytes(),
            issuer_root_binding_signature: *issuer_root_binding_signature,
        }),
    };
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(map_witness_error)?;
    let witness = generate_claim_root_witness(artifact_json, &inputs).map_err(map_witness_error)?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness.into_zeroizing_bytes())
}

pub(crate) fn generate_persona_credential_evidence_issuer_envelope_witness(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
    input: &ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
) -> Result<ZkWitness, ZkError> {
    let inputs = prepared_issuer_envelope_inputs(circuit_ref, input)?;
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(map_witness_error)?;
    let witness =
        generate_issuer_envelope_witness(artifact_json, &inputs).map_err(map_witness_error)?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness.into_zeroizing_bytes())
}

fn prepared_issuer_envelope_inputs(
    circuit_ref: ZkCircuitRef,
    input: &ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
) -> Result<PersonaCredentialEvidenceV1IssuerEnvelopeInputs, ZkError> {
    if circuit_ref
        != ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
            .source_ref(circuit_ref.credential_hash_algorithm)
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let operation = &input.operation;
    let issuer = p256_public_key(&operation.issuer_public_key)?;
    let holder = p256_public_key(&operation.holder_public_key)?;
    let subject = p256_public_key(&operation.subject_public_key)?;
    let nonce = bytes32(&operation.token_nonce)?;
    let envelope_hash = bytes32(&operation.envelope_hash)?;
    let claims_root = bytes32(&operation.claims_root)?;
    let binding = bytes32(&operation.credential_binding)?;
    let proof_window = ZkPersonaCredentialEvidenceValidityWindow::try_new(
        operation.evidence_valid_from_unix,
        operation.evidence_valid_until_unix,
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let derived = derive_persona_credential_evidence_binding(
        circuit_ref.credential_hash_algorithm,
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: ZkIssuerPublicKey {
                x: *issuer.x.as_bytes(),
                y: *issuer.y.as_bytes(),
            },
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: *subject.x.as_bytes(),
                y: *subject.y.as_bytes(),
            },
            holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
                x: *holder.x.as_bytes(),
                y: *holder.y.as_bytes(),
            },
            token_nonce: *nonce,
            proof_window,
        },
    )?;
    if derived != *binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    // Convert every fallible field before the private struct literal so an
    // early return can only drop zeroizing owners, never bare witness arrays.
    let issuer_envelope_signature = bytes64(&operation.issuer_envelope_signature)?;
    let issuer_subject_binding_signature = bytes64(&operation.issuer_subject_binding_signature)?;
    Ok(PersonaCredentialEvidenceV1IssuerEnvelopeInputs {
        public_inputs: PersonaCredentialEvidenceV1IssuerEnvelopePublicInputs {
            issuer_x: *issuer.x.as_bytes(),
            issuer_y: *issuer.y.as_bytes(),
            holder_x: *holder.x.as_bytes(),
            holder_y: *holder.y.as_bytes(),
            token_nonce: *nonce,
            prepared_from: operation.evidence_valid_from_unix,
            prepared_until: operation.evidence_valid_until_unix,
            credential_binding: *binding,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1IssuerEnvelopePrivateInputs {
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            subject_x: *subject.x.as_bytes(),
            subject_y: *subject.y.as_bytes(),
            issuer_envelope_signature: *issuer_envelope_signature,
            issuer_subject_binding_signature: *issuer_subject_binding_signature,
        }),
    })
}

#[cfg(test)]
#[path = "persona_credential_evidence/tests.rs"]
mod tests;
