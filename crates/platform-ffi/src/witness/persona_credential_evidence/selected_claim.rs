// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Convert a selected Wallet opening into the exact prepared claim witness.

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceSubjectPublicKey,
        ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::ZkWitness,
};
use reallyme_zk_backend_bb::BbExactCircuitArtifacts;
use reallyme_zk_noir_witness_core::{
    circuits::persona_credential_evidence_v1_claim::{
        generate_witness_from_artifact_json, PersonaCredentialEvidenceClaimMode,
        PersonaCredentialEvidencePrivatePersonaAuthorization,
        PersonaCredentialEvidenceV1ClaimInputs, PersonaCredentialEvidenceV1ClaimPrivateInputs,
        PersonaCredentialEvidenceV1ClaimPublicInputs,
    },
    CompiledProgramArtifactJson, SecretInputs, CLAIM_TREE_DEPTH,
};
use reallyme_zk_proto_codec::operation::ZkPersonaCredentialEvidenceSelectedClaimProveRequest;
use zeroize::Zeroizing;

use crate::witness::{
    input::{bytes16, bytes32, bytes64, fixed_bytes, p256_public_key},
    map_witness_error,
};

/// Requires a selected claim opening to declare and carry exactly the fixed
/// claim-tree depth. Shorter paths are never padded and longer paths are
/// never truncated; both are rejected before any binding or proving work.
fn require_full_depth_claim_path(path_length: u32, sibling_count: usize) -> Result<(), ZkError> {
    let declared_length =
        usize::try_from(path_length).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if declared_length > CLAIM_TREE_DEPTH || sibling_count > CLAIM_TREE_DEPTH {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    if declared_length != CLAIM_TREE_DEPTH || sibling_count != CLAIM_TREE_DEPTH {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}

pub(crate) fn generate_persona_credential_evidence_selected_claim_witness(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
    mode: ZkPersonaCredentialEvidenceMode,
    input: &ZkPersonaCredentialEvidenceSelectedClaimProveRequest,
) -> Result<ZkWitness, ZkError> {
    let stage = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        }
    };
    if circuit_ref != stage.source_ref(circuit_ref.credential_hash_algorithm) {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let operation = &input.operation;
    let issuer = p256_public_key(&operation.issuer_public_key)?;
    let holder = p256_public_key(&operation.holder_public_key)?;
    let subject = p256_public_key(&operation.subject_public_key)?;
    let persona = p256_public_key(&operation.persona_public_key)?;
    let disclosure = operation
        .disclosure
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let opening = operation
        .claim_opening
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let path = opening
        .path
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    require_full_depth_claim_path(path.path_length, path.siblings.len())?;
    let nonce = bytes32(&operation.token_nonce)?;
    let envelope_hash = bytes32(&opening.envelope_hash)?;
    let claims_root = bytes32(&opening.merkle_root)?;
    let binding = bytes32(&disclosure.credential_binding)?;
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

    let value = disclosure
        .value
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let value: Zeroizing<[u8; 64]> = fixed_bytes(&value.value)?;
    let mut siblings = Zeroizing::new([[0_u8; 32]; CLAIM_TREE_DEPTH]);
    for (slot, sibling) in siblings.iter_mut().zip(path.siblings.iter()) {
        *slot = *fixed_bytes(&sibling.value)?;
    }
    // Convert every fallible private field before a private struct literal
    // is started, so an early return can only drop zeroizing owners and never
    // bare witness arrays held in a half-built value.
    let persona_token_authorization_signature = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => None,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            Some(bytes64(&operation.persona_token_authorization_signature)?)
        }
    };
    let claim_name_hash = bytes32(&disclosure.claim_name_hash)?;
    let issuer_subject_binding_signature = bytes64(&operation.issuer_subject_binding_signature)?;
    let subject_persona_link_signature = bytes64(&operation.subject_persona_link_signature)?;
    let claim_salt = bytes16(&opening.claim_salt)?;
    let private_persona = persona_token_authorization_signature
        .as_ref()
        .map(
            |signature| PersonaCredentialEvidencePrivatePersonaAuthorization {
                persona_x: *persona.x.as_bytes(),
                persona_y: *persona.y.as_bytes(),
                persona_token_authorization_signature: **signature,
            },
        );
    let inputs = PersonaCredentialEvidenceV1ClaimInputs {
        mode: match mode {
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
                PersonaCredentialEvidenceClaimMode::Public
            }
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
                PersonaCredentialEvidenceClaimMode::PrivateOneTime
            }
        },
        public_inputs: PersonaCredentialEvidenceV1ClaimPublicInputs {
            issuer_x: *issuer.x.as_bytes(),
            issuer_y: *issuer.y.as_bytes(),
            holder_x: *holder.x.as_bytes(),
            holder_y: *holder.y.as_bytes(),
            token_nonce: *nonce,
            prepared_from: operation.evidence_valid_from_unix,
            prepared_until: operation.evidence_valid_until_unix,
            credential_binding: *binding,
            value_length: disclosure.value_length,
            value: *value,
            claim_name_hash: *claim_name_hash,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1ClaimPrivateInputs {
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            issuer_subject_binding_signature: *issuer_subject_binding_signature,
            subject_x: *subject.x.as_bytes(),
            subject_y: *subject.y.as_bytes(),
            subject_persona_link_signature: *subject_persona_link_signature,
            private_persona,
            claim_salt: *claim_salt,
            claim_index: opening.leaf_index,
            path_length: path.path_length,
            path: *siblings,
        }),
    };
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(map_witness_error)?;
    let witness =
        generate_witness_from_artifact_json(artifact_json, &inputs).map_err(map_witness_error)?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness.into_zeroizing_bytes())
}

#[cfg(test)]
#[path = "selected_claim/claim_path_tests.rs"]
mod claim_path_tests;
