// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkSessionBinding,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::secret_cleanup::zeroize_stage_witness_input_proto;

mod binding;

const ZK_INPUT_BYTES_32: usize = 32;
const ZK_INPUT_BYTES_16: usize = 16;
const ZK_INPUT_BYTES_64: usize = 64;
const ZK_INPUT_MAX_CLAIM_VALUE_BYTES: usize = ZK_INPUT_BYTES_64;

pub(super) fn validate_stage_witness_input(
    circuit_ref: ZkCircuitRef,
    input: &pb::ZkStageWitnessInput,
) -> Result<(), ZkError> {
    use pb::zk_stage_witness_input::Input;

    match input
        .input
        .as_ref()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?
    {
        Input::CredentialSubjectClaimSession(input) => {
            ensure_witness_ref(
                circuit_ref,
                ZkCircuitFamily::CredentialSubjectClaimV1,
                ZkCircuitStage::Session,
            )?;
            validate_credential_subject_claim_session_input(input)
        }
        Input::PrivatePersonaSession(input) => {
            ensure_witness_ref(
                circuit_ref,
                ZkCircuitFamily::PrivatePersonaClaimV1,
                ZkCircuitStage::Session,
            )?;
            validate_private_persona_session_input(input)
        }
        Input::CredentialEnvelope(input) => {
            ensure_witness_stage(circuit_ref, ZkCircuitStage::CredentialEnvelope)?;
            validate_credential_envelope_input(input)
        }
        Input::CredentialRoot(input) => {
            ensure_witness_stage(circuit_ref, ZkCircuitStage::CredentialRoot)?;
            validate_credential_root_input(input)
        }
        Input::CredentialSubjectClaim(input) => {
            ensure_witness_ref(
                circuit_ref,
                ZkCircuitFamily::CredentialSubjectClaimV1,
                ZkCircuitStage::Claim,
            )?;
            validate_credential_subject_claim_input(input)
        }
        Input::PrivatePersonaClaim(input) => {
            ensure_witness_ref(
                circuit_ref,
                ZkCircuitFamily::PrivatePersonaClaimV1,
                ZkCircuitStage::Claim,
            )?;
            validate_private_persona_claim_input(input)
        }
    }
}

/// Owned stage-witness input with deterministic cleanup for generated protobuf
/// buffers after the request guard has transferred operation ownership.
pub struct ZkStageWitnessInputOwner {
    input: pb::ZkStageWitnessInput,
}

impl ZkStageWitnessInputOwner {
    pub(super) fn try_new(
        circuit_ref: ZkCircuitRef,
        input: pb::ZkStageWitnessInput,
    ) -> Result<Self, ZkError> {
        let owner = Self { input };
        validate_stage_witness_input(circuit_ref, &owner.input)?;
        Ok(owner)
    }

    /// Borrows the active oneof so platform adapters can construct typed
    /// witness inputs without moving generated protobuf buffers out of the
    /// cleanup owner.
    pub fn active_input(&self) -> Option<&pb::zk_stage_witness_input::Input> {
        self.input.input.as_ref()
    }

    /// Returns the active-session binding carried by the witness request input.
    pub fn expected_session_binding(&self) -> Result<ZkSessionBinding, ZkError> {
        binding::expected_session_binding(&self.input)
    }
}

impl Drop for ZkStageWitnessInputOwner {
    fn drop(&mut self) {
        zeroize_stage_witness_input_proto(&mut self.input);
    }
}

fn ensure_witness_ref(
    circuit_ref: ZkCircuitRef,
    family: ZkCircuitFamily,
    stage: ZkCircuitStage,
) -> Result<(), ZkError> {
    if circuit_ref.family == family && circuit_ref.stage == stage {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::StageMismatch))
    }
}

fn ensure_witness_stage(circuit_ref: ZkCircuitRef, stage: ZkCircuitStage) -> Result<(), ZkError> {
    if circuit_ref.stage == stage {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::StageMismatch))
    }
}

fn validate_credential_subject_claim_session_input(
    input: &pb::ZkCredentialSubjectClaimSessionInput,
) -> Result<(), ZkError> {
    validate_session_context(&input.session_context)?;
    validate_subject_session_authorization(&input.authorization)
}

fn validate_private_persona_session_input(
    input: &pb::ZkPrivatePersonaSessionInput,
) -> Result<(), ZkError> {
    validate_session_context(&input.session_context)?;
    validate_persona_session_authorization(&input.authorization)
}

fn validate_credential_envelope_input(
    input: &pb::ZkCredentialEnvelopeInput,
) -> Result<(), ZkError> {
    validate_issuer_context(&input.issuer_context)?;
    validate_bytes32(&input.envelope_binding)?;
    validate_envelope_signature_proof(&input.proof)
}

fn validate_credential_root_input(input: &pb::ZkCredentialRootInput) -> Result<(), ZkError> {
    validate_issuer_context(&input.issuer_context)?;
    validate_bytes32(&input.envelope_binding)?;
    validate_bytes32(&input.credential_binding)?;
    validate_credential_root_proof(&input.proof)
}

fn validate_credential_subject_claim_input(
    input: &pb::ZkCredentialSubjectClaimInput,
) -> Result<(), ZkError> {
    validate_issuer_context(&input.issuer_context)?;
    validate_bytes32(&input.session_binding)?;
    validate_claim_disclosure(&input.disclosure)?;
    validate_merkle_claim_proof(&input.proof)?;
    validate_subject_claim_link(&input.link)
}

fn validate_private_persona_claim_input(
    input: &pb::ZkPrivatePersonaClaimInput,
) -> Result<(), ZkError> {
    validate_issuer_context(&input.issuer_context)?;
    validate_bytes32(&input.session_binding)?;
    validate_claim_disclosure(&input.disclosure)?;
    validate_merkle_claim_proof(&input.proof)?;
    validate_persona_claim_link(&input.link)
}

fn validate_session_context(
    field: &MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>>,
) -> Result<(), ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&context.challenge)?;
    validate_bytes32(&context.audience_hash)?;
    validate_bytes32(&context.session_binding)?;
    validate_bytes32(&context.transaction_data_hash)
}

fn validate_issuer_context(
    field: &MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>>,
) -> Result<(), ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_p256_public_key(&context.issuer_public_key)?;
    validate_bytes32(&context.challenge)?;
    validate_bytes32(&context.audience_hash)?;
    validate_bytes32(&context.transaction_data_hash)
}

fn validate_claim_disclosure(
    field: &MessageField<pb::ZkInputClaimDisclosure, buffa::Inline<pb::ZkInputClaimDisclosure>>,
) -> Result<(), ZkError> {
    let disclosure = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&disclosure.credential_binding)?;
    let active_len = usize::try_from(disclosure.value_length)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if active_len > ZK_INPUT_MAX_CLAIM_VALUE_BYTES {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    let value = validate_bytes64(&disclosure.value)?;
    if value
        .get(active_len..)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    validate_bytes32(&disclosure.claim_name_hash)
}

fn validate_merkle_claim_proof(
    field: &MessageField<pb::ZkInputMerkleClaimProof, buffa::Inline<pb::ZkInputMerkleClaimProof>>,
) -> Result<(), ZkError> {
    let proof = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&proof.envelope_hash)?;
    validate_bytes32(&proof.merkle_root)?;
    validate_bytes16(&proof.claim_salt)?;
    validate_merkle_path(&proof.path)
}

fn validate_merkle_path(
    field: &MessageField<pb::ZkInputMerklePath, buffa::Inline<pb::ZkInputMerklePath>>,
) -> Result<(), ZkError> {
    let path = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    crate::claim_tree::validate_claim_path_shape(path.path_length, path.siblings.len())?;
    for sibling in &path.siblings {
        validate_exact_bytes(sibling.value.as_slice(), ZK_INPUT_BYTES_32)?;
    }
    Ok(())
}

fn validate_envelope_signature_proof(
    field: &MessageField<
        pb::ZkInputEnvelopeSignatureProof,
        buffa::Inline<pb::ZkInputEnvelopeSignatureProof>,
    >,
) -> Result<(), ZkError> {
    let proof = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&proof.envelope_hash)?;
    validate_bytes64(&proof.issuer_signature).map(|_bytes| ())
}

fn validate_credential_root_proof(
    field: &MessageField<
        pb::ZkInputCredentialRootProof,
        buffa::Inline<pb::ZkInputCredentialRootProof>,
    >,
) -> Result<(), ZkError> {
    let proof = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&proof.envelope_hash)?;
    validate_bytes32(&proof.merkle_root)?;
    validate_bytes64(&proof.issuer_root_binding_signature).map(|_bytes| ())
}

fn validate_subject_session_authorization(
    field: &MessageField<
        pb::ZkInputSubjectSessionAuthorization,
        buffa::Inline<pb::ZkInputSubjectSessionAuthorization>,
    >,
) -> Result<(), ZkError> {
    let authorization = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_p256_public_key(&authorization.subject_public_key)?;
    validate_bytes64(&authorization.subject_signature).map(|_bytes| ())
}

fn validate_persona_session_authorization(
    field: &MessageField<
        pb::ZkInputPersonaSessionAuthorization,
        buffa::Inline<pb::ZkInputPersonaSessionAuthorization>,
    >,
) -> Result<(), ZkError> {
    let authorization = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_p256_public_key(&authorization.persona_public_key)?;
    validate_bytes64(&authorization.persona_signature).map(|_bytes| ())
}

fn validate_subject_claim_link(
    field: &MessageField<pb::ZkInputSubjectClaimLink, buffa::Inline<pb::ZkInputSubjectClaimLink>>,
) -> Result<(), ZkError> {
    let link = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes64(&link.issuer_subject_binding_signature)?;
    validate_p256_public_key(&link.subject_public_key)
}

fn validate_persona_claim_link(
    field: &MessageField<pb::ZkInputPersonaClaimLink, buffa::Inline<pb::ZkInputPersonaClaimLink>>,
) -> Result<(), ZkError> {
    let link = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes64(&link.issuer_subject_binding_signature)?;
    validate_p256_public_key(&link.subject_public_key)?;
    validate_p256_public_key(&link.persona_public_key)?;
    validate_bytes64(&link.subject_link_signature).map(|_bytes| ())
}

fn validate_p256_public_key(
    field: &MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>>,
) -> Result<(), ZkError> {
    let key = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&key.x)?;
    validate_bytes32(&key.y)
}

fn validate_bytes32(
    field: &MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<(), ZkError> {
    let bytes = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_exact_bytes(bytes.value.as_slice(), ZK_INPUT_BYTES_32)
}

fn validate_bytes16(
    field: &MessageField<pb::ZkInputBytes16, buffa::Inline<pb::ZkInputBytes16>>,
) -> Result<(), ZkError> {
    let bytes = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_exact_bytes(bytes.value.as_slice(), ZK_INPUT_BYTES_16)
}

fn validate_bytes64(
    field: &MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>,
) -> Result<&[u8], ZkError> {
    let bytes = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_exact_bytes(bytes.value.as_slice(), ZK_INPUT_BYTES_64)?;
    Ok(bytes.value.as_slice())
}

fn validate_exact_bytes(bytes: &[u8], expected: usize) -> Result<(), ZkError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::InvalidProofEncoding))
    }
}
