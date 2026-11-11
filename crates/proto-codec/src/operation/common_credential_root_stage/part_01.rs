// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{Message, MessageField};
use reallyme_zk_api::{common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot}, errors::{ZkError, ZkErrorReason}, proofs::{ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH}};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::common_credential_root::ZkCommonCredentialRootWitnessPlan;

const ZK_INPUT_BYTES_16: usize = 16;
const ZK_INPUT_BYTES_32: usize = 32;
const ZK_INPUT_BYTES_64: usize = 64;
const ZK_INPUT_MAX_CLAIM_VALUE_BYTES: usize = ZK_INPUT_BYTES_64;
const ZK_INPUT_MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH: usize = 20;
const ZK_INPUT_MAX_ISSUER_STATUS_DEPTH: usize = 12;
const ZK_INPUT_MAX_ISSUER_STATUS_ENTRIES: u64 = 1_000_000;

/// Secret-owning generated common-credential-root stage input.
///
/// The owner keeps the generated tree intact for platform adapters while
/// guaranteeing validation has already happened and that drops clear nested
/// private byte buffers. Conversion into Noir witness-core structs should
/// happen while borrowing this owner; raw witness bytes are not exposed here.
pub struct ZkCommonCredentialRootStageInputOwner {
    input: pb::zk_common_credential_root_stage_prove_operation::Input,
}

impl ZkCommonCredentialRootStageInputOwner {
    /// Borrows the active common-credential-root stage input for provider dispatch.
    #[must_use]
    pub const fn active_input(
        &self,
    ) -> &pb::zk_common_credential_root_stage_prove_operation::Input {
        &self.input
    }

    /// Returns the presentation binding embedded in the typed input.
    pub fn expected_session_binding(&self) -> Result<ZkSessionBinding, ZkError> {
        expected_binding_from_common_credential_root_input(&self.input)
    }

    /// Returns the presentation expiry carried by the active stage input.
    pub fn presentation_expiry_unix(&self) -> Result<u64, ZkError> {
        presentation_expiry_unix_from_common_credential_root_input(&self.input)
    }
}

impl Drop for ZkCommonCredentialRootStageInputOwner {
    fn drop(&mut self) {
        zeroize_common_credential_root_stage_input_proto(&mut self.input);
    }
}

pub(super) fn common_credential_root_stage_input_owner_from_proto(
    plan: ZkCommonCredentialRootWitnessPlan,
    input: pb::zk_common_credential_root_stage_prove_operation::Input,
) -> Result<ZkCommonCredentialRootStageInputOwner, ZkError> {
    // Validation can fail after the input has been removed from the outer
    // operation guard. Establish its cleanup owner first so every rejection
    // still clears the nested private fields on drop.
    let owner = ZkCommonCredentialRootStageInputOwner { input };
    validate_common_credential_root_stage_input(plan, owner.active_input())?;
    Ok(owner)
}

fn validate_common_credential_root_stage_input(
    plan: ZkCommonCredentialRootWitnessPlan,
    input: &pb::zk_common_credential_root_stage_prove_operation::Input,
) -> Result<(), ZkError> {
    use pb::zk_common_credential_root_stage_prove_operation::Input;

    match (plan.persona_mode(), plan.slot(), input) {
        (_, ZkCommonCredentialRootProofSlot::RootAttestation, Input::RootAttestation(input)) => {
            validate_root_attestation_input(input)
        }
        (_, ZkCommonCredentialRootProofSlot::RootStatus, Input::RootStatus(input)) => {
            validate_root_status_input(input)
        }
        (
            _,
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0
            | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1,
            Input::IssuerCredentialStatus(input),
        ) => validate_issuer_credential_status_input(input),
        (
            _,
            ZkCommonCredentialRootProofSlot::Lineage0 | ZkCommonCredentialRootProofSlot::Lineage1,
            Input::Lineage(input),
        ) => validate_lineage_input(input),
        (
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCommonCredentialRootProofSlot::SelectedClaim0
            | ZkCommonCredentialRootProofSlot::SelectedClaim1,
            Input::PrivatePersonaClaim(input),
        ) => validate_private_persona_claim_input(input),
        (
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            ZkCommonCredentialRootProofSlot::SelectedClaim0
            | ZkCommonCredentialRootProofSlot::SelectedClaim1,
            Input::PublicPersonaClaim(input),
        ) => validate_public_persona_claim_input(input),
        (
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCommonCredentialRootProofSlot::Session,
            Input::PrivatePersonaSession(input),
        ) => validate_private_persona_session_input(input),
        (
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            ZkCommonCredentialRootProofSlot::Session,
            Input::PublicPersonaSession(input),
        ) => validate_public_persona_session_input(input),
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn validate_root_attestation_input(
    input: &pb::ZkCommonCredentialRootAttestationInput,
) -> Result<(), ZkError> {
    validate_presentation_context(&input.presentation)?;
    validate_p256_public_key(&input.reallyme_public_key)?;
    validate_bytes32(&input.assurance_policy_id)?;
    validate_bytes32(&input.root_join)?;
    validate_bytes32(&input.attestation_join)?;
    validate_bytes32(&input.root)?;
    validate_bytes64(&input.attestation_signature)?;
    validate_join_salt(&input.join_salt)
}

fn validate_root_status_input(
    input: &pb::ZkCommonCredentialRootStatusInput,
) -> Result<(), ZkError> {
    validate_presentation_context(&input.presentation)?;
    validate_bytes32(&input.active_status_root)?;
    validate_bytes32(&input.root_join)?;
    validate_bytes32(&input.attestation_join)?;
    validate_bytes32(&input.root)?;
    validate_bytes32(&input.attestation_id)?;
    validate_join_salt(&input.join_salt)?;
    validate_common_credential_root_status_path(&input.status_path)
}

fn validate_issuer_credential_status_input(
    input: &pb::ZkCommonCredentialRootIssuerCredentialStatusInput,
) -> Result<(), ZkError> {
    validate_presentation_context(&input.presentation)?;
    let presentation = input
        .presentation
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_p256_public_key(&input.issuer_public_key)?;
    validate_bytes32(&input.credential_binding)?;
    validate_bytes32(&input.status_root)?;
    validate_bytes32(&input.status_list_id)?;
    validate_bytes32(&input.status_url_hash)?;
    validate_bytes32(&input.envelope_hash)?;
    validate_bytes32(&input.claims_root)?;
    validate_bytes64(&input.issuer_validity_status_signature)?;
    validate_bytes32(&input.status_chunk)?;
    if input.status_length == 0
        || input.status_length > ZK_INPUT_MAX_ISSUER_STATUS_ENTRIES
        || input.status_index >= input.status_length
        || crate::issuer_status::purpose_from_proto(input.status_purpose).is_err()
        || input.presentation_expiry != presentation.expiry_unix
        || input.valid_from >= input.valid_until
        || input.verifier_now < input.valid_from
        || input.verifier_now >= input.valid_until
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    validate_path_len_and_siblings(
        input.path_length,
        input.path.len(),
        ZK_INPUT_MAX_ISSUER_STATUS_DEPTH,
    )?;
    for sibling in &input.path {
        validate_exact_bytes(sibling.value.as_slice(), ZK_INPUT_BYTES_32)?;
    }
    Ok(())
}

fn validate_lineage_input(input: &pb::ZkCommonCredentialRootLineageInput) -> Result<(), ZkError> {
    validate_presentation_context(&input.presentation)?;
    validate_bytes32(&input.root_join)?;
    validate_lineage_slot(&input.slot)?;
    validate_bytes32(&input.root)?;
    validate_join_salt(&input.join_salt)?;
    validate_lineage_witness(&input.witness)
}

fn validate_private_persona_claim_input(
    input: &pb::ZkCommonCredentialRootPrivatePersonaClaimInput,
) -> Result<(), ZkError> {
    validate_issuer_context(&input.issuer_context)?;
    validate_bytes32(&input.session_binding)?;
    validate_bytes32(&input.subject_join)?;
    validate_claim_disclosure(&input.disclosure)?;
    validate_merkle_claim_proof(&input.proof)?;
    validate_persona_claim_link(&input.link)?;
    validate_join_salt(&input.join_salt)
}

fn validate_public_persona_claim_input(
    input: &pb::ZkCommonCredentialRootPublicPersonaClaimInput,
) -> Result<(), ZkError> {
    validate_issuer_context(&input.issuer_context)?;
    validate_p256_public_key(&input.persona_public_key)?;
    validate_bytes32(&input.session_binding)?;
    validate_bytes32(&input.subject_join)?;
    validate_claim_disclosure(&input.disclosure)?;
    validate_merkle_claim_proof(&input.proof)?;
    validate_public_persona_claim_link(&input.link)?;
    validate_join_salt(&input.join_salt)
}

fn validate_private_persona_session_input(
    input: &pb::ZkPrivatePersonaSessionInput,
) -> Result<(), ZkError> {
    validate_session_context(&input.session_context)?;
    validate_persona_session_authorization(&input.authorization)
}

fn validate_public_persona_session_input(
    input: &pb::ZkPublicPersonaSessionInput,
) -> Result<(), ZkError> {
    validate_p256_public_key(&input.persona_public_key)?;
    validate_session_context(&input.session_context)?;
    validate_public_persona_session_authorization(&input.authorization)
}

fn validate_lineage_slot(
    field: &MessageField<
        pb::ZkInputCommonCredentialRootLineageSlot,
        buffa::Inline<pb::ZkInputCommonCredentialRootLineageSlot>,
    >,
) -> Result<(), ZkError> {
    let slot = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_p256_public_key(&slot.issuer_public_key)?;
    validate_bytes32(&slot.credential_binding)?;
    validate_bytes32(&slot.subject_join)
}

fn validate_lineage_witness(
    field: &MessageField<
        pb::ZkInputCommonCredentialRootLineageWitness,
        buffa::Inline<pb::ZkInputCommonCredentialRootLineageWitness>,
    >,
) -> Result<(), ZkError> {
    let witness = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&witness.envelope_hash)?;
    validate_bytes32(&witness.merkle_root)?;
    validate_bytes64(&witness.issuer_root_binding_signature)?;
    validate_p256_public_key(&witness.subject_public_key)?;
    validate_bytes32(&witness.relationship_did_hash)?;
    validate_bytes32(&witness.relationship_nonce)?;
    validate_bytes16(&witness.claim_salt)?;
    validate_merkle_path(&witness.merkle_path)
}

fn validate_presentation_context(
    field: &MessageField<
        pb::ZkInputPresentationContext,
        buffa::Inline<pb::ZkInputPresentationContext>,
    >,
) -> Result<(), ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes32(&context.challenge)?;
    validate_bytes32(&context.audience_hash)?;
    validate_bytes32(&context.transaction_data_hash)?;
    if context.expiry_unix == 0 {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
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
    let value = bytes64(&disclosure.value)?;
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
