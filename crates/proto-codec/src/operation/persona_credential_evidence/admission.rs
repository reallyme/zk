// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed admission of prepared proving operations from canonical protobuf.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::{
    ZkPersonaCredentialEvidenceClaimRootProveRequest,
    ZkPersonaCredentialEvidenceCurrentStateProveRequest,
    ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
    ZkPersonaCredentialEvidenceSelectedClaimProveRequest,
    ZkPersonaCredentialEvidenceSignedValidityProveRequest, MAX_PREPARED_STATUS_INDEX,
    PREPARED_DIGEST_BYTES, PREPARED_SIGNATURE_BYTES,
};
use crate::domain::{circuit_ref_from_proto_message, proof_suite_from_proto};
use crate::operation::{
    secret_cleanup::{
        PersonaCredentialEvidenceCurrentStateProveOperationGuard,
        PersonaCredentialEvidenceStageProveOperationGuard,
    },
    witness_from_proto, ZkProviderOperation,
};
use crate::persona_credential_evidence_proof_set::ZkPersonaCredentialEvidenceProofSet;
use crate::persona_credential_evidence_stage_proof::{
    persona_credential_evidence_stage_proof_from_proto, profile_from_proto,
};

pub(in crate::operation) fn verify_persona_credential_evidence_stage_from_proto(
    mut operation: pb::ZkPersonaCredentialEvidenceStageVerifyOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let package = operation
        .proof
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    persona_credential_evidence_stage_proof_from_proto(package)
        .map(|proof| ZkProviderOperation::VerifyPersonaCredentialEvidenceStage { proof })
}

pub(in crate::operation) fn prove_persona_credential_evidence_stage_from_proto(
    operation: pb::ZkPersonaCredentialEvidenceStageProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = PersonaCredentialEvidenceStageProveOperationGuard::new(operation);
    let mode = profile_from_proto(operation.mode())?;
    let circuit_ref = circuit_ref_from_proto_message(operation.take_circuit_ref())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    proof_suite.require_production()?;
    let witness = operation
        .take_witness()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let witness = witness_from_proto(witness, circuit_ref)?;
    Ok(ZkProviderOperation::ProvePersonaCredentialEvidenceStage {
        mode,
        circuit_ref,
        proof_suite,
        witness,
    })
}

pub(in crate::operation) fn prove_persona_credential_evidence_current_state_from_proto(
    operation: pb::ZkPersonaCredentialEvidenceCurrentStateProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = PersonaCredentialEvidenceCurrentStateProveOperationGuard::new(operation);
    let mode = profile_from_proto(operation.mode())?;
    let circuit_ref = circuit_ref_from_proto_message(operation.take_circuit_ref())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    proof_suite.require_production()?;
    let mut evidence = operation
        .take_evidence_proof_set()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let issuer_envelope = persona_credential_evidence_stage_proof_from_proto(
        evidence
            .issuer_envelope
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let claim_root = persona_credential_evidence_stage_proof_from_proto(
        evidence
            .claim_root
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let signed_validity = persona_credential_evidence_stage_proof_from_proto(
        evidence
            .signed_validity
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let selected_claim = persona_credential_evidence_stage_proof_from_proto(
        evidence
            .selected_claim
            .take()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?,
    )?;
    let evidence = ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        issuer_envelope,
        claim_root,
        signed_validity,
        selected_claim,
    )?;
    if evidence.mode() != mode {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    // Install the cleanup owner before either private protobuf branch leaves
    // the operation guard. A missing second branch must wipe the first one.
    let mut input = Box::new(ZkPersonaCredentialEvidenceCurrentStateProveRequest {
        evidence,
        credential: pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput::default(),
        current_status: pb::ZkPersonaCredentialEvidenceCurrentStatusInput::default(),
        verification_time_unix: operation.verification_time_unix(),
    });
    input.credential = operation
        .take_credential()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    input.current_status = operation
        .take_current_status()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(
        ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState {
            mode,
            circuit_ref,
            proof_suite,
            input,
        },
    )
}

pub(in crate::operation) fn prove_persona_credential_evidence_issuer_envelope_from_proto(
    operation: pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut input = Box::new(ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest { operation });
    let mode = profile_from_proto(input.operation.mode)?;
    let circuit_ref =
        circuit_ref_from_proto_message(core::mem::take(&mut input.operation.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(input.operation.proof_suite)?;
    proof_suite.require_production()?;
    validate_issuer_envelope_wire(&input.operation)?;
    Ok(
        ZkProviderOperation::ProvePersonaCredentialEvidenceIssuerEnvelope {
            mode,
            circuit_ref,
            proof_suite,
            input,
        },
    )
}

pub(in crate::operation) fn prove_persona_credential_evidence_claim_root_from_proto(
    operation: pb::ZkPersonaCredentialEvidenceClaimRootProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut input = Box::new(ZkPersonaCredentialEvidenceClaimRootProveRequest { operation });
    let mode = profile_from_proto(input.operation.mode)?;
    let circuit_ref =
        circuit_ref_from_proto_message(core::mem::take(&mut input.operation.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(input.operation.proof_suite)?;
    proof_suite.require_production()?;
    if circuit_ref
        != reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
            .source_ref(circuit_ref.credential_hash_algorithm)
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    validate_claim_root_wire(&input.operation)?;
    Ok(
        ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot {
            mode,
            circuit_ref,
            proof_suite,
            input,
        },
    )
}

pub(in crate::operation) fn prove_persona_credential_evidence_signed_validity_from_proto(
    operation: pb::ZkPersonaCredentialEvidenceSignedValidityProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut input = Box::new(ZkPersonaCredentialEvidenceSignedValidityProveRequest { operation });
    let mode = profile_from_proto(input.operation.mode)?;
    let circuit_ref =
        circuit_ref_from_proto_message(core::mem::take(&mut input.operation.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(input.operation.proof_suite)?;
    proof_suite.require_production()?;
    if circuit_ref
        != reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceSourceStage::SignedValidity
            .source_ref(circuit_ref.credential_hash_algorithm)
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    validate_signed_validity_wire(&input.operation)?;
    Ok(
        ZkProviderOperation::ProvePersonaCredentialEvidenceSignedValidity {
            mode,
            circuit_ref,
            proof_suite,
            input,
        },
    )
}

pub(in crate::operation) fn prove_persona_credential_evidence_selected_claim_from_proto(
    operation: pb::ZkPersonaCredentialEvidenceSelectedClaimProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut input = Box::new(ZkPersonaCredentialEvidenceSelectedClaimProveRequest { operation });
    let mode = profile_from_proto(input.operation.mode)?;
    let circuit_ref =
        circuit_ref_from_proto_message(core::mem::take(&mut input.operation.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(input.operation.proof_suite)?;
    proof_suite.require_production()?;
    let stage = match mode {
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        }
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        }
    };
    if circuit_ref != stage.source_ref(circuit_ref.credential_hash_algorithm) {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    validate_selected_claim_wire(&input.operation, mode)?;
    Ok(
        ZkProviderOperation::ProvePersonaCredentialEvidenceSelectedClaim {
            mode,
            circuit_ref,
            proof_suite,
            input,
        },
    )
}

fn validate_selected_claim_wire(
    operation: &pb::ZkPersonaCredentialEvidenceSelectedClaimProveOperation,
    mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
) -> Result<(), ZkError> {
    let invalid = || ZkError::new(ZkErrorReason::InvalidProofEncoding);
    let bytes32 =
        |field: &buffa::MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>| {
            field
                .as_option()
                .is_some_and(|value| value.value.len() == 32)
        };
    let bytes64 =
        |field: &buffa::MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>| {
            field
                .as_option()
                .is_some_and(|value| value.value.len() == 64)
        };
    let key = |field: &buffa::MessageField<
        pb::ZkInputP256PublicKey,
        buffa::Inline<pb::ZkInputP256PublicKey>,
    >| {
        field
            .as_option()
            .is_some_and(|value| bytes32(&value.x) && bytes32(&value.y))
    };
    let disclosure = operation.disclosure.as_option().ok_or_else(invalid)?;
    let opening = operation.claim_opening.as_option().ok_or_else(invalid)?;
    let path = opening.path.as_option().ok_or_else(invalid)?;
    let value_len = usize::try_from(disclosure.value_length)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let path_len = usize::try_from(path.path_length)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if !key(&operation.issuer_public_key)
        || !key(&operation.holder_public_key)
        || !key(&operation.subject_public_key)
        || !key(&operation.persona_public_key)
        || !bytes32(&operation.token_nonce)
        || !bytes32(&disclosure.credential_binding)
        || !bytes32(&disclosure.claim_name_hash)
        || !bytes32(&opening.envelope_hash)
        || !bytes32(&opening.merkle_root)
        || !bytes64(&operation.issuer_subject_binding_signature)
        || !bytes64(&operation.subject_persona_link_signature)
        || opening
            .claim_salt
            .as_option()
            .is_none_or(|salt| salt.value.len() != 16 || salt.value.iter().all(|byte| *byte == 0))
        || disclosure.value.as_option().is_none_or(|value| {
            value.value.len() != 64
                || value_len == 0
                || value_len > 64
                || value.value[value_len..].iter().any(|byte| *byte != 0)
        })
        || !crate::claim_tree::is_claim_tree_depth(path_len)
        || path.siblings.len() != path_len
        || path
            .siblings
            .iter()
            .any(|sibling| sibling.value.len() != 32)
        || opening.leaf_index >= 64
        || opening.leaf_index >> path_len != 0
        || operation.evidence_valid_from_unix >= operation.evidence_valid_until_unix
    {
        return Err(invalid());
    }
    match mode {
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            if operation.persona_public_key != operation.holder_public_key
                || operation
                    .persona_token_authorization_signature
                    .as_option()
                    .is_some()
            {
                return Err(invalid());
            }
        }
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            if operation.persona_public_key == operation.holder_public_key
                || !bytes64(&operation.persona_token_authorization_signature)
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn validate_signed_validity_wire(
    operation: &pb::ZkPersonaCredentialEvidenceSignedValidityProveOperation,
) -> Result<(), ZkError> {
    for field in [
        &operation.token_nonce,
        &operation.credential_binding,
        &operation.envelope_hash,
        &operation.claims_root,
        &operation.status_list_id,
        &operation.status_url_hash,
    ] {
        if field
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    for field in [
        &operation.issuer_public_key,
        &operation.holder_public_key,
        &operation.subject_public_key,
    ] {
        let key = field
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        if key
            .x
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
            || key
                .y
                .as_option()
                .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    if operation
        .issuer_validity_status_signature
        .as_option()
        .is_none_or(|value| value.value.len() != PREPARED_SIGNATURE_BYTES)
        || operation.evidence_valid_from_unix >= operation.evidence_valid_until_unix
        || operation.valid_from_unix >= operation.valid_until_unix
        || operation.valid_from_unix > operation.evidence_valid_from_unix
        || operation.evidence_valid_until_unix > operation.valid_until_unix
        || operation.status_index >= MAX_PREPARED_STATUS_INDEX
        || crate::issuer_status::purpose_from_proto(operation.status_purpose).is_err()
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}

fn validate_claim_root_wire(
    operation: &pb::ZkPersonaCredentialEvidenceClaimRootProveOperation,
) -> Result<(), ZkError> {
    for field in [
        &operation.token_nonce,
        &operation.credential_binding,
        &operation.envelope_hash,
        &operation.claims_root,
    ] {
        if field
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    for field in [
        &operation.issuer_public_key,
        &operation.holder_public_key,
        &operation.subject_public_key,
    ] {
        let key = field
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        if key
            .x
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
            || key
                .y
                .as_option()
                .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    if operation
        .issuer_root_binding_signature
        .as_option()
        .is_none_or(|value| value.value.len() != PREPARED_SIGNATURE_BYTES)
        || operation.evidence_valid_from_unix >= operation.evidence_valid_until_unix
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}

fn validate_issuer_envelope_wire(
    operation: &pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation,
) -> Result<(), ZkError> {
    let required32 = [
        &operation.token_nonce,
        &operation.credential_binding,
        &operation.envelope_hash,
        &operation.claims_root,
    ];
    if required32.iter().any(|field| {
        field
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
    }) {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    for field in [
        &operation.issuer_public_key,
        &operation.holder_public_key,
        &operation.subject_public_key,
    ] {
        let key = field
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        if key
            .x
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
            || key
                .y
                .as_option()
                .is_none_or(|value| value.value.len() != PREPARED_DIGEST_BYTES)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
    }
    if operation
        .issuer_envelope_signature
        .as_option()
        .is_none_or(|value| value.value.len() != PREPARED_SIGNATURE_BYTES)
        || operation
            .issuer_subject_binding_signature
            .as_option()
            .is_none_or(|value| value.value.len() != PREPARED_SIGNATURE_BYTES)
        || operation.evidence_valid_from_unix >= operation.evidence_valid_until_unix
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}
