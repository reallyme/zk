// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Current issuer-status witness for an already prepared credential.

use crypto_sha2_256::digest as sha256;
use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCircuitStage},
    common_root::COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        check_persona_credential_evidence_v1_joins, derive_persona_credential_evidence_binding,
        ZkPersonaCredentialEvidenceBindingInputs, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageJoin,
        ZkPersonaCredentialEvidenceSubjectPublicKey,
    },
    proofs::{ZkProofSuite, ZkWitness},
};
use reallyme_zk_backend_bb::BbExactCircuitArtifacts;
use reallyme_zk_noir_witness_core::{
    circuits::persona_credential_evidence_v1_current_state::{
        generate_witness_from_artifact_json, PersonaCredentialEvidenceV1CurrentStateInputs,
        PersonaCredentialEvidenceV1CurrentStatePrivateInputs,
        PersonaCredentialEvidenceV1CurrentStatePublicInputs,
    },
    CompiledProgramArtifactJson, SecretInputs,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkPersonaCredentialEvidenceCurrentStateProveRequest;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::witness::{
    input::{bytes32, bytes64, fixed_bytes, p256_public_key},
    map_witness_error,
};

const MAX_CURRENT_STATUS_LENGTH: u64 = 1_000_000;

pub(crate) fn generate_persona_credential_evidence_current_state_witness(
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    artifacts: &BbExactCircuitArtifacts,
    input: &ZkPersonaCredentialEvidenceCurrentStateProveRequest,
) -> Result<ZkWitness, ZkError> {
    let inputs = prepared_current_state_inputs(circuit_ref, proof_suite, input)?;
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(map_witness_error)?;
    let witness =
        generate_witness_from_artifact_json(artifact_json, &inputs).map_err(map_witness_error)?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness.into_zeroizing_bytes())
}

pub(super) fn prepared_current_state_inputs(
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: &ZkPersonaCredentialEvidenceCurrentStateProveRequest,
) -> Result<PersonaCredentialEvidenceV1CurrentStateInputs, ZkError> {
    if input.evidence.mode() != input_profile(input, proof_suite)? {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let expected_ref = ZkPersonaCredentialEvidenceSourceStage::CurrentState
        .source_ref(input.evidence.credential_hash_algorithm());
    if circuit_ref != expected_ref || circuit_ref.stage != ZkCircuitStage::EvidenceCurrentState {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let selected_join = input
        .evidence
        .selected_claim()
        .public_inputs()
        .join(proof_suite)?;
    selected_join
        .proof_window
        .validate_at(input.verification_time_unix)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let status_pointer = input
        .evidence
        .signed_validity()
        .public_inputs()
        .status_list_pointer()?;
    let status = current_status_fields(&input.current_status)?;
    if status_pointer.list_id != status.status_list_id
        || status_pointer.url_hash != status.status_url_hash
        || status_pointer.purpose
            != reallyme_zk_proto_codec::issuer_status::purpose_from_proto(
                input.current_status.status_purpose,
            )?
    {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    if input.current_status.issued_unix >= input.current_status.expires_unix
        || input.verification_time_unix < input.current_status.issued_unix
        || input.verification_time_unix >= input.current_status.expires_unix
    {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }

    let credential = credential_fields(&input.credential)?;
    selected_join
        .proof_window
        .validate_issuer_bounds(credential.valid_from, credential.valid_until)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let derived_binding = derive_persona_credential_evidence_binding(
        input.evidence.credential_hash_algorithm(),
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: selected_join.issuer_key,
            envelope_hash: credential.envelope_hash,
            claims_root: credential.claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: credential.subject_x,
                y: credential.subject_y,
            },
            holder_key: selected_join.holder_key,
            token_nonce: selected_join.token_nonce,
            proof_window: selected_join.proof_window,
        },
    )?;
    if derived_binding != selected_join.credential_binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    verify_current_status_opening(
        &status.status_root,
        input.current_status.status_length,
        input.credential.status_index,
        &status.status_chunk,
        status
            .path
            .get(..status.path_length)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
    )?;
    let status_purpose = reallyme_zk_proto_codec::issuer_status::purpose_from_proto(
        input.current_status.status_purpose,
    )?
    .wire_value();

    Ok(PersonaCredentialEvidenceV1CurrentStateInputs {
        public_inputs: PersonaCredentialEvidenceV1CurrentStatePublicInputs {
            issuer_x: selected_join.issuer_key.x,
            issuer_y: selected_join.issuer_key.y,
            holder_x: selected_join.holder_key.x,
            holder_y: selected_join.holder_key.y,
            token_nonce: selected_join.token_nonce,
            prepared_from: selected_join.proof_window.valid_from_unix(),
            prepared_until: selected_join.proof_window.valid_until_unix(),
            credential_binding: selected_join.credential_binding,
            status_root: status.status_root,
            status_length: input.current_status.status_length,
            status_list_id: status.status_list_id,
            status_url_hash: status.status_url_hash,
            status_purpose,
        },
        private_inputs: SecretInputs::new(PersonaCredentialEvidenceV1CurrentStatePrivateInputs {
            envelope_hash: credential.envelope_hash,
            claims_root: credential.claims_root,
            subject_x: credential.subject_x,
            subject_y: credential.subject_y,
            issuer_validity_status_signature: credential.issuer_validity_status_signature,
            valid_from: credential.valid_from,
            valid_until: credential.valid_until,
            status_index: input.credential.status_index,
            status_chunk: status.status_chunk,
            path_length: input.current_status.path_length,
            path: status.path,
        }),
    })
}

fn input_profile(
    input: &ZkPersonaCredentialEvidenceCurrentStateProveRequest,
    proof_suite: ZkProofSuite,
) -> Result<ZkPersonaCredentialEvidenceMode, ZkError> {
    let selected_join = input
        .evidence
        .selected_claim()
        .public_inputs()
        .join(proof_suite)?;
    let current_join = ZkPersonaCredentialEvidenceStageJoin {
        credential_hash_algorithm: input.evidence.credential_hash_algorithm(),
        proof_suite,
        issuer_key: selected_join.issuer_key,
        holder_key: selected_join.holder_key,
        token_nonce: selected_join.token_nonce,
        proof_window: selected_join.proof_window,
        credential_binding: selected_join.credential_binding,
    };
    check_persona_credential_evidence_v1_joins(
        &selected_join,
        &current_join,
        input.verification_time_unix,
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    Ok(input.evidence.mode())
}

// Parsing creates a second stack owner before SecretInputs takes the witness.
// Wipe that owner on every return path, including status-opening rejection.
#[derive(Zeroize, ZeroizeOnDrop)]
struct CredentialFields {
    envelope_hash: [u8; 32],
    claims_root: [u8; 32],
    subject_x: [u8; 32],
    subject_y: [u8; 32],
    issuer_validity_status_signature: [u8; 64],
    valid_from: u64,
    valid_until: u64,
}

fn credential_fields(
    input: &pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput,
) -> Result<CredentialFields, ZkError> {
    let subject = p256_public_key(&input.subject_public_key)?;
    // Convert every fallible field first: a struct literal that returns early
    // drops its already-evaluated fields as bare arrays, without zeroizing.
    let envelope_hash = bytes32(&input.envelope_hash)?;
    let claims_root = bytes32(&input.claims_root)?;
    let issuer_validity_status_signature = bytes64(&input.issuer_validity_status_signature)?;
    Ok(CredentialFields {
        envelope_hash: *envelope_hash,
        claims_root: *claims_root,
        subject_x: *subject.x.as_bytes(),
        subject_y: *subject.y.as_bytes(),
        issuer_validity_status_signature: *issuer_validity_status_signature,
        valid_from: input.valid_from,
        valid_until: input.valid_until,
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct CurrentStatusFields {
    status_root: [u8; 32],
    status_list_id: [u8; 32],
    status_url_hash: [u8; 32],
    status_chunk: [u8; 32],
    path: [[u8; 32]; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH],
    path_length: usize,
}

fn current_status_fields(
    input: &pb::ZkPersonaCredentialEvidenceCurrentStatusInput,
) -> Result<CurrentStatusFields, ZkError> {
    let path_length = usize::try_from(input.path_length)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if path_length != input.path.len()
        || path_length > COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let mut path = Zeroizing::new([[0_u8; 32]; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH]);
    for (index, sibling) in input.path.iter().enumerate() {
        let slot = path
            .get_mut(index)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        *slot = *fixed_bytes(sibling.value.as_slice())?;
    }
    let status_root = bytes32(&input.status_root)?;
    let status_list_id = bytes32(&input.status_list_id)?;
    let status_url_hash = bytes32(&input.status_url_hash)?;
    let status_chunk = bytes32(&input.status_chunk)?;
    Ok(CurrentStatusFields {
        status_root: *status_root,
        status_list_id: *status_list_id,
        status_url_hash: *status_url_hash,
        status_chunk: *status_chunk,
        path: core::mem::take(&mut *path),
        path_length,
    })
}

fn verify_current_status_opening(
    expected_root: &[u8; 32],
    length: u64,
    index: u64,
    chunk: &[u8; 32],
    siblings: &[[u8; 32]],
) -> Result<(), ZkError> {
    if length == 0
        || length > MAX_CURRENT_STATUS_LENGTH
        || index >= length
        || siblings.len() > COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH
        || !selected_status_bit_is_clear(chunk, index)?
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let chunk_index = index
        .checked_div(256)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let leaf_count = length
        .checked_add(255)
        .and_then(|value| value.checked_div(256))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut width = 1_u64;
    let mut expected_depth = 0_usize;
    while width < leaf_count {
        width = width
            .checked_mul(2)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        expected_depth = expected_depth
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    if expected_depth != siblings.len()
        || expected_depth > COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let mut current = status_leaf(chunk);
    for (level, sibling) in siblings.iter().enumerate() {
        let shift =
            u32::try_from(level).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        current = if (chunk_index >> shift) & 1 == 0 {
            status_node(&current, sibling)
        } else {
            status_node(sibling, &current)
        };
    }
    if status_root(length, &current) != *expected_root {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

fn selected_status_bit_is_clear(chunk: &[u8; 32], index: u64) -> Result<bool, ZkError> {
    let offset = index
        .checked_rem(256)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let byte_index =
        usize::try_from(offset / 8).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let shift =
        u32::try_from(offset % 8).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let byte = chunk
        .get(byte_index)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    Ok(byte & (1_u8 << shift) == 0)
}

fn status_leaf(chunk: &[u8; 32]) -> [u8; 32] {
    // The leaf preimage contains the holder's private status chunk. Keep its
    // stack owner zeroizing even though the hash output is public.
    let mut preimage = Zeroizing::new([0_u8; 38]);
    preimage[..6].copy_from_slice(b"RMCSL1");
    preimage[6..].copy_from_slice(chunk);
    sha256(&preimage[..]).into_bytes()
}

fn status_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Zeroizing::new([0_u8; 70]);
    preimage[..6].copy_from_slice(b"RMCSN1");
    preimage[6..38].copy_from_slice(left);
    preimage[38..].copy_from_slice(right);
    sha256(&preimage[..]).into_bytes()
}

fn status_root(length: u64, top: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Zeroizing::new([0_u8; 46]);
    preimage[..6].copy_from_slice(b"RMCSR1");
    preimage[6..14].copy_from_slice(&length.to_be_bytes());
    preimage[14..].copy_from_slice(top);
    sha256(&preimage[..]).into_bytes()
}
