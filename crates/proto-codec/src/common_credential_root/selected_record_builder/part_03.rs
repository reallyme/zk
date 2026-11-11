// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn credential_binding(
    input: &BuildContext<'_>,
    record: &ZkCommonCredentialRootSelectedCredentialRecord<'_>,
) -> Result<[u8; 32], ZkError> {
    if record.claims.credential_hash_algorithm() != input.credential_hash_algorithm {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    derive_common_credential_root_credential_binding(
        input.credential_hash_algorithm,
        ZkCommonCredentialRootCredentialBindingInputs {
            issuer_key: record.issuer_public_key,
            envelope_hash: record.envelope_hash,
            claims_root: record.claims.root(),
            request: request_context(input.expected_binding),
            expiry_unix: input.presentation_expiry_unix,
        },
    )
}

fn persona_session_binding(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    mode: ZkCommonCredentialRootPersonaMode,
    persona_key: ZkIssuerPublicKey,
    request: ZkCommonCredentialRootRequestJoinContext,
    expiry_unix: u64,
) -> Result<[u8; 32], ZkError> {
    let subject = ZkCommonCredentialRootSubjectPublicKey {
        x: persona_key.x,
        y: persona_key.y,
    };
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            Ok(common_credential_root_sha256_persona_session_binding(
                mode,
                subject,
                request,
                expiry_unix,
            ))
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            common_credential_root_poseidon2_persona_session_binding(
                mode,
                subject,
                request,
                expiry_unix,
            )
        }
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

fn subject_key(key: ZkIssuerPublicKey) -> ZkCommonCredentialRootSubjectPublicKey {
    ZkCommonCredentialRootSubjectPublicKey { x: key.x, y: key.y }
}

fn lineage_opening<'a>(
    record: &'a ZkCommonCredentialRootSelectedCredentialRecord<'a>,
) -> Result<&'a ZkCommonCredentialRootClaimOpening, ZkError> {
    record
        .claims
        .openings()
        .first()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))
}

fn selected_claim_opening<'a>(
    record: &'a ZkCommonCredentialRootSelectedCredentialRecord<'a>,
) -> Result<&'a ZkCommonCredentialRootClaimOpening, ZkError> {
    if record.selected_claim_index == 0 {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    record
        .claims
        .openings()
        .get(record.selected_claim_index)
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))
}

fn issuer_context(
    input: &BuildContext<'_>,
    record: &ZkCommonCredentialRootSelectedCredentialRecord<'_>,
) -> MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>> {
    let request = request_context(input.expected_binding);
    MessageField::some(pb::ZkInputIssuerContext {
        issuer_public_key: input_key(record.issuer_public_key),
        challenge: bytes32(request.challenge),
        audience_hash: bytes32(request.audience_hash),
        expiry_unix: input.presentation_expiry_unix,
        transaction_data_hash: bytes32(request.transaction_data_hash),
        __buffa_unknown_fields: Default::default(),
    })
}

fn presentation_context(
    input: &BuildContext<'_>,
) -> MessageField<pb::ZkInputPresentationContext, buffa::Inline<pb::ZkInputPresentationContext>> {
    let request = request_context(input.expected_binding);
    MessageField::some(pb::ZkInputPresentationContext {
        challenge: bytes32(request.challenge),
        audience_hash: bytes32(request.audience_hash),
        transaction_data_hash: bytes32(request.transaction_data_hash),
        expiry_unix: input.presentation_expiry_unix,
        __buffa_unknown_fields: Default::default(),
    })
}

fn session_context(
    input: &BuildContext<'_>,
    session_binding: [u8; 32],
) -> MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>> {
    let request = request_context(input.expected_binding);
    MessageField::some(pb::ZkInputSessionContext {
        challenge: bytes32(request.challenge),
        audience_hash: bytes32(request.audience_hash),
        expiry_unix: input.presentation_expiry_unix,
        session_binding: bytes32(session_binding),
        transaction_data_hash: bytes32(request.transaction_data_hash),
        __buffa_unknown_fields: Default::default(),
    })
}

fn claim_disclosure(
    credential_binding: [u8; 32],
    opening: &ZkCommonCredentialRootClaimOpening,
    value_length: u32,
) -> MessageField<pb::ZkInputClaimDisclosure, buffa::Inline<pb::ZkInputClaimDisclosure>> {
    let value = opening.value();
    let mut padded = Zeroizing::new([0_u8; CLAIM_VALUE_BYTES]);
    padded[..value.len()].copy_from_slice(value);
    MessageField::some(pb::ZkInputClaimDisclosure {
        credential_binding: bytes32(credential_binding),
        value_length,
        value: bytes64_any(&padded),
        claim_name_hash: bytes32(opening.name_hash()),
        __buffa_unknown_fields: Default::default(),
    })
}

fn claim_proof(
    record: &ZkCommonCredentialRootSelectedCredentialRecord<'_>,
    opening: &ZkCommonCredentialRootClaimOpening,
    path_length: u32,
) -> MessageField<pb::ZkInputMerkleClaimProof, buffa::Inline<pb::ZkInputMerkleClaimProof>> {
    let path = merkle_path_with_length(opening.siblings(), path_length);
    MessageField::some(pb::ZkInputMerkleClaimProof {
        envelope_hash: bytes32(record.envelope_hash),
        merkle_root: bytes32(record.claims.root()),
        claim_salt: bytes16(*opening.salt()),
        leaf_index: opening.leaf_index(),
        path,
        __buffa_unknown_fields: Default::default(),
    })
}

fn claim_disclosure_value_length(
    opening: &ZkCommonCredentialRootClaimOpening,
) -> Result<u32, ZkError> {
    let value = opening.value();
    if value.is_empty() || value.len() > CLAIM_VALUE_BYTES {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    u32::try_from(value.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))
}

fn merkle_path_with_length(
    siblings: &[[u8; 32]],
    path_length: u32,
) -> MessageField<pb::ZkInputMerklePath, buffa::Inline<pb::ZkInputMerklePath>> {
    MessageField::some(pb::ZkInputMerklePath {
        path_length,
        siblings: siblings.iter().copied().map(bytes32_message).collect(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn request_context(binding: ZkSessionBinding) -> ZkCommonCredentialRootRequestJoinContext {
    ZkCommonCredentialRootRequestJoinContext {
        challenge: binding.nonce_hash,
        audience_hash: binding.audience_hash,
        transaction_data_hash: binding.transaction_data_public_input(),
    }
}

fn record<'a>(
    input: &'a BuildContext<'_>,
    index: usize,
) -> Result<&'a ZkCommonCredentialRootSelectedCredentialRecord<'a>, ZkError> {
    input
        .records
        .get(index)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))
}

const fn lineage_slot(index: usize) -> Result<ZkCommonCredentialRootProofSlot, ZkError> {
    match index {
        0 => Ok(ZkCommonCredentialRootProofSlot::Lineage0),
        1 => Ok(ZkCommonCredentialRootProofSlot::Lineage1),
        _ => Err(ZkError::new(ZkErrorReason::LengthOverflow)),
    }
}

const fn selected_claim_slot(index: usize) -> Result<ZkCommonCredentialRootProofSlot, ZkError> {
    match index {
        0 => Ok(ZkCommonCredentialRootProofSlot::SelectedClaim0),
        1 => Ok(ZkCommonCredentialRootProofSlot::SelectedClaim1),
        _ => Err(ZkError::new(ZkErrorReason::LengthOverflow)),
    }
}

const fn issuer_status_slot(index: usize) -> Result<ZkCommonCredentialRootProofSlot, ZkError> {
    match index {
        0 => Ok(ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0),
        1 => Ok(ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1),
        _ => Err(ZkError::new(ZkErrorReason::LengthOverflow)),
    }
}

fn path_len(len: usize) -> Result<u32, ZkError> {
    u32::try_from(len).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))
}

/// A selected claim or lineage opening must carry the full fixed-depth claim
/// path; anything else cannot satisfy the claim circuits.
fn claim_path_len(len: usize) -> Result<u32, ZkError> {
    if !crate::claim_tree::is_claim_tree_depth(len) {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    path_len(len)
}

fn input_key(
    key: impl Into<reallyme_zk_api::keys::ZkP256PublicKey>,
) -> MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>> {
    let key = key.into();
    MessageField::some(pb::ZkInputP256PublicKey {
        x: bytes32(key.x),
        y: bytes32(key.y),
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes32(value: [u8; 32]) -> MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>> {
    MessageField::some(bytes32_message(value))
}

fn bytes32_from_owned(
    value: [u8; 32],
) -> MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>> {
    bytes32(value)
}

fn bytes32_message(value: [u8; 32]) -> pb::ZkInputBytes32 {
    pb::ZkInputBytes32 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn bytes16(value: [u8; 16]) -> MessageField<pb::ZkInputBytes16, buffa::Inline<pb::ZkInputBytes16>> {
    MessageField::some(pb::ZkInputBytes16 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn require_bytes64_nonzero(value: &[u8; SIGNATURE_BYTES]) -> Result<(), ZkError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

fn bytes64_any(
    value: &[u8; SIGNATURE_BYTES],
) -> MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>> {
    MessageField::some(pb::ZkInputBytes64 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes64_p256_witness(
    value: &[u8; SIGNATURE_BYTES],
) -> Result<MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>, ZkError> {
    require_bytes64_nonzero(value)?;
    let normalized = normalize_common_credential_root_p256_signature_low_s(*value)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    Ok(MessageField::some(pb::ZkInputBytes64 {
        value: normalized.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }))
}
