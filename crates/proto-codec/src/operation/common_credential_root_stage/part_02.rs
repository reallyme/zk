// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_common_credential_root_status_path(
    field: &MessageField<
        pb::ZkInputCommonCredentialRootStatusPath,
        buffa::Inline<pb::ZkInputCommonCredentialRootStatusPath>,
    >,
) -> Result<(), ZkError> {
    let path = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_path_len_and_siblings(
        path.path_length,
        path.siblings.len(),
        ZK_INPUT_MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH,
    )?;
    for sibling in &path.siblings {
        validate_exact_bytes(sibling.value.as_slice(), ZK_INPUT_BYTES_32)?;
    }
    Ok(())
}

fn validate_path_len_and_siblings(
    path_length: u32,
    sibling_count: usize,
    maximum_depth: usize,
) -> Result<(), ZkError> {
    let active_len =
        usize::try_from(path_length).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if active_len > maximum_depth || sibling_count > maximum_depth {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    if sibling_count != active_len {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
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
    validate_bytes64(&link.subject_link_signature)
}

fn validate_public_persona_claim_link(
    field: &MessageField<
        pb::ZkInputPublicPersonaClaimLink,
        buffa::Inline<pb::ZkInputPublicPersonaClaimLink>,
    >,
) -> Result<(), ZkError> {
    let link = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes64(&link.issuer_subject_binding_signature)?;
    validate_p256_public_key(&link.subject_public_key)?;
    validate_bytes64(&link.subject_link_signature)
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
    validate_bytes64(&authorization.persona_signature)
}

fn validate_public_persona_session_authorization(
    field: &MessageField<
        pb::ZkInputPublicPersonaSessionAuthorization,
        buffa::Inline<pb::ZkInputPublicPersonaSessionAuthorization>,
    >,
) -> Result<(), ZkError> {
    let authorization = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    validate_bytes64(&authorization.persona_fresh_signature)
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
    bytes32(field).map(|_bytes| ())
}

fn validate_join_salt(
    field: &MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<(), ZkError> {
    let salt = bytes32(field)?;
    if salt.iter().all(|byte| *byte == 0) {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(())
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
) -> Result<(), ZkError> {
    bytes64(field).map(|_bytes| ())
}

fn bytes32(
    field: &MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<[u8; ZK_INPUT_BYTES_32], ZkError> {
    let bytes = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    bytes
        .value
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

fn bytes64(
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

fn expected_binding_from_common_credential_root_input(
    input: &pb::zk_common_credential_root_stage_prove_operation::Input,
) -> Result<ZkSessionBinding, ZkError> {
    use pb::zk_common_credential_root_stage_prove_operation::Input;

    match input {
        Input::RootAttestation(input) => binding_from_presentation_context(&input.presentation),
        Input::RootStatus(input) => binding_from_presentation_context(&input.presentation),
        Input::IssuerCredentialStatus(input) => {
            binding_from_presentation_context(&input.presentation)
        }
        Input::Lineage(input) => binding_from_presentation_context(&input.presentation),
        Input::PrivatePersonaClaim(input) => binding_from_issuer_context(&input.issuer_context),
        Input::PublicPersonaClaim(input) => binding_from_issuer_context(&input.issuer_context),
        Input::PrivatePersonaSession(input) => binding_from_session_context(&input.session_context),
        Input::PublicPersonaSession(input) => binding_from_session_context(&input.session_context),
    }
}

fn presentation_expiry_unix_from_common_credential_root_input(
    input: &pb::zk_common_credential_root_stage_prove_operation::Input,
) -> Result<u64, ZkError> {
    use pb::zk_common_credential_root_stage_prove_operation::Input;

    match input {
        Input::RootAttestation(input) => {
            presentation_expiry_unix_from_presentation_context(&input.presentation)
        }
        Input::RootStatus(input) => {
            presentation_expiry_unix_from_presentation_context(&input.presentation)
        }
        Input::IssuerCredentialStatus(input) => {
            presentation_expiry_unix_from_presentation_context(&input.presentation)
        }
        Input::Lineage(input) => {
            presentation_expiry_unix_from_presentation_context(&input.presentation)
        }
        Input::PrivatePersonaClaim(input) => {
            presentation_expiry_unix_from_issuer_context(&input.issuer_context)
        }
        Input::PublicPersonaClaim(input) => {
            presentation_expiry_unix_from_issuer_context(&input.issuer_context)
        }
        Input::PrivatePersonaSession(input) => {
            presentation_expiry_unix_from_session_context(&input.session_context)
        }
        Input::PublicPersonaSession(input) => {
            presentation_expiry_unix_from_session_context(&input.session_context)
        }
    }
}

fn presentation_expiry_unix_from_presentation_context(
    field: &MessageField<
        pb::ZkInputPresentationContext,
        buffa::Inline<pb::ZkInputPresentationContext>,
    >,
) -> Result<u64, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(context.expiry_unix)
}

fn presentation_expiry_unix_from_session_context(
    field: &MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>>,
) -> Result<u64, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(context.expiry_unix)
}

fn presentation_expiry_unix_from_issuer_context(
    field: &MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>>,
) -> Result<u64, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(context.expiry_unix)
}

fn binding_from_presentation_context(
    field: &MessageField<
        pb::ZkInputPresentationContext,
        buffa::Inline<pb::ZkInputPresentationContext>,
    >,
) -> Result<ZkSessionBinding, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkSessionBinding {
        nonce_hash: bytes32(&context.challenge)?,
        audience_hash: bytes32(&context.audience_hash)?,
        transaction_data_hash: optional_transaction_hash(bytes32(&context.transaction_data_hash)?),
    })
}

fn binding_from_session_context(
    field: &MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>>,
) -> Result<ZkSessionBinding, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkSessionBinding {
        nonce_hash: bytes32(&context.challenge)?,
        audience_hash: bytes32(&context.audience_hash)?,
        transaction_data_hash: optional_transaction_hash(bytes32(&context.transaction_data_hash)?),
    })
}

fn binding_from_issuer_context(
    field: &MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>>,
) -> Result<ZkSessionBinding, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkSessionBinding {
        nonce_hash: bytes32(&context.challenge)?,
        audience_hash: bytes32(&context.audience_hash)?,
        transaction_data_hash: optional_transaction_hash(bytes32(&context.transaction_data_hash)?),
    })
}

fn optional_transaction_hash(hash: [u8; ZK_INPUT_BYTES_32]) -> Option<[u8; ZK_INPUT_BYTES_32]> {
    if hash == ABSENT_TRANSACTION_DATA_HASH {
        None
    } else {
        Some(hash)
    }
}

pub(super) fn zeroize_common_credential_root_stage_input_proto(
    input: &mut pb::zk_common_credential_root_stage_prove_operation::Input,
) {
    use pb::zk_common_credential_root_stage_prove_operation::Input;

    match input {
        Input::RootAttestation(input) => input.clear(),
        Input::RootStatus(input) => zeroize_root_status_input(input),
        Input::IssuerCredentialStatus(input) => zeroize_issuer_credential_status_input(input),
        Input::Lineage(input) => zeroize_lineage_input(input),
        Input::PrivatePersonaClaim(input) => zeroize_private_persona_claim_input(input),
        Input::PublicPersonaClaim(input) => zeroize_public_persona_claim_input(input),
        Input::PrivatePersonaSession(input) => input.clear(),
        Input::PublicPersonaSession(input) => input.clear(),
    }
}

fn zeroize_root_status_input(input: &mut pb::ZkCommonCredentialRootStatusInput) {
    if let Some(mut status_path) = input.status_path.take() {
        status_path.clear();
    }
    input.clear();
}

fn zeroize_issuer_credential_status_input(
    input: &mut pb::ZkCommonCredentialRootIssuerCredentialStatusInput,
) {
    use zeroize::Zeroize;

    if let Some(mut presentation) = input.presentation.take() {
        wipe_bytes32(&mut presentation.challenge);
        wipe_bytes32(&mut presentation.audience_hash);
        wipe_bytes32(&mut presentation.transaction_data_hash);
    }
    if let Some(mut issuer) = input.issuer_public_key.take() {
        wipe_bytes32(&mut issuer.x);
        wipe_bytes32(&mut issuer.y);
    }
    wipe_bytes32(&mut input.credential_binding);
    wipe_bytes32(&mut input.status_root);
    wipe_bytes32(&mut input.status_list_id);
    wipe_bytes32(&mut input.status_url_hash);
    wipe_bytes32(&mut input.envelope_hash);
    wipe_bytes32(&mut input.claims_root);
    if let Some(mut signature) = input.issuer_validity_status_signature.take() {
        signature.value.zeroize();
    }
    wipe_bytes32(&mut input.status_chunk);
    for sibling in &mut input.path {
        sibling.value.zeroize();
    }
    input.path.clear();
    input.status_index.zeroize();
}

fn zeroize_lineage_input(input: &mut pb::ZkCommonCredentialRootLineageInput) {
    if let Some(mut witness) = input.witness.take() {
        witness.clear();
    }
    input.clear();
}

fn zeroize_private_persona_claim_input(
    input: &mut pb::ZkCommonCredentialRootPrivatePersonaClaimInput,
) {
    zeroize_claim_disclosure_and_proof(&mut input.disclosure, &mut input.proof);
    input.clear();
}

fn zeroize_public_persona_claim_input(
    input: &mut pb::ZkCommonCredentialRootPublicPersonaClaimInput,
) {
    zeroize_claim_disclosure_and_proof(&mut input.disclosure, &mut input.proof);
    input.clear();
}

fn zeroize_claim_disclosure_and_proof(
    disclosure: &mut MessageField<
        pb::ZkInputClaimDisclosure,
        buffa::Inline<pb::ZkInputClaimDisclosure>,
    >,
    proof: &mut MessageField<
        pb::ZkInputMerkleClaimProof,
        buffa::Inline<pb::ZkInputMerkleClaimProof>,
    >,
) {
    if let Some(mut disclosure) = disclosure.take() {
        disclosure.clear();
    }
    if let Some(mut proof) = proof.take() {
        proof.clear();
    }
}

fn wipe_bytes32(field: &mut MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>) {
    use zeroize::Zeroize;
    if let Some(mut value) = field.take() {
        value.value.zeroize();
    }
}
