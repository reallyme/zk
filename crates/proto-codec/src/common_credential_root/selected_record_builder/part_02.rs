// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn root_attestation_operation(
    input: &BuildContext<'_>,
    composer: &mut reallyme_zk_api::common_root::ZkCommonCredentialRootStageInputComposer,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    let mut material = match composer
        .compose_stage(ZkCommonCredentialRootProofSlot::RootAttestation)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?
    {
        ZkCommonCredentialRootStageInputMaterial::RootAttestation(material) => material,
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    };
    let mut salt = Zeroizing::new([0_u8; 32]);
    material
        .copy_join_salt_once(&mut salt)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    require_bytes64_nonzero(input.holder_assurance.signature())?;
    let operation = stage_operation(
        input,
        ZkCommonCredentialRootProofSlot::RootAttestation,
        pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(Box::new(
            pb::ZkCommonCredentialRootAttestationInput {
                presentation: presentation_context(input),
                reallyme_public_key: input_key(input.holder_assurance.signer()),
                assurance_policy_id: bytes32(input.holder_assurance.assurance_policy_id()),
                request_unix: input.request_time_unix,
                root_join: bytes32(material.root_join()),
                attestation_join: bytes32(material.attestation_join()),
                root: bytes32(*input.holder_assurance.root()),
                attestation_issued_unix: input.holder_assurance.issued_unix(),
                attestation_expires_unix: input.holder_assurance.expires_unix(),
                attestation_epoch: input.holder_assurance.epoch(),
                attestation_signature: bytes64_p256_witness(input.holder_assurance.signature())?,
                join_salt: bytes32_from_owned(*salt),
                __buffa_unknown_fields: Default::default(),
            },
        )),
    );
    Ok(operation)
}

fn root_status_operation(
    input: &BuildContext<'_>,
    composer: &mut reallyme_zk_api::common_root::ZkCommonCredentialRootStageInputComposer,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    let mut material = match composer
        .compose_stage(ZkCommonCredentialRootProofSlot::RootStatus)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?
    {
        ZkCommonCredentialRootStageInputMaterial::RootStatus(material) => material,
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    };
    let mut salt = Zeroizing::new([0_u8; 32]);
    material
        .copy_join_salt_once(&mut salt)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let status_path_length = path_len(input.holder_assurance.siblings().len())?;
    let operation = stage_operation(
        input,
        ZkCommonCredentialRootProofSlot::RootStatus,
        pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(Box::new(
            pb::ZkCommonCredentialRootStatusInput {
                presentation: presentation_context(input),
                active_status_root: bytes32(input.active_status_snapshot.root()),
                root_join: bytes32(material.root_join()),
                attestation_join: bytes32(material.attestation_join()),
                root: bytes32(*input.holder_assurance.root()),
                attestation_id: bytes32(*input.holder_assurance.attestation_id()),
                join_salt: bytes32_from_owned(*salt),
                status_index: input.holder_assurance.status_index(),
                status_path: MessageField::some(pb::ZkInputCommonCredentialRootStatusPath {
                    path_length: status_path_length,
                    siblings: input
                        .holder_assurance
                        .siblings()
                        .iter()
                        .copied()
                        .map(bytes32_message)
                        .collect(),
                    __buffa_unknown_fields: Default::default(),
                }),
                __buffa_unknown_fields: Default::default(),
            },
        )),
    );
    Ok(operation)
}

fn lineage_operation(
    input: &BuildContext<'_>,
    composer: &mut reallyme_zk_api::common_root::ZkCommonCredentialRootStageInputComposer,
    index: usize,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    let slot = lineage_slot(index)?;
    let record = record(input, index)?;
    let mut material = match composer
        .compose_stage(slot)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?
    {
        ZkCommonCredentialRootStageInputMaterial::Lineage(material) => material,
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    };
    let lineage = lineage_opening(record)?;
    let binding = credential_binding(input, record)?;
    let mut salt = Zeroizing::new([0_u8; 32]);
    material
        .copy_join_salt_once(&mut salt)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    require_bytes64_nonzero(record.issuer_root_binding_signature)?;
    let merkle_path_length = claim_path_len(lineage.siblings().len())?;
    let operation = stage_operation(
        input,
        slot,
        pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(Box::new(
            pb::ZkCommonCredentialRootLineageInput {
                presentation: presentation_context(input),
                root_join: bytes32(material.root_join()),
                slot: MessageField::some(pb::ZkInputCommonCredentialRootLineageSlot {
                    issuer_public_key: input_key(record.issuer_public_key),
                    expiry_unix: input.presentation_expiry_unix,
                    credential_binding: bytes32(binding),
                    subject_join: bytes32(material.subject_join()),
                    __buffa_unknown_fields: Default::default(),
                }),
                root: bytes32(*input.holder_assurance.root()),
                join_salt: bytes32_from_owned(*salt),
                witness: MessageField::some(pb::ZkInputCommonCredentialRootLineageWitness {
                    envelope_hash: bytes32(record.envelope_hash),
                    merkle_root: bytes32(record.claims.root()),
                    issuer_root_binding_signature: bytes64_p256_witness(
                        record.issuer_root_binding_signature,
                    )?,
                    subject_public_key: input_key(record.subject_public_key),
                    relationship_did_hash: bytes32(record.relationship_did_hash),
                    relationship_nonce: bytes32(record.relationship_nonce),
                    claim_salt: bytes16(*lineage.salt()),
                    merkle_leaf_index: lineage.leaf_index(),
                    merkle_path: merkle_path_with_length(lineage.siblings(), merkle_path_length),
                    __buffa_unknown_fields: Default::default(),
                }),
                __buffa_unknown_fields: Default::default(),
            },
        )),
    );
    Ok(operation)
}

fn selected_claim_operation(
    input: &BuildContext<'_>,
    composer: &mut reallyme_zk_api::common_root::ZkCommonCredentialRootStageInputComposer,
    session_binding: [u8; 32],
    index: usize,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    let slot = selected_claim_slot(index)?;
    let record = record(input, index)?;
    let mut material = match composer
        .compose_stage(slot)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?
    {
        ZkCommonCredentialRootStageInputMaterial::SelectedClaim(material) => material,
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    };
    let opening = selected_claim_opening(record)?;
    let binding = credential_binding(input, record)?;
    let mut salt = Zeroizing::new([0_u8; 32]);
    material
        .copy_join_salt_once(&mut salt)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let persona_mode = input.persona_mode;
    let claim_value_length = claim_disclosure_value_length(opening)?;
    let claim_path_length = claim_path_len(opening.siblings().len())?;
    require_bytes64_nonzero(record.issuer_subject_binding_signature)?;
    require_bytes64_nonzero(record.subject_link_signature)?;
    let disclosure = claim_disclosure(binding, opening, claim_value_length);
    let proof = claim_proof(record, opening, claim_path_length);
    match persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => Ok(stage_operation(
            input,
            slot,
            pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
                Box::new(pb::ZkCommonCredentialRootPrivatePersonaClaimInput {
                    issuer_context: issuer_context(input, record),
                    session_binding: bytes32(session_binding),
                    subject_join: bytes32(material.subject_join()),
                    disclosure,
                    proof,
                    link: MessageField::some(pb::ZkInputPersonaClaimLink {
                        issuer_subject_binding_signature: bytes64_p256_witness(
                            record.issuer_subject_binding_signature,
                        )?,
                        subject_public_key: input_key(record.subject_public_key),
                        persona_public_key: input_key(input.presenter_authorization.persona_key()),
                        subject_link_signature: bytes64_p256_witness(
                            record.subject_link_signature,
                        )?,
                        __buffa_unknown_fields: Default::default(),
                    }),
                    join_salt: bytes32_from_owned(*salt),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        )),
        ZkCommonCredentialRootPersonaMode::PublicPersona => Ok(stage_operation(
            input,
            slot,
            pb::zk_common_credential_root_stage_prove_operation::Input::PublicPersonaClaim(
                Box::new(pb::ZkCommonCredentialRootPublicPersonaClaimInput {
                    issuer_context: issuer_context(input, record),
                    persona_public_key: input_key(input.presenter_authorization.persona_key()),
                    session_binding: bytes32(session_binding),
                    subject_join: bytes32(material.subject_join()),
                    disclosure,
                    proof,
                    link: MessageField::some(pb::ZkInputPublicPersonaClaimLink {
                        issuer_subject_binding_signature: bytes64_p256_witness(
                            record.issuer_subject_binding_signature,
                        )?,
                        subject_public_key: input_key(record.subject_public_key),
                        subject_link_signature: bytes64_p256_witness(
                            record.subject_link_signature,
                        )?,
                        __buffa_unknown_fields: Default::default(),
                    }),
                    join_salt: bytes32_from_owned(*salt),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        )),
    }
}

fn session_operation(
    input: &BuildContext<'_>,
    composer: &mut reallyme_zk_api::common_root::ZkCommonCredentialRootStageInputComposer,
    mode: ZkCommonCredentialRootPersonaMode,
    session_binding: [u8; 32],
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    match composer
        .compose_stage(ZkCommonCredentialRootProofSlot::Session)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?
    {
        ZkCommonCredentialRootStageInputMaterial::Session(_) => {}
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    match (&input.presenter_authorization, mode) {
        (
            ZkCommonCredentialRootPresenterAuthorization::Private {
                persona_public_key,
                persona_signature,
            },
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ) => {
            require_bytes64_nonzero(persona_signature)?;
            Ok(stage_operation(
                input,
                ZkCommonCredentialRootProofSlot::Session,
                pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaSession(
                    Box::new(pb::ZkPrivatePersonaSessionInput {
                        session_context: session_context(input, session_binding),
                        authorization: MessageField::some(pb::ZkInputPersonaSessionAuthorization {
                            persona_public_key: input_key(*persona_public_key),
                            persona_signature: bytes64_p256_witness(persona_signature)?,
                            __buffa_unknown_fields: Default::default(),
                        }),
                        __buffa_unknown_fields: Default::default(),
                    }),
                ),
            ))
        }
        (
            ZkCommonCredentialRootPresenterAuthorization::Public {
                persona_public_key,
                persona_fresh_signature,
            },
            ZkCommonCredentialRootPersonaMode::PublicPersona,
        ) => {
            require_bytes64_nonzero(persona_fresh_signature)?;
            Ok(stage_operation(
                input,
                ZkCommonCredentialRootProofSlot::Session,
                pb::zk_common_credential_root_stage_prove_operation::Input::PublicPersonaSession(
                    Box::new(pb::ZkPublicPersonaSessionInput {
                        persona_public_key: input_key(*persona_public_key),
                        session_context: session_context(input, session_binding),
                        authorization: MessageField::some(
                            pb::ZkInputPublicPersonaSessionAuthorization {
                                persona_fresh_signature: bytes64_p256_witness(
                                    persona_fresh_signature,
                                )?,
                                __buffa_unknown_fields: Default::default(),
                            },
                        ),
                        __buffa_unknown_fields: Default::default(),
                    }),
                ),
            ))
        }
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn issuer_status_operation(
    input: &BuildContext<'_>,
    composer: &mut reallyme_zk_api::common_root::ZkCommonCredentialRootStageInputComposer,
    index: usize,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, ZkError> {
    let slot = issuer_status_slot(index)?;
    let record = record(input, index)?;
    match composer
        .compose_stage(slot)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?
    {
        ZkCommonCredentialRootStageInputMaterial::IssuerCredentialStatus(_) => {}
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    let status = &record.issuer_status;
    verify_common_credential_root_issuer_status_opening(
        &status.root,
        status.length,
        status.status_index,
        status.opening,
    )
    .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let binding = credential_binding(input, record)?;
    require_bytes64_nonzero(status.issuer_validity_status_signature)?;
    let status_path_length = path_len(status.opening.siblings().len())?;
    Ok(stage_operation(
        input,
        slot,
        pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
            Box::new(pb::ZkCommonCredentialRootIssuerCredentialStatusInput {
                presentation: presentation_context(input),
                issuer_public_key: input_key(record.issuer_public_key),
                presentation_expiry: input.presentation_expiry_unix,
                credential_binding: bytes32(binding),
                status_root: bytes32(status.root),
                status_length: status.length,
                status_list_id: bytes32(status.list_id),
                status_url_hash: bytes32(status.url_hash),
                status_purpose: crate::issuer_status::purpose_to_proto(status.purpose),
                verifier_now: input.status_validation_time_unix,
                envelope_hash: bytes32(record.envelope_hash),
                claims_root: bytes32(record.claims.root()),
                issuer_validity_status_signature: bytes64_p256_witness(
                    status.issuer_validity_status_signature,
                )?,
                valid_from: status.valid_from,
                valid_until: status.valid_until,
                status_index: status.status_index,
                status_chunk: bytes32(*status.opening.chunk()),
                path_length: status_path_length,
                path: status
                    .opening
                    .siblings()
                    .iter()
                    .copied()
                    .map(bytes32_message)
                    .collect(),
                __buffa_unknown_fields: Default::default(),
            }),
        ),
    ))
}

fn stage_operation(
    input: &BuildContext<'_>,
    slot: ZkCommonCredentialRootProofSlot,
    stage_input: pb::zk_common_credential_root_stage_prove_operation::Input,
) -> pb::ZkCommonCredentialRootStageProveOperation {
    pb::ZkCommonCredentialRootStageProveOperation {
        persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto(
            input.persona_mode,
        )),
        slot: EnumValue::from(common_credential_root_slot_to_proto(slot)),
        circuit_ref: MessageField::some(circuit_ref_to_proto(
            input
                .persona_mode
                .source_ref(input.credential_hash_algorithm, slot),
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(input.proof_suite)),
        expected_binding: MessageField::some(session_binding_to_proto_message(
            input.expected_binding,
        )),
        input: Some(stage_input),
        __buffa_unknown_fields: Default::default(),
    }
}
