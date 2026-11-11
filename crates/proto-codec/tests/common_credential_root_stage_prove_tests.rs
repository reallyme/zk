// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    ZkCircuitFamily as ProtoCircuitFamily, ZkCircuitRef as ProtoCircuitRef,
    ZkCircuitStage as ProtoCircuitStage,
    ZkCommonCredentialRootPersonaMode as ProtoCommonCredentialRootProfile,
    ZkCommonCredentialRootProofSlot as ProtoCommonCredentialRootProofSlot,
    ZkCredentialHashAlgorithm as ProtoCredentialHashAlgorithm, ZkProofSuite as ProtoProofSuite,
    ZkSessionBinding as ProtoSessionBinding,
};
use reallyme_zk_proto_codec::operation::{decode_operation_request, ZkProviderOperation};

fn proto_ref(circuit_ref: ZkCircuitRef) -> ProtoCircuitRef {
    let family = match circuit_ref.family {
        ZkCircuitFamily::PrivatePersonaClaimV1 => {
            ProtoCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
        }
        ZkCircuitFamily::CommonCredentialRootV1 => {
            ProtoCircuitFamily::ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1
        }
        _ => ProtoCircuitFamily::ZK_CIRCUIT_FAMILY_UNSPECIFIED,
    };
    let stage = match circuit_ref.stage {
        ZkCircuitStage::Session => ProtoCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        ZkCircuitStage::PublicSession => ProtoCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_SESSION,
        ZkCircuitStage::RootAttestation => ProtoCircuitStage::ZK_CIRCUIT_STAGE_ROOT_ATTESTATION,
        ZkCircuitStage::RootStatus => ProtoCircuitStage::ZK_CIRCUIT_STAGE_ROOT_STATUS,
        ZkCircuitStage::Lineage => ProtoCircuitStage::ZK_CIRCUIT_STAGE_LINEAGE,
        ZkCircuitStage::IssuerCredentialStatus => {
            ProtoCircuitStage::ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS
        }
        ZkCircuitStage::PrivatePersonaClaim => {
            ProtoCircuitStage::ZK_CIRCUIT_STAGE_PRIVATE_PERSONA_CLAIM
        }
        ZkCircuitStage::PublicPersonaClaim => {
            ProtoCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_PERSONA_CLAIM
        }
        _ => ProtoCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED,
    };

    ProtoCircuitRef {
        credential_hash_algorithm: EnumValue::from(
            ProtoCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2,
        ),
        family: EnumValue::from(family),
        stage: EnumValue::from(stage),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_profile(
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> ProtoCommonCredentialRootProfile {
    match persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            ProtoCommonCredentialRootProfile::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            ProtoCommonCredentialRootProfile::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PUBLIC_PERSONA_V1
        }
    }
}

fn proto_slot(slot: ZkCommonCredentialRootProofSlot) -> ProtoCommonCredentialRootProofSlot {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION
        }
        ZkCommonCredentialRootProofSlot::RootStatus => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS
        }
        ZkCommonCredentialRootProofSlot::Lineage0 => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_0
        }
        ZkCommonCredentialRootProofSlot::Lineage1 => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_LINEAGE_1
        }
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0
        }
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_1
        }
        ZkCommonCredentialRootProofSlot::Session => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_1
        }
        _ => ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_UNSPECIFIED,
    }
}

fn input_bytes32(byte: u8) -> pb::ZkInputBytes32 {
    pb::ZkInputBytes32 {
        value: vec![byte; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn input_presentation() -> pb::ZkInputPresentationContext {
    pb::ZkInputPresentationContext {
        challenge: MessageField::some(input_bytes32(1)),
        audience_hash: MessageField::some(input_bytes32(2)),
        transaction_data_hash: MessageField::some(input_bytes32(3)),
        expiry_unix: 1_800_000_120,
        __buffa_unknown_fields: Default::default(),
    }
}

fn session_binding() -> ProtoSessionBinding {
    ProtoSessionBinding {
        nonce_hash: vec![1; 32],
        audience_hash: vec![2; 32],
        transaction_data_hash: vec![3; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn common_credential_root_stage_request(
    input: pb::zk_common_credential_root_stage_prove_operation::Input,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<Vec<u8>, ZkError> {
    let circuit_ref = persona_mode.source_ref(ZkCredentialHashAlgorithm::Poseidon2, slot);
    let request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(
                Box::new(pb::ZkCommonCredentialRootStageProveOperation {
                    persona_mode: EnumValue::from(proto_profile(persona_mode)),
                    slot: EnumValue::from(proto_slot(slot)),
                    circuit_ref: MessageField::some(proto_ref(circuit_ref)),
                    proof_suite: EnumValue::from(
                        ProtoProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                    ),
                    expected_binding: MessageField::some(session_binding()),
                    input: Some(input),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let mut encoded = Vec::new();
    request
        .try_encode_bounded(u32::MAX, &mut encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

fn root_status_input(join_salt: u8) -> pb::zk_common_credential_root_stage_prove_operation::Input {
    pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(Box::new(
        pb::ZkCommonCredentialRootStatusInput {
            presentation: MessageField::some(input_presentation()),
            active_status_root: MessageField::some(input_bytes32(4)),
            root_join: MessageField::some(input_bytes32(5)),
            attestation_join: MessageField::some(input_bytes32(6)),
            root: MessageField::some(input_bytes32(7)),
            attestation_id: MessageField::some(input_bytes32(8)),
            join_salt: MessageField::some(input_bytes32(join_salt)),
            status_index: 0,
            status_path: MessageField::some(pb::ZkInputCommonCredentialRootStatusPath {
                path_length: 0,
                siblings: Vec::new(),
                __buffa_unknown_fields: Default::default(),
            }),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

fn issuer_status_input() -> pb::ZkCommonCredentialRootIssuerCredentialStatusInput {
    pb::ZkCommonCredentialRootIssuerCredentialStatusInput {
        presentation: MessageField::some(input_presentation()),
        issuer_public_key: MessageField::some(pb::ZkInputP256PublicKey {
            x: MessageField::some(input_bytes32(4)),
            y: MessageField::some(input_bytes32(5)),
            __buffa_unknown_fields: Default::default(),
        }),
        presentation_expiry: 1800000120,
        credential_binding: MessageField::some(input_bytes32(6)),
        status_root: MessageField::some(input_bytes32(7)),
        status_length: 8,
        status_list_id: MessageField::some(input_bytes32(8)),
        status_url_hash: MessageField::some(input_bytes32(9)),
        status_purpose: buffa::EnumValue::from(reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION),
        verifier_now: 1800000000,
        envelope_hash: MessageField::some(input_bytes32(10)),
        claims_root: MessageField::some(input_bytes32(11)),
        issuer_validity_status_signature: MessageField::some(pb::ZkInputBytes64 {
            value: vec![12; 64],
            __buffa_unknown_fields: Default::default(),
        }),
        valid_from: 1700000000,
        valid_until: 1900000000,
        status_index: 3,
        status_chunk: MessageField::some(input_bytes32(0)),
        path_length: 0,
        path: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn common_credential_root_stage_prove_operation_decodes_root_status_owner() -> Result<(), ZkError> {
    let encoded = common_credential_root_stage_request(
        root_status_input(9),
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::RootStatus,
    )?;

    let operation = decode_operation_request(encoded.as_slice())?;
    match operation {
        ZkProviderOperation::ProveCommonCredentialRootStage { plan, .. } => {
            assert_eq!(plan.slot(), ZkCommonCredentialRootProofSlot::RootStatus);
            assert_eq!(
                plan.circuit_ref(),
                ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
                    ZkCredentialHashAlgorithm::Poseidon2,
                    ZkCommonCredentialRootProofSlot::RootStatus
                )
            );
        }
        _ => return Err(ZkError::new(ZkErrorReason::MissingOperation)),
    }
    Ok(())
}

#[test]
fn issuer_status_stage_owns_private_witness_and_rejects_invalid_index() -> Result<(), ZkError> {
    let persona_mode = ZkCommonCredentialRootPersonaMode::PrivatePersona;
    let slot = ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0;
    let valid = common_credential_root_stage_request(
        pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
            Box::new(issuer_status_input()),
        ),
        persona_mode,
        slot,
    )?;
    match decode_operation_request(valid.as_slice())? {
        ZkProviderOperation::ProveCommonCredentialRootStage { plan, .. } => {
            assert_eq!(plan.slot(), slot);
            assert_eq!(
                plan.circuit_ref().stage,
                ZkCircuitStage::IssuerCredentialStatus
            );
        }
        _ => return Err(ZkError::new(ZkErrorReason::MissingOperation)),
    }

    let mut invalid = issuer_status_input();
    invalid.status_index = invalid.status_length;
    let bytes = common_credential_root_stage_request(
        pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
            Box::new(invalid),
        ),
        persona_mode,
        slot,
    )?;
    assert!(matches!(
        decode_operation_request(bytes.as_slice()),
        Err(error) if error.reason() == ZkErrorReason::InvalidProofEncoding
    ));

    // The wire path contains only active siblings. Fixed-size witness padding
    // is added after decoding and must never be accepted in the request.
    let mut padded = issuer_status_input();
    padded.path.push(input_bytes32(0));
    let bytes = common_credential_root_stage_request(
        pb::zk_common_credential_root_stage_prove_operation::Input::IssuerCredentialStatus(
            Box::new(padded),
        ),
        persona_mode,
        slot,
    )?;
    assert!(matches!(
        decode_operation_request(bytes.as_slice()),
        Err(error) if error.reason() == ZkErrorReason::InvalidProofEncoding
    ));
    Ok(())
}

#[test]
fn common_credential_root_stage_prove_operation_rejects_wrong_input_branch() -> Result<(), ZkError>
{
    let encoded = common_credential_root_stage_request(
        root_status_input(9),
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    )?;

    assert!(matches!(
        decode_operation_request(encoded.as_slice()),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_stage_prove_operation_rejects_zero_join_salt() -> Result<(), ZkError> {
    let encoded = common_credential_root_stage_request(
        root_status_input(0),
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::RootStatus,
    )?;

    assert!(matches!(
        decode_operation_request(encoded.as_slice()),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));
    Ok(())
}

#[path = "common_credential_root_stage_prove_tests/claim_path_depth_tests.rs"]
mod claim_path_depth_tests;
