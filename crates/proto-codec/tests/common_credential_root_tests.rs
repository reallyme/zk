// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootRawPublicInputs,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    ZkCircuitFamily as ProtoCircuitFamily, ZkCircuitRef as ProtoCircuitRef,
    ZkCircuitStage as ProtoCircuitStage,
    ZkCommonCredentialRootClaimExpectation as ProtoCommonCredentialRootClaimExpectation,
    ZkCommonCredentialRootJoinPolicy as ProtoCommonCredentialRootJoinPolicy,
    ZkCommonCredentialRootPersonaMode as ProtoCommonCredentialRootProfile,
    ZkCommonCredentialRootPresentation as ProtoCommonCredentialRootPresentation,
    ZkCommonCredentialRootProofSlot as ProtoCommonCredentialRootProofSlot,
    ZkCommonCredentialRootRawProofPackage as ProtoCommonCredentialRootRawProofPackage,
    ZkCommonCredentialRootRawPublicInputs as ProtoCommonCredentialRootRawPublicInputs,
    ZkCredentialHashAlgorithm as ProtoCredentialHashAlgorithm,
    ZkP256PublicKey as ProtoIssuerPublicKey, ZkProofSuite as ProtoProofSuite,
    ZkSessionBinding as ProtoSessionBinding,
};
use reallyme_zk_proto_codec::common_credential_root::{
    common_credential_root_witness_plan, common_credential_root_witness_plan_for_circuit,
    decode_common_credential_root_raw_public_inputs,
    encode_common_credential_root_raw_public_inputs, ZkCommonCredentialRootPresentation,
};

#[path = "common_credential_root_tests/canonical_admission.rs"]
mod canonical_admission;
use canonical_admission::{admit_presentation, admit_raw_public_inputs};

const REQUEST_TIME: u64 = 1;
const EXPIRY: u64 = 181;
const ROOT_JOIN: [u8; 32] = [0x44; 32];
const ATTESTATION_JOIN: [u8; 32] = [0x55; 32];
const SESSION_BINDING: [u8; 32] = [0x88; 32];

fn raw_inputs(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<ZkCommonCredentialRootRawPublicInputs, ZkError> {
    let circuit_ref = persona_mode.source_ref(ZkCredentialHashAlgorithm::Poseidon2, slot);
    ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        circuit_ref,
        canonical_raw(circuit_ref, slot),
    )
}

fn canonical_raw(circuit_ref: ZkCircuitRef, slot: ZkCommonCredentialRootProofSlot) -> Vec<u8> {
    let fields = match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => 258,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus) => 192,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => 257,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => 292,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => 354,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => 418,
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => 129,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => 193,
        _ => 0,
    };
    let mut raw = vec![0_u8; fields * 32];
    let request_start = match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => 98,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus)
        | (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => 0,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => 64,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => 128,
        _ => 0,
    };
    set_request(&mut raw, request_start);
    match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => {
            set_key(&mut raw, 0, issuer(21));
            set_bytes(&mut raw, 64, &[4; 32]);
            set_u64(&mut raw, 96, REQUEST_TIME);
            set_u64(&mut raw, 97, EXPIRY);
            set_bytes(&mut raw, 194, &ROOT_JOIN);
            set_bytes(&mut raw, 226, &ATTESTATION_JOIN);
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus) => {
            set_bytes(&mut raw, 96, &[5; 32]);
            set_bytes(&mut raw, 128, &ROOT_JOIN);
            set_bytes(&mut raw, 160, &ATTESTATION_JOIN);
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => {
            set_bytes(&mut raw, 96, &ROOT_JOIN);
            set_key(&mut raw, 128, credential_issuer(slot));
            set_u64(&mut raw, 192, EXPIRY);
            set_bytes(&mut raw, 193, &credential_binding(slot));
            set_bytes(&mut raw, 225, &subject_join(slot));
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => {
            set_key(&mut raw, 96, credential_issuer(slot));
            set_u64(&mut raw, 160, EXPIRY);
            set_bytes(&mut raw, 161, &credential_binding(slot));
            set_bytes(&mut raw, 193, &status_root(slot));
            set_u64(&mut raw, 225, 256);
            set_bytes(&mut raw, 226, &status_list_id(slot));
            set_bytes(&mut raw, 258, &status_url_hash(slot));
            set_bytes(&mut raw, 290, &[1]);
            set_u64(&mut raw, 291, REQUEST_TIME);
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => {
            let value = claim_value(slot);
            set_key(&mut raw, 0, credential_issuer(slot));
            set_u64(&mut raw, 160, EXPIRY);
            set_bytes(&mut raw, 161, &SESSION_BINDING);
            set_bytes(&mut raw, 193, &credential_binding(slot));
            set_bytes(&mut raw, 225, &subject_join(slot));
            let value_length = u32::try_from(value.len()).unwrap_or_default();
            set_u32(&mut raw, 257, value_length);
            set_bytes(&mut raw, 258, value);
            set_bytes(&mut raw, 322, &claim_name(slot));
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => {
            set_u32(&mut raw, 321, 1);
        }
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => {
            set_u64(&mut raw, 96, EXPIRY);
            set_bytes(&mut raw, 97, &SESSION_BINDING);
        }
        _ => {}
    }
    raw
}

fn set_request(raw: &mut [u8], field_index: usize) {
    set_bytes(raw, field_index, &[1; 32]);
    set_bytes(raw, field_index + 32, &[2; 32]);
    set_bytes(raw, field_index + 64, &[3; 32]);
}

fn set_bytes(raw: &mut [u8], field_index: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        let index = (field_index + offset) * 32 + 31;
        raw[index] = *byte;
    }
}

fn set_key(raw: &mut [u8], field_index: usize, key: ProtoIssuerPublicKey) {
    set_bytes(raw, field_index, key.x.as_slice());
    set_bytes(raw, field_index + 32, key.y.as_slice());
}

fn set_u64(raw: &mut [u8], field_index: usize, value: u64) {
    let start = field_index * 32 + 24;
    raw[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn set_u32(raw: &mut [u8], field_index: usize, value: u32) {
    let start = field_index * 32 + 28;
    raw[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

fn credential_issuer(slot: ZkCommonCredentialRootProofSlot) -> ProtoIssuerPublicKey {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => issuer(61),
        _ => issuer(31),
    }
}

fn credential_binding(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => [0xd2; 32],
        _ => [0xd1; 32],
    }
}

fn subject_join(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1 => [0xe2; 32],
        _ => [0xe1; 32],
    }
}

fn claim_name(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::SelectedClaim1 {
        [71; 32]
    } else {
        [41; 32]
    }
}

fn claim_value(slot: ZkCommonCredentialRootProofSlot) -> &'static [u8] {
    if slot == ZkCommonCredentialRootProofSlot::SelectedClaim1 {
        &[81]
    } else {
        &[51, 52]
    }
}

fn status_root(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 {
        [94; 32]
    } else {
        [91; 32]
    }
}

fn status_list_id(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 {
        [95; 32]
    } else {
        [92; 32]
    }
}

fn status_url_hash(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 {
        [96; 32]
    } else {
        [93; 32]
    }
}

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
        ZkCircuitStage::PublicSession => ProtoCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_SESSION,
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

fn raw_proof_package(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
) -> ProtoCommonCredentialRootRawProofPackage {
    let circuit_ref = persona_mode.source_ref(ZkCredentialHashAlgorithm::Poseidon2, slot);
    ProtoCommonCredentialRootRawProofPackage {
        persona_mode: EnumValue::from(proto_profile(persona_mode)),
        slot: EnumValue::from(proto_slot(slot)),
        circuit_ref: MessageField::some(proto_ref(circuit_ref)),
        proof: vec![7; 32],
        public_inputs: MessageField::some(ProtoCommonCredentialRootRawPublicInputs {
            persona_mode: EnumValue::from(proto_profile(persona_mode)),
            slot: EnumValue::from(proto_slot(slot)),
            circuit_ref: MessageField::some(proto_ref(circuit_ref)),
            raw_fields: canonical_raw(circuit_ref, slot),
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_identity: Some(
            reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkArtifactSetIdentity {
                value: vec![9; 32],
                __buffa_unknown_fields: Default::default(),
            }
            .into(),
        ),
        proof_suite: EnumValue::from(
            ProtoProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn presentation(
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> ProtoCommonCredentialRootPresentation {
    ProtoCommonCredentialRootPresentation {
        persona_mode: EnumValue::from(proto_profile(persona_mode)),
        credential_hash_algorithm: EnumValue::from(
            ProtoCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2,
        ),
        proof_suite: EnumValue::from(
            ProtoProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        session_binding: MessageField::some(ProtoSessionBinding {
            nonce_hash: vec![1; 32],
            audience_hash: vec![2; 32],
            transaction_data_hash: vec![3; 32],
            __buffa_unknown_fields: Default::default(),
        }),
        proofs: ZkCommonCredentialRootProofSlot::ALL
            .iter()
            .copied()
            .map(|slot| raw_proof_package(persona_mode, slot))
            .collect(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn issuer(byte: u8) -> ProtoIssuerPublicKey {
    ProtoIssuerPublicKey {
        x: vec![byte; 32],
        y: vec![byte.wrapping_add(1); 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn join_policy() -> ProtoCommonCredentialRootJoinPolicy {
    ProtoCommonCredentialRootJoinPolicy {
        challenge: vec![1; 32],
        audience_hash: vec![2; 32],
        transaction_data_hash: vec![3; 32],
        request_time_unix: 1,
        status_validation_time_unix: 1,
        status_validation_max_age_seconds: 120,
        attestation_signer: MessageField::some(issuer(21)),
        assurance_policy_id: vec![4; 32],
        status_root: vec![5; 32],
        claims: vec![
            ProtoCommonCredentialRootClaimExpectation {
                issuer: MessageField::some(issuer(31)),
                claim_name_hash: vec![41; 32],
                claim_value: vec![51, 52],
                claim_value_length: 2,
                __buffa_unknown_fields: Default::default(),
            },
            ProtoCommonCredentialRootClaimExpectation {
                issuer: MessageField::some(issuer(61)),
                claim_name_hash: vec![71; 32],
                claim_value: vec![81],
                claim_value_length: 1,
                __buffa_unknown_fields: Default::default(),
            },
        ],
        issuer_status: vec![
            pb::ZkCommonCredentialRootIssuerStatusExpectation {
                root: vec![91; 32],
                length: 256,
                list_id: vec![92; 32],
                url_hash: vec![93; 32],
                purpose: buffa::EnumValue::from(reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION),
                __buffa_unknown_fields: Default::default(),
            },
            pb::ZkCommonCredentialRootIssuerStatusExpectation {
                root: vec![94; 32],
                length: 256,
                list_id: vec![95; 32],
                url_hash: vec![96; 32],
                purpose: buffa::EnumValue::from(reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION),
                __buffa_unknown_fields: Default::default(),
            },
        ],
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn common_credential_root_raw_public_inputs_round_trip() -> Result<(), ZkError> {
    let persona_mode = ZkCommonCredentialRootPersonaMode::PublicPersona;
    let slot = ZkCommonCredentialRootProofSlot::SelectedClaim1;
    let inputs = raw_inputs(persona_mode, slot)?;
    let encoded = encode_common_credential_root_raw_public_inputs(persona_mode, slot, &inputs)?;
    let decoded = decode_common_credential_root_raw_public_inputs(encoded.as_slice())?;

    assert_eq!(decoded.persona_mode(), persona_mode);
    assert_eq!(decoded.slot(), slot);
    assert_eq!(decoded.public_inputs().circuit_ref(), inputs.circuit_ref());
    assert_eq!(decoded.public_inputs().as_bytes(), inputs.as_bytes());
    Ok(())
}

#[test]
fn common_credential_root_raw_public_inputs_reject_profile_slot_mismatch() -> Result<(), ZkError> {
    let inputs = raw_inputs(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    )?;
    let result = encode_common_credential_root_raw_public_inputs(
        ZkCommonCredentialRootPersonaMode::PublicPersona,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
        &inputs,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_witness_plan_uses_profile_specific_selected_claim_circuit() {
    let private_plan = common_credential_root_witness_plan(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    );
    let public_plan = common_credential_root_witness_plan(
        ZkCommonCredentialRootPersonaMode::PublicPersona,
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    );

    assert_eq!(
        private_plan.circuit_ref().stage,
        ZkCircuitStage::PrivatePersonaClaim
    );
    assert_eq!(
        public_plan.circuit_ref().stage,
        ZkCircuitStage::PublicPersonaClaim
    );
}

#[test]
fn common_credential_root_witness_plan_rejects_mismatched_circuit_ref() {
    let public_claim_ref = ZkCommonCredentialRootPersonaMode::PublicPersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    );

    assert!(matches!(
        common_credential_root_witness_plan_for_circuit(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCommonCredentialRootProofSlot::SelectedClaim0,
            public_claim_ref
        ),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
}

#[test]
fn common_credential_root_raw_public_inputs_reject_invalid_raw_length() {
    let circuit_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::RootStatus,
    );
    let message = ProtoCommonCredentialRootRawPublicInputs {
        persona_mode: EnumValue::from(
            ProtoCommonCredentialRootProfile::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
        ),
        slot: EnumValue::from(
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_STATUS,
        ),
        circuit_ref: MessageField::some(proto_ref(circuit_ref)),
        raw_fields: vec![1; 32],
        __buffa_unknown_fields: Default::default(),
    };
    assert!(matches!(
        admit_raw_public_inputs(message),
        Err(error) if error.reason() == ZkErrorReason::InvalidProofEncoding
    ));
}

#[test]
fn common_credential_root_raw_public_inputs_reject_mismatched_ref() -> Result<(), ZkError> {
    let private_inputs = raw_inputs(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    )?;
    let message = ProtoCommonCredentialRootRawPublicInputs {
        persona_mode: EnumValue::from(ProtoCommonCredentialRootProfile::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PUBLIC_PERSONA_V1),
        slot: EnumValue::from(ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SELECTED_CLAIM_0),
        circuit_ref: MessageField::some(proto_ref(private_inputs.circuit_ref())),
        raw_fields: private_inputs.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    assert!(matches!(
        admit_raw_public_inputs(message),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_raw_public_inputs_reject_unspecified_slot() -> Result<(), ZkError> {
    let inputs = raw_inputs(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    )?;
    let message = ProtoCommonCredentialRootRawPublicInputs {
        persona_mode: EnumValue::from(
            ProtoCommonCredentialRootProfile::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
        ),
        slot: EnumValue::from(
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_UNSPECIFIED,
        ),
        circuit_ref: MessageField::some(proto_ref(inputs.circuit_ref())),
        raw_fields: inputs.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    assert!(matches!(
        admit_raw_public_inputs(message),
        Err(error) if error.reason() == ZkErrorReason::InvalidClaimProofBundle
    ));
    Ok(())
}

#[test]
fn common_credential_root_raw_public_inputs_reject_noncanonical_binary() -> Result<(), ZkError> {
    let persona_mode = ZkCommonCredentialRootPersonaMode::PrivatePersona;
    let slot = ZkCommonCredentialRootProofSlot::Session;
    let inputs = raw_inputs(persona_mode, slot)?;
    let message = ProtoCommonCredentialRootRawPublicInputs {
        persona_mode: EnumValue::from(
            ProtoCommonCredentialRootProfile::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
        ),
        slot: EnumValue::from(
            ProtoCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_SESSION,
        ),
        circuit_ref: MessageField::some(proto_ref(inputs.circuit_ref())),
        raw_fields: inputs.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let mut encoded = Vec::new();
    message
        .try_encode_bounded(u32::MAX, &mut encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    encoded.extend_from_slice(&[0x20, 0x00]);

    assert!(matches!(
        decode_common_credential_root_raw_public_inputs(encoded.as_slice()),
        Err(error) if error.reason() == ZkErrorReason::MalformedProtobuf
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_accepts_canonical_slot_order() -> Result<(), ZkError> {
    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;

    assert_eq!(
        decoded.persona_mode(),
        ZkCommonCredentialRootPersonaMode::PrivatePersona
    );
    assert_eq!(
        decoded.proofs().len(),
        ZkCommonCredentialRootProofSlot::ALL.len()
    );
    assert_eq!(
        decoded.proofs()[0].slot(),
        ZkCommonCredentialRootProofSlot::RootAttestation
    );
    assert_eq!(
        decoded.proofs()[6].slot(),
        ZkCommonCredentialRootProofSlot::Session
    );
    Ok(())
}

#[test]
fn common_credential_root_presentation_rejects_reordered_slots() {
    let mut message = presentation(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    message.proofs.swap(0, 1);

    assert!(matches!(
        admit_presentation(message),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
}

#[test]
fn common_credential_root_presentation_owner_reassembles_decoded_packages() -> Result<(), ZkError> {
    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;
    let (persona_mode, credential_hash_algorithm, proof_suite, session_binding, proofs) =
        decoded.into_parts();

    let reassembled = ZkCommonCredentialRootPresentation::try_from_raw_packages(
        persona_mode,
        credential_hash_algorithm,
        proof_suite,
        session_binding,
        proofs,
    )?;

    assert_eq!(
        reassembled.persona_mode(),
        ZkCommonCredentialRootPersonaMode::PrivatePersona
    );
    assert_eq!(
        reassembled.credential_hash_algorithm(),
        ZkCredentialHashAlgorithm::Poseidon2
    );
    assert_eq!(reassembled.proof_suite(), ZkProofSuite::PRODUCTION);
    assert_eq!(reassembled.session_binding().nonce_hash, [1; 32]);
    assert_eq!(
        reassembled.proofs().len(),
        ZkCommonCredentialRootProofSlot::ALL.len()
    );
    Ok(())
}

#[test]
fn common_credential_root_presentation_owner_rejects_missing_package() -> Result<(), ZkError> {
    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;
    let (persona_mode, credential_hash_algorithm, proof_suite, session_binding, mut proofs) =
        decoded.into_parts();
    let _removed = proofs.pop();

    assert!(matches!(
        ZkCommonCredentialRootPresentation::try_from_raw_packages(
            persona_mode,
            credential_hash_algorithm,
            proof_suite,
            session_binding,
            proofs,
        ),
        Err(error) if error.reason() == ZkErrorReason::MissingStage
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_owner_rejects_reordered_packages() -> Result<(), ZkError> {
    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;
    let (persona_mode, credential_hash_algorithm, proof_suite, session_binding, mut proofs) =
        decoded.into_parts();
    proofs.swap(0, 1);

    assert!(matches!(
        ZkCommonCredentialRootPresentation::try_from_raw_packages(
            persona_mode,
            credential_hash_algorithm,
            proof_suite,
            session_binding,
            proofs,
        ),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_owner_rejects_mismatched_hash_or_suite(
) -> Result<(), ZkError> {
    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;
    let (persona_mode, credential_hash_algorithm, proof_suite, session_binding, proofs) =
        decoded.into_parts();
    assert_eq!(
        credential_hash_algorithm,
        ZkCredentialHashAlgorithm::Poseidon2
    );
    assert_eq!(proof_suite, ZkProofSuite::PRODUCTION);

    assert!(matches!(
        ZkCommonCredentialRootPresentation::try_from_raw_packages(
            persona_mode,
            ZkCredentialHashAlgorithm::Sha256,
            proof_suite,
            session_binding,
            proofs,
        ),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));

    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;
    let (persona_mode, credential_hash_algorithm, _proof_suite, session_binding, proofs) =
        decoded.into_parts();
    assert!(matches!(
        ZkCommonCredentialRootPresentation::try_from_raw_packages(
            persona_mode,
            credential_hash_algorithm,
            ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa,
            session_binding,
            proofs,
        ),
        Err(error) if error.reason() == ZkErrorReason::StageMismatch
    ));
    Ok(())
}

#[test]
fn common_credential_root_presentation_owner_rejects_invalid_session_binding() -> Result<(), ZkError>
{
    let decoded = admit_presentation(presentation(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
    ))?;
    let (persona_mode, credential_hash_algorithm, proof_suite, mut session_binding, proofs) =
        decoded.into_parts();
    session_binding.nonce_hash = [0; 32];

    assert!(matches!(
        ZkCommonCredentialRootPresentation::try_from_raw_packages(
            persona_mode,
            credential_hash_algorithm,
            proof_suite,
            session_binding,
            proofs,
        ),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));
    Ok(())
}

#[path = "common_credential_root_tests/join_policy_tests.rs"]
mod join_policy_tests;
