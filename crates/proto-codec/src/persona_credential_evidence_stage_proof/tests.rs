// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::ZkPersonaCredentialEvidenceSourceStage,
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::decode_persona_credential_evidence_stage_proof;
use crate::artifact::{circuit_ref_to_proto, proof_suite_to_proto};
use crate::exchange::{
    decode_operation_request_kind, validate_operation_exchange, ZkProviderOperationKind,
};
use crate::result::{
    encode_persona_credential_evidence_stage_proof_response,
    encode_persona_credential_evidence_stage_verification_response,
};

const FIELD_BYTES: usize = 32;

fn put_byte(bytes: &mut [u8], field: usize, value: u8) {
    bytes[field * FIELD_BYTES + FIELD_BYTES - 1] = value;
}

fn put_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn inputs() -> Vec<u8> {
    let mut bytes = vec![0_u8; 291 * FIELD_BYTES];
    for (field, value) in [(0, 1), (32, 2), (64, 3), (96, 4), (128, 5), (162, 6)] {
        put_byte(&mut bytes, field, value);
    }
    put_u64(&mut bytes, 160, 100);
    put_u64(&mut bytes, 161, 200);
    put_byte(&mut bytes, 194, 1);
    put_byte(&mut bytes, 195, 18);
    put_byte(&mut bytes, 259, 7);
    bytes
}

fn package() -> pb::ZkPersonaCredentialEvidenceStageProof {
    let mode = pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1;
    let slot =
        pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM;
    let circuit_ref = ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        .source_ref(ZkCredentialHashAlgorithm::Sha256);
    pb::ZkPersonaCredentialEvidenceStageProof {
        mode: EnumValue::from(mode),
        proof_slot: EnumValue::from(slot),
        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
        proof: vec![42],
        public_inputs: MessageField::some(pb::ZkPersonaCredentialEvidenceRawPublicInputs {
            mode: EnumValue::from(mode),
            proof_slot: EnumValue::from(slot),
            circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
            raw_fields: inputs(),
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_set_identity_sha256: MessageField::some(pb::ZkArtifactSetIdentity {
            value: vec![11; 32],
            __buffa_unknown_fields: Default::default(),
        }),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn valid_package_admits_exact_profile_and_circuit() -> Result<(), ZkError> {
    let wire = package().encode_to_vec();
    let decoded = decode_persona_credential_evidence_stage_proof(&wire)?;
    assert_eq!(
        decoded.public_inputs().stage(),
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
    );
    assert_eq!(decoded.proof_bytes().as_bytes(), &[42]);
    assert_eq!(decoded.artifact_set_identity_sha256().as_bytes(), &[11; 32]);
    Ok(())
}

#[test]
fn mismatched_nested_metadata_and_manifest_fail() {
    let mut changed = package();
    if let Some(mut nested) = changed.public_inputs.take() {
        nested.proof_slot =
            EnumValue::from(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE);
        changed.public_inputs = MessageField::some(nested);
    }
    assert_eq!(
        decode_persona_credential_evidence_stage_proof(&changed.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::StageMismatch)
    );
    let mut changed = package();
    if let Some(mut digest) = changed.artifact_set_identity_sha256.take() {
        digest.value.fill(0);
        changed.artifact_set_identity_sha256 = MessageField::some(digest);
    }
    assert_eq!(
        decode_persona_credential_evidence_stage_proof(&changed.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
}

#[test]
fn unknown_or_duplicated_wire_fields_fail_canonical_admission() {
    let mut unknown = package().encode_to_vec();
    unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert_eq!(
        decode_persona_credential_evidence_stage_proof(&unknown)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MalformedProtobuf)
    );
    let mut duplicated = package().encode_to_vec();
    duplicated.extend_from_slice(&[0x08, 0x02]);
    assert_eq!(
        decode_persona_credential_evidence_stage_proof(&duplicated)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MalformedProtobuf)
    );
}

#[test]
fn prepared_native_verification_exchange_binds_exact_request_and_stage() -> Result<(), ZkError> {
    let request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::VerifyPersonaCredentialEvidenceStage(
                Box::new(pb::ZkPersonaCredentialEvidenceStageVerifyOperation {
                    proof: MessageField::some(package()),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let request_bytes = request.encode_to_vec();
    assert_eq!(
        decode_operation_request_kind(&request_bytes)?,
        ZkProviderOperationKind::VerifyPersonaCredentialEvidenceStage
    );
    let proof = decode_persona_credential_evidence_stage_proof(&package().encode_to_vec())?;
    let response =
        encode_persona_credential_evidence_stage_verification_response(&request_bytes, &proof)?;
    validate_operation_exchange(&request_bytes, response.as_slice())?;

    let mut forged = pb::ZkProviderOperationResponse::decode(&mut response.as_slice())
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let Some(pb::zk_provider_operation_response::Outcome::Result(result)) = forged.outcome.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    };
    let Some(pb::zk_provider_operation_result::Result::PersonaCredentialEvidenceStageVerification(
        report,
    )) = result.result.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    };
    report.mode = EnumValue::from(
        pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
    );
    assert_eq!(
        validate_operation_exchange(&request_bytes, &forged.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::StageMismatch)
    );

    let changed_request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::VerifyPersonaCredentialEvidenceStage(
                Box::new(pb::ZkPersonaCredentialEvidenceStageVerifyOperation {
                    proof: MessageField::some({
                        let mut changed = package();
                        changed.proof[0] ^= 1;
                        changed
                    }),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec();
    assert_eq!(
        validate_operation_exchange(&changed_request, response.as_slice())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BackendFailure)
    );
    Ok(())
}

#[test]
fn prepared_proving_exchange_binds_profile_circuit_and_result() -> Result<(), ZkError> {
    let proof = decode_persona_credential_evidence_stage_proof(&package().encode_to_vec())?;
    let circuit_ref = proof.public_inputs().circuit_ref();
    let request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceStage(
                Box::new(pb::ZkPersonaCredentialEvidenceStageProveOperation {
                    mode: EnumValue::from(
                        pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1,
                    ),
                    circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
                    proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
                    witness: MessageField::some(pb::ZkWitness {
                        encoded: vec![1, 2, 3],
                        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
                        encoding: EnumValue::from(
                            pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
                        ),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let request_bytes = request.encode_to_vec();
    assert_eq!(
        decode_operation_request_kind(&request_bytes)?,
        ZkProviderOperationKind::ProvePersonaCredentialEvidenceStage
    );
    let response = encode_persona_credential_evidence_stage_proof_response(&request_bytes, &proof)?;
    validate_operation_exchange(&request_bytes, response.as_slice())?;

    let mut wrong_profile = request;
    let Some(pb::__buffa::oneof::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceStage(
        operation,
    )) = wrong_profile.operation.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    };
    operation.mode = EnumValue::from(
        pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
    );
    assert_eq!(
        validate_operation_exchange(&wrong_profile.encode_to_vec(), response.as_slice())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BackendFailure)
    );
    Ok(())
}
