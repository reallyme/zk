// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{PREPARED_DIGEST_BYTES, PREPARED_SIGNATURE_BYTES};
use crate::artifact::{circuit_ref_to_proto, proof_suite_to_proto};
use crate::exchange::validate_operation_exchange;
use crate::exchange::{decode_operation_request_kind, ZkProviderOperationKind};
use crate::persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_from_proto;
use crate::result::encode_persona_credential_evidence_stage_proof_response;
use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

fn request() -> pb::ZkProviderOperationRequest {
    let bytes32 = |value: u8| {
        MessageField::some(pb::ZkInputBytes32 {
            value: vec![value; PREPARED_DIGEST_BYTES],
            __buffa_unknown_fields: Default::default(),
        })
    };
    let bytes64 = |value: u8| {
        MessageField::some(pb::ZkInputBytes64 {
            value: vec![value; PREPARED_SIGNATURE_BYTES],
            __buffa_unknown_fields: Default::default(),
        })
    };
    let key = |x: u8, y: u8| {
        MessageField::some(pb::ZkInputP256PublicKey {
            x: bytes32(x),
            y: bytes32(y),
            __buffa_unknown_fields: Default::default(),
        })
    };
    pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(Box::new(
                pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation {
                    mode: EnumValue::from(
                        pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
                    ),
                    circuit_ref: MessageField::some(circuit_ref_to_proto(
                        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
                            .source_ref(ZkCredentialHashAlgorithm::Sha256),
                    )),
                    proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
                    issuer_public_key: key(1, 2),
                    holder_public_key: key(3, 4),
                    token_nonce: bytes32(5),
                    evidence_valid_from_unix: 100,
                    evidence_valid_until_unix: 200,
                    credential_binding: bytes32(6),
                    envelope_hash: bytes32(7),
                    claims_root: bytes32(8),
                    subject_public_key: key(9, 10),
                    issuer_envelope_signature: bytes64(11),
                    issuer_subject_binding_signature: bytes64(12),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn typed_issuer_envelope_request_is_admitted_and_malformed_fields_fail() -> Result<(), ZkError> {
    let valid = request();
    assert_eq!(
        decode_operation_request_kind(&valid.encode_to_vec()),
        Ok(ZkProviderOperationKind::ProvePersonaCredentialEvidenceIssuerEnvelope)
    );
    for mutation in 0..3 {
        let mut invalid = request();
        let Some(pb::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(
            operation,
        )) = invalid.operation.as_mut()
        else {
            return Err(ZkError::new(ZkErrorReason::MissingOperation));
        };
        match mutation {
            0 => {
                operation.token_nonce = MessageField::some(pb::ZkInputBytes32 {
                    value: vec![5; PREPARED_DIGEST_BYTES - 1],
                    __buffa_unknown_fields: Default::default(),
                });
            }
            1 => {
                operation.evidence_valid_until_unix = operation.evidence_valid_from_unix;
            }
            _ => {
                operation.issuer_envelope_signature.take();
            }
        }
        assert_eq!(
            decode_operation_request_kind(&invalid.encode_to_vec())
                .err()
                .map(|error| error.reason()),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    Ok(())
}

fn public_fields(nonce_byte: u8) -> Vec<u8> {
    const FIELD_BYTES: usize = 32;
    const JOIN_FIELDS: usize = 194;
    let mut bytes = vec![0_u8; JOIN_FIELDS * FIELD_BYTES];
    for (start, value) in [
        (0, 1),
        (32, 2),
        (64, 3),
        (96, 4),
        (128, nonce_byte),
        (162, 6),
    ] {
        for index in start..start + FIELD_BYTES {
            bytes[index * FIELD_BYTES + FIELD_BYTES - 1] = value;
        }
    }
    bytes[160 * FIELD_BYTES + FIELD_BYTES - 1] = 100;
    bytes[161 * FIELD_BYTES + FIELD_BYTES - 1] = 200;
    bytes
}

fn proof(nonce_byte: u8) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let mode =
        pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1;
    let slot =
        pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE;
    let circuit = ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        .source_ref(ZkCredentialHashAlgorithm::Sha256);
    persona_credential_evidence_stage_proof_from_proto(pb::ZkPersonaCredentialEvidenceStageProof {
        mode: EnumValue::from(mode),
        proof_slot: EnumValue::from(slot),
        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit)),
        proof: vec![42],
        public_inputs: MessageField::some(pb::ZkPersonaCredentialEvidenceRawPublicInputs {
            mode: EnumValue::from(mode),
            proof_slot: EnumValue::from(slot),
            circuit_ref: MessageField::some(circuit_ref_to_proto(circuit)),
            raw_fields: public_fields(nonce_byte),
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_set_identity_sha256: MessageField::some(pb::ZkArtifactSetIdentity {
            value: vec![13; PREPARED_DIGEST_BYTES],
            __buffa_unknown_fields: Default::default(),
        }),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        __buffa_unknown_fields: Default::default(),
    })
}

#[test]
fn provider_cannot_return_another_prepared_tokens_proof() -> Result<(), ZkError> {
    let request_bytes = request().encode_to_vec();
    let matching = proof(5)?;
    let response =
        encode_persona_credential_evidence_stage_proof_response(&request_bytes, &matching)?;
    validate_operation_exchange(&request_bytes, response.as_slice())?;

    let substituted = proof(9)?;
    let response =
        encode_persona_credential_evidence_stage_proof_response(&request_bytes, &substituted)?;
    assert_eq!(
        validate_operation_exchange(&request_bytes, response.as_slice())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BackendFailure)
    );
    Ok(())
}
