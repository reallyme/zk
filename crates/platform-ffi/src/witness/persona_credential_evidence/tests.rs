// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::common_credential_root_issuer_status_opening,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceRawPublicInputs, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceSubjectPublicKey,
        ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    operation::ZkPersonaCredentialEvidenceCurrentStateProveRequest,
    persona_credential_evidence_proof_set::ZkPersonaCredentialEvidenceProofSet,
};

use super::{current_state::prepared_current_state_inputs, prepared_issuer_envelope_inputs};
use reallyme_zk_proto_codec::operation::ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest;

const FIELD_BYTES: usize = 32;
const PROFILE: ZkPersonaCredentialEvidenceMode =
    ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1;
const HASH: ZkCredentialHashAlgorithm = ZkCredentialHashAlgorithm::Sha256;
const ISSUER_X: [u8; 32] = [1; 32];
const ISSUER_Y: [u8; 32] = [2; 32];
const HOLDER_X: [u8; 32] = [3; 32];
const HOLDER_Y: [u8; 32] = [4; 32];
const TOKEN_NONCE: [u8; 32] = [9; 32];
const ENVELOPE_HASH: [u8; 32] = [10; 32];
const CLAIMS_ROOT: [u8; 32] = [11; 32];
const SUBJECT_X: [u8; 32] = [13; 32];
const SUBJECT_Y: [u8; 32] = [14; 32];
const STATUS_LIST_ID: [u8; 32] = [7; 32];
const STATUS_URL_HASH: [u8; 32] = [8; 32];

fn put_bytes(bytes: &mut [u8], start: usize, value: &[u8; FIELD_BYTES]) {
    for (offset, byte) in value.iter().enumerate() {
        bytes[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn put_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], field: usize, value: u32) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 4;
    bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_byte(bytes: &mut [u8], field: usize, value: u8) {
    bytes[field * FIELD_BYTES + FIELD_BYTES - 1] = value;
}

fn binding() -> Result<[u8; 32], ZkError> {
    derive_persona_credential_evidence_binding(
        HASH,
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: ZkIssuerPublicKey {
                x: ISSUER_X,
                y: ISSUER_Y,
            },
            envelope_hash: ENVELOPE_HASH,
            claims_root: CLAIMS_ROOT,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: SUBJECT_X,
                y: SUBJECT_Y,
            },
            holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
                x: HOLDER_X,
                y: HOLDER_Y,
            },
            token_nonce: TOKEN_NONCE,
            proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)
                .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?,
        },
    )
}

fn issuer_envelope_request(
) -> Result<ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest, ZkError> {
    let bytes32 = |value: [u8; 32]| {
        MessageField::some(pb::ZkInputBytes32 {
            value: value.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })
    };
    let bytes64 = |value: [u8; 64]| {
        MessageField::some(pb::ZkInputBytes64 {
            value: value.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })
    };
    let key = |x: [u8; 32], y: [u8; 32]| {
        MessageField::some(pb::ZkInputP256PublicKey {
            x: bytes32(x),
            y: bytes32(y),
            __buffa_unknown_fields: Default::default(),
        })
    };
    Ok(ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest {
        operation: pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation {
            issuer_public_key: key(ISSUER_X, ISSUER_Y),
            holder_public_key: key(HOLDER_X, HOLDER_Y),
            token_nonce: bytes32(TOKEN_NONCE),
            evidence_valid_from_unix: 100,
            evidence_valid_until_unix: 200,
            credential_binding: bytes32(binding()?),
            envelope_hash: bytes32(ENVELOPE_HASH),
            claims_root: bytes32(CLAIMS_ROOT),
            subject_public_key: key(SUBJECT_X, SUBJECT_Y),
            issuer_envelope_signature: bytes64([15; 64]),
            issuer_subject_binding_signature: bytes64([16; 64]),
            ..Default::default()
        },
    })
}

#[test]
fn typed_issuer_envelope_rejects_wrong_join_before_artifact_resolution() -> Result<(), ZkError> {
    let circuit = ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope.source_ref(HASH);
    let valid = issuer_envelope_request()?;
    assert!(prepared_issuer_envelope_inputs(circuit, &valid).is_ok());
    let mut wrong = issuer_envelope_request()?;
    wrong.operation.credential_binding = MessageField::some(pb::ZkInputBytes32 {
        value: vec![0_u8; FIELD_BYTES],
        __buffa_unknown_fields: Default::default(),
    });
    assert_eq!(
        prepared_issuer_envelope_inputs(circuit, &wrong)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    assert_eq!(
        prepared_issuer_envelope_inputs(
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot.source_ref(HASH),
            &valid
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::StageMismatch)
    );
    Ok(())
}

fn stage_fields(stage: ZkPersonaCredentialEvidenceSourceStage) -> Result<Vec<u8>, ZkError> {
    let credential_binding = binding()?;
    let mut claim = vec![0_u8; 291 * FIELD_BYTES];
    put_bytes(&mut claim, 0, &ISSUER_X);
    put_bytes(&mut claim, 32, &ISSUER_Y);
    put_bytes(&mut claim, 64, &HOLDER_X);
    put_bytes(&mut claim, 96, &HOLDER_Y);
    put_bytes(&mut claim, 128, &TOKEN_NONCE);
    put_u64(&mut claim, 160, 100);
    put_u64(&mut claim, 161, 200);
    put_bytes(&mut claim, 162, &credential_binding);
    put_u32(&mut claim, 194, 1);
    put_byte(&mut claim, 195, 18);
    put_bytes(&mut claim, 259, &[6; FIELD_BYTES]);
    match stage {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        | ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => {
            Ok(claim[..194 * FIELD_BYTES].to_vec())
        }
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => {
            let mut fields = vec![0_u8; 259 * FIELD_BYTES];
            fields[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
            put_bytes(&mut fields, 194, &STATUS_LIST_ID);
            put_bytes(&mut fields, 226, &STATUS_URL_HASH);
            put_byte(&mut fields, 258, 1);
            Ok(fields)
        }
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => Ok(claim),
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

fn proof(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    marker: u8,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        PROFILE,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes([marker; FIELD_BYTES]),
        ZkProofBytes::try_from_bytes(vec![marker])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            stage.source_ref(HASH),
            stage_fields(stage)?,
        )?,
    )
}

fn evidence() -> Result<ZkPersonaCredentialEvidenceProofSet, ZkError> {
    ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        proof(ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope, 1)?,
        proof(ZkPersonaCredentialEvidenceSourceStage::ClaimRoot, 2)?,
        proof(ZkPersonaCredentialEvidenceSourceStage::SignedValidity, 3)?,
        proof(ZkPersonaCredentialEvidenceSourceStage::PrivateClaim, 4)?,
    )
}

fn bytes32(value: [u8; 32]) -> MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>> {
    MessageField::some(pb::ZkInputBytes32 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes64(value: [u8; 64]) -> MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>> {
    MessageField::some(pb::ZkInputBytes64 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn subject_key() -> MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>>
{
    MessageField::some(pb::ZkInputP256PublicKey {
        x: bytes32(SUBJECT_X),
        y: bytes32(SUBJECT_Y),
        __buffa_unknown_fields: Default::default(),
    })
}

fn request() -> Result<ZkPersonaCredentialEvidenceCurrentStateProveRequest, ZkError> {
    let status_list = [0_u8];
    let (status_root, opening) = common_credential_root_issuer_status_opening(&status_list, 8, 0)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    Ok(ZkPersonaCredentialEvidenceCurrentStateProveRequest {
        evidence: evidence()?,
        credential: pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput {
            envelope_hash: bytes32(ENVELOPE_HASH),
            claims_root: bytes32(CLAIMS_ROOT),
            subject_public_key: subject_key(),
            issuer_validity_status_signature: bytes64([12; 64]),
            valid_from: 90,
            valid_until: 210,
            status_index: 0,
            __buffa_unknown_fields: Default::default(),
        },
        current_status: pb::ZkPersonaCredentialEvidenceCurrentStatusInput {
            status_root: bytes32(status_root),
            status_length: 8,
            status_list_id: bytes32(STATUS_LIST_ID),
            status_url_hash: bytes32(STATUS_URL_HASH),
            status_purpose: buffa::EnumValue::from(reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION),
            issued_unix: 99,
            expires_unix: 201,
            status_chunk: bytes32(*opening.chunk()),
            path_length: u32::try_from(opening.siblings().len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            path: opening
                .siblings()
                .iter()
                .map(|sibling| pb::ZkInputBytes32 {
                    value: sibling.to_vec(),
                    __buffa_unknown_fields: Default::default(),
                })
                .collect(),
            __buffa_unknown_fields: Default::default(),
        },
        verification_time_unix: 150,
    })
}

#[test]
fn current_state_builder_accepts_joined_status_opening() -> Result<(), ZkError> {
    let request = request()?;
    let inputs = prepared_current_state_inputs(
        ZkPersonaCredentialEvidenceSourceStage::CurrentState.source_ref(HASH),
        ZkProofSuite::PRODUCTION,
        &request,
    )?;

    assert_eq!(inputs.public_inputs.status_length, 8);
    assert_eq!(inputs.public_inputs.credential_binding, binding()?);
    Ok(())
}

#[test]
fn current_state_builder_rejects_wrong_status_pointer() -> Result<(), ZkError> {
    let mut request = request()?;
    request.current_status.status_list_id = bytes32([99; 32]);
    let error = prepared_current_state_inputs(
        ZkPersonaCredentialEvidenceSourceStage::CurrentState.source_ref(HASH),
        ZkProofSuite::PRODUCTION,
        &request,
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::BindingMismatch));
    Ok(())
}

#[test]
fn current_state_builder_rejects_bad_credential_join_stale_feed_and_path() -> Result<(), ZkError> {
    let mut wrong_join = request()?;
    wrong_join.credential.subject_public_key = MessageField::some(pb::ZkInputP256PublicKey {
        x: bytes32([77; 32]),
        y: bytes32(SUBJECT_Y),
        __buffa_unknown_fields: Default::default(),
    });
    let mut stale_feed = request()?;
    stale_feed.current_status.expires_unix = 150;
    let mut bad_path = request()?;
    bad_path.current_status.status_root = bytes32([55; 32]);

    for input in [&wrong_join, &stale_feed, &bad_path] {
        let error = prepared_current_state_inputs(
            ZkPersonaCredentialEvidenceSourceStage::CurrentState.source_ref(HASH),
            ZkProofSuite::PRODUCTION,
            input,
        )
        .err()
        .map(|error| error.reason());
        assert_eq!(error, Some(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}
