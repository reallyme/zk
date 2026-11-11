// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    common_root::common_credential_root_issuer_status_root,
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusPurpose,
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

use crate::{
    operation::{
        decode_operation_request, encode_sensitive_operation_request, ZkProviderOperation,
    },
    persona_credential_evidence_proof_set::ZkPersonaCredentialEvidenceProofSet,
    result::encode_persona_credential_evidence_stage_proof_response,
};

use super::{
    accept_persona_credential_evidence_current_state_prove_response,
    build_persona_credential_evidence_current_state_prove_request,
    ZkPersonaCredentialEvidenceAuthenticatedStatus, ZkPersonaCredentialEvidenceSelectedCredential,
};

const FIELD_BYTES: usize = 32;
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

fn credential() -> ZkPersonaCredentialEvidenceSelectedCredential {
    ZkPersonaCredentialEvidenceSelectedCredential {
        envelope_hash: ENVELOPE_HASH,
        claims_root: CLAIMS_ROOT,
        subject_key_x: SUBJECT_X,
        subject_key_y: SUBJECT_Y,
        issuer_validity_status_signature: [12; 64],
        valid_from: 90,
        valid_until: 210,
        status_index: 0,
    }
}

fn status(bitstring: &[u8]) -> Result<ZkPersonaCredentialEvidenceAuthenticatedStatus<'_>, ZkError> {
    Ok(ZkPersonaCredentialEvidenceAuthenticatedStatus {
        bitstring,
        root: common_credential_root_issuer_status_root(bitstring, 8)
            .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?,
        length: 8,
        list_id: STATUS_LIST_ID,
        url_hash: STATUS_URL_HASH,
        purpose: ZkIssuerStatusPurpose::Revocation,
        issued_unix: 99,
        expires_unix: 201,
    })
}

fn binding(lane: ZkCredentialHashAlgorithm) -> Result<[u8; 32], ZkError> {
    derive_persona_credential_evidence_binding(
        lane,
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

fn stage_fields(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    lane: ZkCredentialHashAlgorithm,
) -> Result<Vec<u8>, ZkError> {
    let mut claim = vec![0_u8; 291 * FIELD_BYTES];
    put_bytes(&mut claim, 0, &ISSUER_X);
    put_bytes(&mut claim, 32, &ISSUER_Y);
    put_bytes(&mut claim, 64, &HOLDER_X);
    put_bytes(&mut claim, 96, &HOLDER_Y);
    put_bytes(&mut claim, 128, &TOKEN_NONCE);
    put_u64(&mut claim, 160, 100);
    put_u64(&mut claim, 161, 200);
    put_bytes(&mut claim, 162, &binding(lane)?);
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
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        | ZkPersonaCredentialEvidenceSourceStage::PublicClaim => Ok(claim),
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => {
            let mut fields = vec![0_u8; 292 * FIELD_BYTES];
            fields[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
            let active = status(&[0])?;
            put_bytes(&mut fields, 194, &active.root);
            put_u64(&mut fields, 226, active.length);
            put_bytes(&mut fields, 227, &active.list_id);
            put_bytes(&mut fields, 259, &active.url_hash);
            put_byte(&mut fields, 291, active.purpose.wire_value());
            Ok(fields)
        }
    }
}

fn proof(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    mode: ZkPersonaCredentialEvidenceMode,
    lane: ZkCredentialHashAlgorithm,
    marker: u8,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        mode,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([marker; FIELD_BYTES])).as_bytes(),
        ),
        ZkProofBytes::try_from_bytes(vec![marker])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            stage.source_ref(lane),
            stage_fields(stage, lane)?,
        )?,
    )
}

fn evidence(
    mode: ZkPersonaCredentialEvidenceMode,
    lane: ZkCredentialHashAlgorithm,
) -> Result<ZkPersonaCredentialEvidenceProofSet, ZkError> {
    let claim_stage = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        }
    };
    ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        proof(
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
            mode,
            lane,
            1,
        )?,
        proof(
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
            mode,
            lane,
            2,
        )?,
        proof(
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
            mode,
            lane,
            3,
        )?,
        proof(claim_stage, mode, lane, 4)?,
    )
}

#[test]
fn authenticated_current_status_builds_canonical_operation_in_both_lanes() -> Result<(), ZkError> {
    for lane in [
        ZkCredentialHashAlgorithm::Sha256,
        ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        for mode in [
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        ] {
            let evidence = evidence(mode, lane)?;
            let request = build_persona_credential_evidence_current_state_prove_request(
                &evidence,
                credential(),
                status(&[0])?,
                150,
            )?;
            let wire = encode_sensitive_operation_request(request)?;
            match decode_operation_request(wire.as_slice())? {
                ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState {
                    mode: parsed_profile,
                    circuit_ref,
                    proof_suite,
                    input,
                } => {
                    assert_eq!(parsed_profile, mode);
                    assert_eq!(
                        circuit_ref,
                        ZkPersonaCredentialEvidenceSourceStage::CurrentState.source_ref(lane)
                    );
                    assert_eq!(proof_suite, ZkProofSuite::PRODUCTION);
                    assert_eq!(input.credential.status_index, 0);
                    assert_eq!(input.current_status.status_length, 8);
                    assert_eq!(input.current_status.path_length, 0);
                }
                _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
            }
        }
    }
    Ok(())
}

#[test]
fn status_builder_rejects_revocation_mismatch_expiry_and_wrong_credential() -> Result<(), ZkError> {
    let evidence = evidence(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        ZkCredentialHashAlgorithm::Sha256,
    )?;
    let revoked = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        credential(),
        status(&[1])?,
        150,
    );
    assert_eq!(
        revoked.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut wrong_list = status(&[0])?;
    wrong_list.list_id[0] ^= 1;
    let wrong_pointer = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        credential(),
        wrong_list,
        150,
    );
    assert_eq!(
        wrong_pointer.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let expired = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        credential(),
        status(&[0])?,
        201,
    );
    assert_eq!(
        expired.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut wrong_credential = credential();
    wrong_credential.envelope_hash[0] ^= 1;
    let wrong_binding = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        wrong_credential,
        status(&[0])?,
        150,
    );
    assert_eq!(
        wrong_binding.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut wrong_root = status(&[0])?;
    wrong_root.root[0] ^= 1;
    let mismatch = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        credential(),
        wrong_root,
        150,
    );
    assert_eq!(
        mismatch.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut malformed_length = status(&[0])?;
    malformed_length.length = 9;
    let invalid = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        credential(),
        malformed_length,
        150,
    );
    assert_eq!(
        invalid.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    Ok(())
}

#[test]
fn current_status_builder_opens_private_index_in_second_chunk() -> Result<(), ZkError> {
    let evidence = evidence(
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkCredentialHashAlgorithm::Sha256,
    )?;
    let bitstring = [0_u8; 64];
    let mut authenticated = status(&[0])?;
    authenticated.bitstring = &bitstring;
    authenticated.length = 512;
    authenticated.root = common_credential_root_issuer_status_root(&bitstring, 512)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    let mut selected = credential();
    selected.status_index = 257;
    let request = build_persona_credential_evidence_current_state_prove_request(
        &evidence,
        selected,
        authenticated,
        150,
    )?;
    let wire = encode_sensitive_operation_request(request)?;
    match decode_operation_request(wire.as_slice())? {
        ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState { input, .. } => {
            assert_eq!(input.credential.status_index, 257);
            assert_eq!(input.current_status.path_length, 1);
            assert_eq!(input.current_status.path.len(), 1);
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
    Ok(())
}

#[test]
fn current_state_result_requires_exact_request_join_and_authenticated_feed() -> Result<(), ZkError>
{
    for lane in [
        ZkCredentialHashAlgorithm::Sha256,
        ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        let mode = ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1;
        let evidence = evidence(mode, lane)?;
        let active = status(&[0])?;
        let request = build_persona_credential_evidence_current_state_prove_request(
            &evidence,
            credential(),
            status(&[0])?,
            150,
        )?;
        let wire = encode_sensitive_operation_request(request)?;
        let proved = proof(
            ZkPersonaCredentialEvidenceSourceStage::CurrentState,
            mode,
            lane,
            5,
        )?;
        let response =
            encode_persona_credential_evidence_stage_proof_response(wire.as_slice(), &proved)?;
        let expected = reallyme_zk_api::issuer_status::ZkIssuerStatusFeed {
            root: active.root,
            length: active.length,
            list_id: active.list_id,
            url_hash: active.url_hash,
            purpose: active.purpose,
        };
        let accepted = accept_persona_credential_evidence_current_state_prove_response(
            wire.as_slice(),
            response.as_slice(),
            &evidence,
            &expected,
            150,
        )?;
        assert!(accepted.public_inputs().status_feed()? == expected);

        let other_request = build_persona_credential_evidence_current_state_prove_request(
            &evidence,
            credential(),
            status(&[0])?,
            151,
        )?;
        let wrong_request = encode_sensitive_operation_request(other_request)?;
        let mismatch = accept_persona_credential_evidence_current_state_prove_response(
            &wrong_request,
            response.as_slice(),
            &evidence,
            &expected,
            150,
        );
        assert_eq!(
            mismatch.err().map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch)
        );

        let wrong_feed = reallyme_zk_api::issuer_status::ZkIssuerStatusFeed {
            root: [1; FIELD_BYTES],
            length: active.length,
            list_id: active.list_id,
            url_hash: active.url_hash,
            purpose: active.purpose,
        };
        let mismatch = accept_persona_credential_evidence_current_state_prove_response(
            wire.as_slice(),
            response.as_slice(),
            &evidence,
            &wrong_feed,
            150,
        );
        assert_eq!(
            mismatch.err().map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch)
        );

        let mut wrong_fields =
            stage_fields(ZkPersonaCredentialEvidenceSourceStage::CurrentState, lane)?;
        put_bytes(&mut wrong_fields, 128, &[0x77; FIELD_BYTES]);
        let wrong_proof = ZkPersonaCredentialEvidenceStageProof::try_from_parts(
            mode,
            ZkProofSuite::PRODUCTION,
            reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
                *(ZkArtifactManifestDigest::from_bytes([6; FIELD_BYTES])).as_bytes(),
            ),
            ZkProofBytes::try_from_bytes(vec![6])?,
            ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
                ZkPersonaCredentialEvidenceSourceStage::CurrentState.source_ref(lane),
                wrong_fields,
            )?,
        )?;
        let wrong_response =
            encode_persona_credential_evidence_stage_proof_response(wire.as_slice(), &wrong_proof)?;
        let mismatch = accept_persona_credential_evidence_current_state_prove_response(
            wire.as_slice(),
            wrong_response.as_slice(),
            &evidence,
            &expected,
            150,
        );
        assert_eq!(
            mismatch.err().map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch)
        );

        let wrong_profile_proof = proof(
            ZkPersonaCredentialEvidenceSourceStage::CurrentState,
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            lane,
            7,
        )?;
        let wrong_profile_response = encode_persona_credential_evidence_stage_proof_response(
            wire.as_slice(),
            &wrong_profile_proof,
        )?;
        let mismatch = accept_persona_credential_evidence_current_state_prove_response(
            wire.as_slice(),
            wrong_profile_response.as_slice(),
            &evidence,
            &expected,
            150,
        );
        assert_eq!(
            mismatch.err().map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch)
        );

        let stale = accept_persona_credential_evidence_current_state_prove_response(
            wire.as_slice(),
            response.as_slice(),
            &evidence,
            &expected,
            201,
        );
        assert_eq!(
            stale.err().map(|error| error.reason()),
            Some(ZkErrorReason::BindingMismatch)
        );
    }
    Ok(())
}
