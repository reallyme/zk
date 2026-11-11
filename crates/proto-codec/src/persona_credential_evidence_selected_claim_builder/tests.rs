// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    accept_persona_credential_evidence_selected_claim_prove_response,
    build_persona_credential_evidence_selected_claim_prove_request,
    ZkPersonaCredentialEvidenceSelectedClaimCredential,
};
use crate::{
    exchange::{decode_operation_request_kind, ZkProviderOperationKind},
    operation::{
        decode_operation_request, encode_sensitive_operation_request, ZkProviderOperation,
    },
    persona_credential_evidence_token::ZkPersonaCredentialEvidenceToken,
    result::encode_persona_credential_evidence_stage_proof_response,
};
use buffa::{DecodeOptions, Message};
use pb::zk_provider_operation_request::Operation;
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceRawPublicInputs, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

const FIELD_BYTES: usize = 32;
const CLAIM_FIELDS: usize = 291;
const CLAIM_TREE_DEPTH: usize = 6;

fn token(
    mode: ZkPersonaCredentialEvidenceMode,
) -> Result<ZkPersonaCredentialEvidenceToken, ZkError> {
    Ok(ZkPersonaCredentialEvidenceToken {
        mode,
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        issuer_key: ZkIssuerPublicKey {
            x: [1; 32],
            y: [2; 32],
        },
        holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
            x: [3; 32],
            y: [4; 32],
        },
        token_nonce: [11; 32],
        proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)
            .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?,
    })
}

fn claim(
    mode: ZkPersonaCredentialEvidenceMode,
) -> ZkPersonaCredentialEvidenceSelectedClaimCredential {
    let public = mode == ZkPersonaCredentialEvidenceMode::PublicPersonaV1;
    ZkPersonaCredentialEvidenceSelectedClaimCredential {
        envelope_hash: [5; 32],
        claims_root: [6; 32],
        subject_x: [7; 32],
        subject_y: [8; 32],
        issuer_subject_binding_signature: [9; 64],
        persona_x: if public { [3; 32] } else { [13; 32] },
        persona_y: if public { [4; 32] } else { [14; 32] },
        subject_persona_link_signature: [15; 64],
        persona_token_authorization_signature: if public { None } else { Some([16; 64]) },
        claim_name_hash: [17; 32],
        claim_value: b"over_18".to_vec(),
        claim_salt: [18; 16],
        claim_index: 1,
        claim_path: vec![[19; 32]; CLAIM_TREE_DEPTH],
    }
}

fn put_bytes(fields: &mut [u8], start: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        fields[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn put_u64(fields: &mut [u8], position: usize, value: u64) {
    let start = position * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn proof(
    mode: ZkPersonaCredentialEvidenceMode,
    binding: [u8; 32],
    value: &[u8],
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let mut fields = vec![0_u8; CLAIM_FIELDS * FIELD_BYTES];
    put_bytes(&mut fields, 0, &[1; 32]);
    put_bytes(&mut fields, 32, &[2; 32]);
    put_bytes(&mut fields, 64, &[3; 32]);
    put_bytes(&mut fields, 96, &[4; 32]);
    put_bytes(&mut fields, 128, &[11; 32]);
    put_u64(&mut fields, 160, 100);
    put_u64(&mut fields, 161, 200);
    put_bytes(&mut fields, 162, &binding);
    put_u64(
        &mut fields,
        194,
        u64::try_from(value.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
    );
    put_bytes(&mut fields, 195, value);
    put_bytes(&mut fields, 259, &[17; 32]);
    let stage = match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        }
    };
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        mode,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([1; 32])).as_bytes(),
        ),
        ZkProofBytes::try_from_bytes(vec![1])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            stage.source_ref(ZkCredentialHashAlgorithm::Sha256),
            fields,
        )?,
    )
}

#[test]
fn selected_claim_accepts_only_exact_public_and_private_disclosures() -> Result<(), ZkError> {
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        let request = encode_sensitive_operation_request(
            build_persona_credential_evidence_selected_claim_prove_request(
                token(mode)?,
                claim(mode),
            )?,
        )?;
        assert_eq!(
            decode_operation_request_kind(&request)?,
            ZkProviderOperationKind::ProvePersonaCredentialEvidenceSelectedClaim
        );
        let ZkProviderOperation::ProvePersonaCredentialEvidenceSelectedClaim { input, .. } =
            decode_operation_request(&request)?
        else {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        };
        let disclosure = input
            .operation
            .disclosure
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        let binding: [u8; 32] = disclosure
            .credential_binding
            .as_option()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?
            .value
            .as_slice()
            .try_into()
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        let accepted = proof(mode, binding, b"over_18")?;
        let response =
            encode_persona_credential_evidence_stage_proof_response(&request, &accepted)?;
        assert!(
            accept_persona_credential_evidence_selected_claim_prove_response(&request, &response)
                .is_ok()
        );
        let substituted = proof(mode, binding, b"over_21")?;
        let response =
            encode_persona_credential_evidence_stage_proof_response(&request, &substituted)?;
        assert!(
            accept_persona_credential_evidence_selected_claim_prove_response(&request, &response)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn selected_claim_rejects_mismatched_persona_and_path() -> Result<(), ZkError> {
    let mode = ZkPersonaCredentialEvidenceMode::PublicPersonaV1;
    let mut wrong_persona = claim(mode);
    wrong_persona.persona_x = [13; 32];
    assert_eq!(
        build_persona_credential_evidence_selected_claim_prove_request(token(mode)?, wrong_persona)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch),
    );
    let mut bad_index = claim(mode);
    bad_index.claim_index = 64;
    assert_eq!(
        build_persona_credential_evidence_selected_claim_prove_request(token(mode)?, bad_index)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding),
    );
    Ok(())
}

#[test]
fn selected_claim_requires_the_fixed_claim_tree_depth() -> Result<(), ZkError> {
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        for rejected in [0_usize, 1, 5, 7] {
            let mut wrong_depth = claim(mode);
            // Index zero is in range for every depth, so only the path
            // length can cause the rejection.
            wrong_depth.claim_index = 0;
            wrong_depth.claim_path = vec![[19; 32]; rejected];
            assert_eq!(
                build_persona_credential_evidence_selected_claim_prove_request(
                    token(mode)?,
                    wrong_depth
                )
                .err()
                .map(|error| error.reason()),
                Some(ZkErrorReason::InvalidProofEncoding),
            );
        }
        let mut full_depth = claim(mode);
        full_depth.claim_index = 0;
        full_depth.claim_path = vec![[19; 32]; CLAIM_TREE_DEPTH];
        assert!(
            build_persona_credential_evidence_selected_claim_prove_request(
                token(mode)?,
                full_depth
            )
            .is_ok()
        );
    }
    Ok(())
}

fn admission_reason_with_claim_path(
    mode: ZkPersonaCredentialEvidenceMode,
    path_length: u32,
    sibling_count: usize,
) -> Result<Option<ZkErrorReason>, ZkError> {
    let request = encode_sensitive_operation_request(
        build_persona_credential_evidence_selected_claim_prove_request(token(mode)?, claim(mode))?,
    )?;
    let mut message = DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(&request)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let Some(Operation::ProvePersonaCredentialEvidenceSelectedClaim(operation)) =
        message.operation.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    };
    let opening = operation
        .claim_opening
        .as_option_mut()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    // Index zero is in range for every depth, so only the path shape can
    // cause the rejection.
    opening.leaf_index = 0;
    let path = opening
        .path
        .as_option_mut()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let sibling = pb::ZkInputBytes32 {
        value: vec![19; 32],
        __buffa_unknown_fields: Default::default(),
    };
    path.path_length = path_length;
    path.siblings = vec![sibling; sibling_count];
    Ok(decode_operation_request(&message.encode_to_vec())
        .err()
        .map(|error| error.reason()))
}

#[test]
fn selected_claim_admission_requires_the_fixed_claim_tree_depth() -> Result<(), ZkError> {
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        assert_eq!(admission_reason_with_claim_path(mode, 6, 6)?, None);
        for (path_length, sibling_count) in [
            (0_u32, 0_usize),
            (1, 1),
            (5, 5),
            (7, 7),
            (6, 5),
            (5, 6),
            (6, 7),
            (7, 6),
        ] {
            assert_eq!(
                admission_reason_with_claim_path(mode, path_length, sibling_count)?,
                Some(ZkErrorReason::InvalidProofEncoding),
            );
        }
    }
    Ok(())
}
