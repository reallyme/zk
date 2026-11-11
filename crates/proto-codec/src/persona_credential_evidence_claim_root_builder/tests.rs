// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    accept_persona_credential_evidence_claim_root_prove_response,
    build_persona_credential_evidence_claim_root_prove_request,
    ZkPersonaCredentialEvidenceClaimRootCredential,
};
use crate::persona_credential_evidence_token::ZkPersonaCredentialEvidenceToken;
use crate::{
    exchange::{decode_operation_request_kind, ZkProviderOperationKind},
    operation::{
        decode_operation_request, encode_sensitive_operation_request, ZkProviderOperation,
    },
    result::encode_persona_credential_evidence_stage_proof_response,
};
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

const FIELD_BYTES: usize = 32;
const JOIN_FIELDS: usize = 194;

fn put_bytes(fields: &mut [u8], start: usize, value: &[u8; FIELD_BYTES]) {
    for (offset, byte) in value.iter().enumerate() {
        fields[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn put_u64(fields: &mut [u8], position: usize, value: u64) {
    let start = position * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn proof(
    nonce: [u8; 32],
    binding: [u8; 32],
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let mut fields = vec![0_u8; JOIN_FIELDS * FIELD_BYTES];
    put_bytes(&mut fields, 0, &[1; 32]);
    put_bytes(&mut fields, 32, &[2; 32]);
    put_bytes(&mut fields, 64, &[3; 32]);
    put_bytes(&mut fields, 96, &[4; 32]);
    put_bytes(&mut fields, 128, &nonce);
    put_u64(&mut fields, 160, 100);
    put_u64(&mut fields, 161, 200);
    put_bytes(&mut fields, 162, &binding);
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([1; 32])).as_bytes(),
        ),
        ZkProofBytes::try_from_bytes(vec![1])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
                .source_ref(ZkCredentialHashAlgorithm::Sha256),
            fields,
        )?,
    )
}

fn token(nonce: [u8; 32]) -> Result<ZkPersonaCredentialEvidenceToken, ZkError> {
    Ok(ZkPersonaCredentialEvidenceToken {
        mode: ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        issuer_key: ZkIssuerPublicKey {
            x: [1; 32],
            y: [2; 32],
        },
        holder_key: ZkPersonaCredentialEvidenceHolderPublicKey {
            x: [3; 32],
            y: [4; 32],
        },
        token_nonce: nonce,
        proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)
            .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?,
    })
}

fn credential() -> ZkPersonaCredentialEvidenceClaimRootCredential {
    ZkPersonaCredentialEvidenceClaimRootCredential {
        envelope_hash: [5; 32],
        claims_root: [6; 32],
        subject_x: [7; 32],
        subject_y: [8; 32],
        issuer_root_binding_signature: [9; 64],
    }
}

#[test]
fn builder_emits_typed_canonical_request_and_distinct_token_bindings() -> Result<(), ZkError> {
    let first = encode_sensitive_operation_request(
        build_persona_credential_evidence_claim_root_prove_request(token([11; 32])?, credential())?,
    )?;
    let second = encode_sensitive_operation_request(
        build_persona_credential_evidence_claim_root_prove_request(token([12; 32])?, credential())?,
    )?;
    assert_eq!(
        decode_operation_request_kind(first.as_slice())?,
        ZkProviderOperationKind::ProvePersonaCredentialEvidenceClaimRoot
    );
    let ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot {
        circuit_ref,
        input: first_input,
        ..
    } = decode_operation_request(first.as_slice())?
    else {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    };
    let ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot {
        input: second_input,
        ..
    } = decode_operation_request(second.as_slice())?
    else {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    };
    assert_eq!(
        circuit_ref,
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
            .source_ref(ZkCredentialHashAlgorithm::Sha256)
    );
    assert_ne!(
        first_input
            .operation
            .credential_binding
            .as_option()
            .map(|value| value.value.as_slice()),
        second_input
            .operation
            .credential_binding
            .as_option()
            .map(|value| value.value.as_slice())
    );
    Ok(())
}

#[test]
fn builder_rejects_zero_token_nonce() -> Result<(), ZkError> {
    assert_eq!(
        build_persona_credential_evidence_claim_root_prove_request(token([0; 32])?, credential())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::EmptyInput)
    );
    Ok(())
}

#[test]
fn issuer_result_rejects_a_different_prepared_token() -> Result<(), ZkError> {
    let first = encode_sensitive_operation_request(
        build_persona_credential_evidence_claim_root_prove_request(token([11; 32])?, credential())?,
    )?;
    let second = encode_sensitive_operation_request(
        build_persona_credential_evidence_claim_root_prove_request(token([12; 32])?, credential())?,
    )?;
    let ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot { input, .. } =
        decode_operation_request(first.as_slice())?
    else {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    };
    let binding: [u8; 32] = input
        .operation
        .credential_binding
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?
        .value
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let proved = proof([11; 32], binding)?;
    let response =
        encode_persona_credential_evidence_stage_proof_response(first.as_slice(), &proved)?;
    let accepted = accept_persona_credential_evidence_claim_root_prove_response(
        first.as_slice(),
        response.as_slice(),
    )?;
    assert_eq!(
        accepted.public_inputs().stage(),
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
    );
    assert!(
        accept_persona_credential_evidence_claim_root_prove_response(
            second.as_slice(),
            response.as_slice(),
        )
        .is_err()
    );
    let substituted = proof([12; 32], binding)?;
    let wrong_response =
        encode_persona_credential_evidence_stage_proof_response(first.as_slice(), &substituted)?;
    assert!(
        accept_persona_credential_evidence_claim_root_prove_response(
            first.as_slice(),
            wrong_response.as_slice(),
        )
        .is_err()
    );
    Ok(())
}
