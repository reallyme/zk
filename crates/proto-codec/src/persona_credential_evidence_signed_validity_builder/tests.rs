// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    accept_persona_credential_evidence_signed_validity_prove_response,
    build_persona_credential_evidence_signed_validity_prove_request,
    ZkPersonaCredentialEvidenceSignedValidityCredential,
};
use crate::{
    operation::{
        decode_operation_request, encode_sensitive_operation_request, ZkProviderOperation,
    },
    persona_credential_evidence_token::ZkPersonaCredentialEvidenceToken,
    result::encode_persona_credential_evidence_stage_proof_response,
};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusListPointer,
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceRawPublicInputs, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};

const FIELD_BYTES: usize = 32;
const VALIDITY_FIELDS: usize = 259;

fn put_bytes(fields: &mut [u8], start: usize, value: &[u8; 32]) {
    for (offset, byte) in value.iter().enumerate() {
        fields[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn put_u64(fields: &mut [u8], position: usize, value: u64) {
    let start = position * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn token() -> Result<ZkPersonaCredentialEvidenceToken, ZkError> {
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
        token_nonce: [11; 32],
        proof_window: ZkPersonaCredentialEvidenceValidityWindow::try_new(100, 200)
            .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?,
    })
}

fn credential() -> ZkPersonaCredentialEvidenceSignedValidityCredential {
    ZkPersonaCredentialEvidenceSignedValidityCredential {
        envelope_hash: [5; 32],
        claims_root: [6; 32],
        subject_x: [7; 32],
        subject_y: [8; 32],
        issuer_validity_status_signature: [9; 64],
        valid_from_unix: 90,
        valid_until_unix: 210,
        status_index: 1,
        status_pointer: ZkIssuerStatusListPointer {
            list_id: [13; 32],
            url_hash: [14; 32],
            purpose: reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::Revocation,
        },
    }
}

fn proof(
    binding: [u8; 32],
    pointer: ZkIssuerStatusListPointer,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let mut fields = vec![0_u8; VALIDITY_FIELDS * FIELD_BYTES];
    put_bytes(&mut fields, 0, &[1; 32]);
    put_bytes(&mut fields, 32, &[2; 32]);
    put_bytes(&mut fields, 64, &[3; 32]);
    put_bytes(&mut fields, 96, &[4; 32]);
    put_bytes(&mut fields, 128, &[11; 32]);
    put_u64(&mut fields, 160, 100);
    put_u64(&mut fields, 161, 200);
    put_bytes(&mut fields, 162, &binding);
    put_bytes(&mut fields, 194, &pointer.list_id);
    put_bytes(&mut fields, 226, &pointer.url_hash);
    fields[258 * FIELD_BYTES + FIELD_BYTES - 1] = pointer.purpose.wire_value();
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([1; 32])).as_bytes(),
        ),
        ZkProofBytes::try_from_bytes(vec![1])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity
                .source_ref(ZkCredentialHashAlgorithm::Sha256),
            fields,
        )?,
    )
}

#[test]
fn signed_validity_requires_issuer_bounds_and_status_purpose() -> Result<(), ZkError> {
    let mut short = credential();
    short.valid_until_unix = 199;
    assert_eq!(
        build_persona_credential_evidence_signed_validity_prove_request(token()?, short)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch),
    );
    assert_eq!(
        reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::try_from_wire_value(3)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding),
    );
    Ok(())
}

#[test]
fn response_correlation_rejects_substituted_signed_status_pointer() -> Result<(), ZkError> {
    let request = encode_sensitive_operation_request(
        build_persona_credential_evidence_signed_validity_prove_request(token()?, credential())?,
    )?;
    let ZkProviderOperation::ProvePersonaCredentialEvidenceSignedValidity { input, .. } =
        decode_operation_request(request.as_slice())?
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
    let correct = proof(
        binding,
        ZkIssuerStatusListPointer {
            list_id: [13; 32],
            url_hash: [14; 32],
            purpose: reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::Revocation,
        },
    )?;
    let accepted_response =
        encode_persona_credential_evidence_stage_proof_response(request.as_slice(), &correct)?;
    assert_eq!(
        accept_persona_credential_evidence_signed_validity_prove_response(
            request.as_slice(),
            accepted_response.as_slice()
        )?
        .public_inputs()
        .stage(),
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
    );
    let substituted = proof(
        binding,
        ZkIssuerStatusListPointer {
            list_id: [13; 32],
            url_hash: [15; 32],
            purpose: reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::Revocation,
        },
    )?;
    let wrong_response =
        encode_persona_credential_evidence_stage_proof_response(request.as_slice(), &substituted)?;
    assert!(
        accept_persona_credential_evidence_signed_validity_prove_response(
            request.as_slice(),
            wrong_response.as_slice()
        )
        .is_err()
    );
    Ok(())
}
