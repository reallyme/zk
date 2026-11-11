// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Construct the prepared issuer validity and status-pointer proof request.

use buffa::{EnumValue, MessageField};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusListPointer,
    persona_evidence::{
        derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceSubjectPublicKey,
    },
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    artifact::{circuit_ref_to_proto, proof_suite_to_proto},
    exchange::validate_operation_exchange,
    operation::ZkSensitiveProviderRequest,
    persona_credential_evidence_token::{bytes32, bytes64, key, ZkPersonaCredentialEvidenceToken},
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
};

const MAX_STATUS_INDEX: u64 = 1_000_000;

/// Exact issuer-signed validity fields from an authenticated SSI credential.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZkPersonaCredentialEvidenceSignedValidityCredential {
    /// Canonical signed envelope digest.
    pub envelope_hash: [u8; 32],
    /// Issuer-signed claim-tree root.
    pub claims_root: [u8; 32],
    /// Hidden issuer-authenticated subject key.
    pub subject_x: [u8; 32],
    /// Hidden issuer-authenticated subject key.
    pub subject_y: [u8; 32],
    /// Raw low-S issuer signature over BINDVLD1.
    pub issuer_validity_status_signature: [u8; 64],
    /// Inclusive issuer validity start.
    pub valid_from_unix: u64,
    /// Exclusive issuer validity end.
    pub valid_until_unix: u64,
    /// Hidden index in the issuer's signed status list.
    pub status_index: u64,
    /// Public issuer-signed list locator, without a current-state root.
    pub status_pointer: ZkIssuerStatusListPointer,
}

/// Build a secret-bearing operation for the exact selected credential. The
/// prepared interval must fit inside issuer validity and the status pointer
/// must come from the SSI-validated envelope, not a caller-selected feed.
pub fn build_persona_credential_evidence_signed_validity_prove_request(
    token: ZkPersonaCredentialEvidenceToken,
    credential: ZkPersonaCredentialEvidenceSignedValidityCredential,
) -> Result<ZkSensitiveProviderRequest, ZkError> {
    token
        .proof_window
        .validate_issuer_bounds(credential.valid_from_unix, credential.valid_until_unix)
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    if credential.status_index >= MAX_STATUS_INDEX {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let credential_binding = derive_persona_credential_evidence_binding(
        token.credential_hash_algorithm,
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: token.issuer_key,
            envelope_hash: credential.envelope_hash,
            claims_root: credential.claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: credential.subject_x,
                y: credential.subject_y,
            },
            holder_key: token.holder_key,
            token_nonce: token.token_nonce,
            proof_window: token.proof_window,
        },
    )?;
    let mode = match token.mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let operation = pb::ZkPersonaCredentialEvidenceSignedValidityProveOperation {
        mode: EnumValue::from(mode),
        circuit_ref: MessageField::some(circuit_ref_to_proto(
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity
                .source_ref(token.credential_hash_algorithm),
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        issuer_public_key: key(token.issuer_key.x, token.issuer_key.y),
        holder_public_key: key(token.holder_key.x, token.holder_key.y),
        token_nonce: bytes32(token.token_nonce),
        evidence_valid_from_unix: token.proof_window.valid_from_unix(),
        evidence_valid_until_unix: token.proof_window.valid_until_unix(),
        credential_binding: bytes32(credential_binding),
        envelope_hash: bytes32(credential.envelope_hash),
        claims_root: bytes32(credential.claims_root),
        subject_public_key: key(credential.subject_x, credential.subject_y),
        issuer_validity_status_signature: bytes64(credential.issuer_validity_status_signature),
        valid_from_unix: credential.valid_from_unix,
        valid_until_unix: credential.valid_until_unix,
        status_index: credential.status_index,
        status_list_id: bytes32(credential.status_pointer.list_id),
        status_url_hash: bytes32(credential.status_pointer.url_hash),
        status_purpose: crate::issuer_status::purpose_to_proto(credential.status_pointer.purpose),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(ZkSensitiveProviderRequest::new(
        pb::ZkProviderOperationRequest {
            operation: Some(
                pb::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceSignedValidity(
                    Box::new(operation),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

/// Admit only the exact request digest, operation, circuit, token join, and
/// issuer-signed status pointer. Pinned-key proof verification remains required.
pub fn accept_persona_credential_evidence_signed_validity_prove_response(
    request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    validate_operation_exchange(request_bytes, response_bytes)?;
    let response = decode_operation_response(response_bytes)?;
    match response.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof) => Ok(proof),
            _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
        },
        ZkProviderOperationOutcome::Failure(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "persona_credential_evidence_signed_validity_builder/tests.rs"]
mod tests;
