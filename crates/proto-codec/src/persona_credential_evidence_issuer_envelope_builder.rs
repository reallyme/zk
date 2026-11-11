// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Construct the first prepared proof request from an authenticated issuer
//! credential and a Wallet-owned token context.
//!
//! The caller validates SSI issuer signatures and the consent-selected record
//! before this boundary. The native circuit verifies both signatures again.

use buffa::{EnumValue, MessageField};
use reallyme_zk_api::{
    errors::ZkError,
    persona_evidence::{
        derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceSubjectPublicKey,
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

/// Exact hidden fields from one validated `reallyme_zk_v1` issuer credential.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZkPersonaCredentialEvidenceIssuerEnvelopeCredential {
    /// Canonical signed SSI envelope digest.
    pub envelope_hash: [u8; 32],
    /// Issuer-signed claims root.
    pub claims_root: [u8; 32],
    /// Issuer-authenticated hidden subject key.
    pub subject_x: [u8; 32],
    /// Issuer-authenticated hidden subject key.
    pub subject_y: [u8; 32],
    /// Raw low-S P-256 signature on the canonical envelope digest.
    pub issuer_envelope_signature: [u8; 64],
    /// Raw low-S P-256 signature binding envelope to subject.
    pub issuer_subject_binding_signature: [u8; 64],
}

/// Build the canonical secret-bearing provider request and derive `PRECB2`
/// from the exact credential and token fields. The returned owner wipes the
/// generated private fields after encoding or rejection.
pub fn build_persona_credential_evidence_issuer_envelope_prove_request(
    token: ZkPersonaCredentialEvidenceToken,
    credential: ZkPersonaCredentialEvidenceIssuerEnvelopeCredential,
) -> Result<ZkSensitiveProviderRequest, ZkError> {
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
    let operation = pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation {
        mode: EnumValue::from(mode),
        circuit_ref: MessageField::some(circuit_ref_to_proto(
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
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
        issuer_envelope_signature: bytes64(credential.issuer_envelope_signature),
        issuer_subject_binding_signature: bytes64(credential.issuer_subject_binding_signature),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(ZkSensitiveProviderRequest::new(
        pb::ZkProviderOperationRequest {
            operation: Some(
                pb::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(
                    Box::new(operation),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

/// Admit the first prepared proof only when the provider response belongs to
/// the exact request and token. This validates transport correlation and the
/// public statement; the caller still verifies the proof cryptographically
/// under the pinned verification key.
pub fn accept_persona_credential_evidence_issuer_envelope_prove_response(
    request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceStageProof, ZkError> {
    validate_operation_exchange(request_bytes, response_bytes)?;
    let response = decode_operation_response(response_bytes)?;
    match response.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof) => Ok(proof),
            _ => Err(ZkError::new(
                reallyme_zk_api::errors::ZkErrorReason::StageMismatch,
            )),
        },
        ZkProviderOperationOutcome::Failure(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "persona_credential_evidence_issuer_envelope_builder/tests.rs"]
mod tests;
