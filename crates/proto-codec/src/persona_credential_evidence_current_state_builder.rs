// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build the canonical prepared current-state prove operation from selected
//! credential material and an independently authenticated status snapshot.
//!
//! The caller authenticates the issuer's signed status list, its URL and list
//! identity, freshness, and a durable rollback floor before this boundary.
//! This builder checks their exact relation to the prepared evidence and
//! derives the private Merkle opening. The circuit repeats the checks.

use buffa::{EnumValue, MessageField};
use reallyme_zk_api::{
    common_root::{
        common_credential_root_issuer_status_opening,
        verify_common_credential_root_issuer_status_opening,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerStatusFeed, ZkIssuerStatusPurpose},
    persona_evidence::{
        check_persona_credential_evidence_v1_joins, derive_persona_credential_evidence_binding,
        ZkPersonaCredentialEvidenceBindingInputs, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceSubjectPublicKey,
    },
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    artifact::{circuit_ref_to_proto, proof_suite_to_proto},
    exchange::{decode_operation_request_kind, ZkProviderOperationKind},
    operation::ZkSensitiveProviderRequest,
    persona_credential_evidence_proof_set::ZkPersonaCredentialEvidenceProofSet,
    persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_to_proto,
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
};
use reallyme_zk_artifacts::Digest32;

/// Private credential fields recovered from the authenticated selected record.
/// The issuer's signed status pointer is recovered from the verified prepared
/// validity proof, not copied from this value.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZkPersonaCredentialEvidenceSelectedCredential {
    /// Exact canonical issuer envelope digest.
    pub envelope_hash: [u8; 32],
    /// Issuer-signed claim root.
    pub claims_root: [u8; 32],
    /// Hidden issuer-authenticated credential subject key coordinates.
    pub subject_key_x: [u8; 32],
    /// Hidden issuer-authenticated credential subject key coordinates.
    pub subject_key_y: [u8; 32],
    /// Issuer signature over validity, pointer, and private status index.
    pub issuer_validity_status_signature: [u8; 64],
    /// Inclusive validity start from the issuer credential.
    pub valid_from: u64,
    /// Exclusive validity end from the issuer credential.
    pub valid_until: u64,
    /// Hidden index from the exact selected issuer credential.
    pub status_index: u64,
}

/// Status-list bytes and coordinates admitted by the wallet's trust authority.
/// Construct this only after signature, issuer, feed identity, freshness, and
/// durable rollback-floor checks. A holder-controlled snapshot is insufficient.
pub struct ZkPersonaCredentialEvidenceAuthenticatedStatus<'a> {
    /// Authenticated canonical little-endian status bitstring.
    pub bitstring: &'a [u8],
    /// Root independently derived from the signature-verified status feed.
    pub root: [u8; 32],
    /// Signed number of entries in the list.
    pub length: u64,
    /// Signed list identity.
    pub list_id: [u8; 32],
    /// SHA-256 of the issuer-signed list URL.
    pub url_hash: [u8; 32],
    /// Signed meaning of a set status bit.
    pub purpose: ZkIssuerStatusPurpose,
    /// Signed issue time.
    pub issued_unix: u64,
    /// Signed expiry time.
    pub expires_unix: u64,
}

/// Construct the exact protobuf provider request for a fresh status proof.
///
/// The returned owner wipes copied proof and private witness material on drop.
/// It does not authenticate the source proofs or the status-list signature;
/// those are mandatory caller and verifier responsibilities.
pub fn build_persona_credential_evidence_current_state_prove_request(
    evidence: &ZkPersonaCredentialEvidenceProofSet,
    credential: ZkPersonaCredentialEvidenceSelectedCredential,
    status: ZkPersonaCredentialEvidenceAuthenticatedStatus<'_>,
    now_unix: u64,
) -> Result<ZkSensitiveProviderRequest, ZkError> {
    let join = evidence
        .selected_claim()
        .public_inputs()
        .join(ZkProofSuite::PRODUCTION)?;
    join.proof_window
        .validate_at(now_unix)
        .map_err(|_| mismatch())?;
    join.proof_window
        .validate_issuer_bounds(credential.valid_from, credential.valid_until)
        .map_err(|_| mismatch())?;
    let pointer = evidence
        .signed_validity()
        .public_inputs()
        .status_list_pointer()?;
    if pointer.list_id != status.list_id
        || pointer.url_hash != status.url_hash
        || pointer.purpose != status.purpose
        || status.issued_unix >= status.expires_unix
        || now_unix < status.issued_unix
        || now_unix >= status.expires_unix
    {
        return Err(mismatch());
    }
    let binding = derive_persona_credential_evidence_binding(
        evidence.credential_hash_algorithm(),
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: join.issuer_key,
            envelope_hash: credential.envelope_hash,
            claims_root: credential.claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: credential.subject_key_x,
                y: credential.subject_key_y,
            },
            holder_key: join.holder_key,
            token_nonce: join.token_nonce,
            proof_window: join.proof_window,
        },
    )?;
    if binding != join.credential_binding {
        return Err(mismatch());
    }
    let (root, opening) = common_credential_root_issuer_status_opening(
        status.bitstring,
        status.length,
        credential.status_index,
    )
    .map_err(|_| mismatch())?;
    if root != status.root {
        return Err(mismatch());
    }
    verify_common_credential_root_issuer_status_opening(
        &root,
        status.length,
        credential.status_index,
        &opening,
    )
    .map_err(|_| mismatch())?;
    let path_length = u32::try_from(opening.siblings().len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mode = match evidence.mode() {
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let operation = pb::ZkPersonaCredentialEvidenceCurrentStateProveOperation {
        mode: EnumValue::from(mode),
        circuit_ref: MessageField::some(circuit_ref_to_proto(
            ZkPersonaCredentialEvidenceSourceStage::CurrentState
                .source_ref(evidence.credential_hash_algorithm()),
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        evidence_proof_set: MessageField::some(pb::ZkPersonaCredentialEvidenceProofSet {
            issuer_envelope: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                evidence.issuer_envelope(),
            )),
            claim_root: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                evidence.claim_root(),
            )),
            signed_validity: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                evidence.signed_validity(),
            )),
            selected_claim: MessageField::some(persona_credential_evidence_stage_proof_to_proto(
                evidence.selected_claim(),
            )),
            __buffa_unknown_fields: Default::default(),
        }),
        credential: MessageField::some(
            pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput {
                envelope_hash: bytes32(credential.envelope_hash),
                claims_root: bytes32(credential.claims_root),
                subject_public_key: MessageField::some(pb::ZkInputP256PublicKey {
                    x: bytes32(credential.subject_key_x),
                    y: bytes32(credential.subject_key_y),
                    __buffa_unknown_fields: Default::default(),
                }),
                issuer_validity_status_signature: MessageField::some(pb::ZkInputBytes64 {
                    value: credential.issuer_validity_status_signature.to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }),
                valid_from: credential.valid_from,
                valid_until: credential.valid_until,
                status_index: credential.status_index,
                __buffa_unknown_fields: Default::default(),
            },
        ),
        current_status: MessageField::some(pb::ZkPersonaCredentialEvidenceCurrentStatusInput {
            status_root: bytes32(root),
            status_length: status.length,
            status_list_id: bytes32(status.list_id),
            status_url_hash: bytes32(status.url_hash),
            status_purpose: crate::issuer_status::purpose_to_proto(status.purpose),
            issued_unix: status.issued_unix,
            expires_unix: status.expires_unix,
            status_chunk: bytes32(*opening.chunk()),
            path_length,
            path: opening
                .siblings()
                .iter()
                .copied()
                .map(bytes32_message)
                .collect(),
            __buffa_unknown_fields: Default::default(),
        }),
        verification_time_unix: now_unix,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(ZkSensitiveProviderRequest::new(
        pb::ZkProviderOperationRequest {
            operation: Some(
                pb::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceCurrentState(Box::new(
                    operation,
                )),
            ),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

/// Admit only the fresh current-state proof returned for the exact provider
/// request and independently authenticated status feed.
///
/// This establishes transport correlation and public-input agreement. The
/// caller must still verify the returned proof under the pinned verification
/// key before including it in a signed presentation.
pub fn accept_persona_credential_evidence_current_state_prove_response(
    request_bytes: &[u8],
    response_bytes: &[u8],
    evidence: &ZkPersonaCredentialEvidenceProofSet,
    expected_status: &ZkIssuerStatusFeed,
    now_unix: u64,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    if decode_operation_request_kind(request_bytes)?
        != ZkProviderOperationKind::ProvePersonaCredentialEvidenceCurrentState
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let response = decode_operation_response(response_bytes)?;
    if response.request_sha256() != Digest32::sha256(request_bytes) {
        return Err(mismatch());
    }
    let proof = match response.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            ZkProviderOperationResult::PersonaCredentialEvidenceStageProof(proof) => proof,
            _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
        },
        ZkProviderOperationOutcome::Failure(error) => return Err(error),
    };
    if proof.mode() != evidence.mode()
        || proof.proof_suite() != ZkProofSuite::PRODUCTION
        || proof.public_inputs().circuit_ref()
            != ZkPersonaCredentialEvidenceSourceStage::CurrentState
                .source_ref(evidence.credential_hash_algorithm())
    {
        return Err(mismatch());
    }
    let selected_join = evidence
        .selected_claim()
        .public_inputs()
        .join(ZkProofSuite::PRODUCTION)?;
    let current_join = proof.public_inputs().join(ZkProofSuite::PRODUCTION)?;
    check_persona_credential_evidence_v1_joins(&selected_join, &current_join, now_unix)
        .map_err(|_| mismatch())?;
    proof
        .public_inputs()
        .validate_status_feed(expected_status)?;
    Ok(proof)
}

fn bytes32(value: [u8; 32]) -> MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>> {
    MessageField::some(bytes32_message(value))
}

fn bytes32_message(value: [u8; 32]) -> pb::ZkInputBytes32 {
    pb::ZkInputBytes32 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

const fn mismatch() -> ZkError {
    ZkError::new(ZkErrorReason::BindingMismatch)
}

#[cfg(test)]
#[path = "persona_credential_evidence_current_state_builder/tests.rs"]
mod tests;
