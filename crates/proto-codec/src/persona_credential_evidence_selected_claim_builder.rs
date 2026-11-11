// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Construct a selected-claim proof from an authenticated Wallet opening.

use buffa::{EnumValue, MessageField};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        derive_persona_credential_evidence_binding, ZkPersonaCredentialEvidenceBindingInputs,
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceSubjectPublicKey,
    },
    proofs::ZkProofSuite,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    artifact::{circuit_ref_to_proto, proof_suite_to_proto},
    exchange::validate_operation_exchange,
    operation::ZkSensitiveProviderRequest,
    persona_credential_evidence_token::{bytes32, bytes64, key, ZkPersonaCredentialEvidenceToken},
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
};

const MAX_CLAIM_VALUE_BYTES: usize = 64;
const MAX_CLAIM_INDEX: u32 = 64;

/// One opening already matched to the SSI issuer-signed claims root.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZkPersonaCredentialEvidenceSelectedClaimCredential {
    /// Canonical issuer envelope digest.
    pub envelope_hash: [u8; 32],
    /// Issuer-signed claim-tree root.
    pub claims_root: [u8; 32],
    /// Hidden credential subject key.
    pub subject_x: [u8; 32],
    /// Hidden credential subject key.
    pub subject_y: [u8; 32],
    /// Issuer signature binding the envelope to the subject key.
    pub issuer_subject_binding_signature: [u8; 64],
    /// Persona key authorized by the subject. Public mode requires this to
    /// equal the token holder key; private mode keeps it hidden.
    pub persona_x: [u8; 32],
    /// Persona key authorized by the subject.
    pub persona_y: [u8; 32],
    /// Subject signature over the lane-specific LINK1 digest.
    pub subject_persona_link_signature: [u8; 64],
    /// Persona PKAUTH1 signature required only for private one-time mode.
    pub persona_token_authorization_signature: Option<[u8; 64]>,
    /// Canonical public name hash for the disclosed claim.
    pub claim_name_hash: [u8; 32],
    /// Exact raw committed value disclosed by this proof.
    pub claim_value: Vec<u8>,
    /// Holder-private claim salt.
    pub claim_salt: [u8; 16],
    /// Original leaf index in the issuer claim tree.
    pub claim_index: u32,
    /// Bottom-up private sibling digests.
    pub claim_path: Vec<[u8; 32]>,
}

/// Bind the chosen claim, persona authorization, and exact prepared token to
/// one typed protobuf operation. The returned owner wipes private openings.
pub fn build_persona_credential_evidence_selected_claim_prove_request(
    token: ZkPersonaCredentialEvidenceToken,
    claim: ZkPersonaCredentialEvidenceSelectedClaimCredential,
) -> Result<ZkSensitiveProviderRequest, ZkError> {
    if claim.claim_value.is_empty()
        || claim.claim_value.len() > MAX_CLAIM_VALUE_BYTES
        || !crate::claim_tree::is_claim_tree_depth(claim.claim_path.len())
        || claim.claim_index >= MAX_CLAIM_INDEX
        || claim.claim_index >> claim.claim_path.len() != 0
        || claim.claim_salt.iter().all(|byte| *byte == 0)
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    match token.mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1
            if claim.persona_x == token.holder_key.x
                && claim.persona_y == token.holder_key.y
                && claim.persona_token_authorization_signature.is_none() => {}
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1
            if claim.persona_x != token.holder_key.x
                && claim.persona_token_authorization_signature.is_some() => {}
        _ => return Err(ZkError::new(ZkErrorReason::BindingMismatch)),
    }
    let credential_binding = derive_persona_credential_evidence_binding(
        token.credential_hash_algorithm,
        ZkPersonaCredentialEvidenceBindingInputs {
            issuer_key: token.issuer_key,
            envelope_hash: claim.envelope_hash,
            claims_root: claim.claims_root,
            subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey {
                x: claim.subject_x,
                y: claim.subject_y,
            },
            holder_key: token.holder_key,
            token_nonce: token.token_nonce,
            proof_window: token.proof_window,
        },
    )?;
    let stage = match token.mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        }
    };
    let mode = match token.mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let mut padded_value = Zeroizing::new([0_u8; MAX_CLAIM_VALUE_BYTES]);
    padded_value[..claim.claim_value.len()].copy_from_slice(&claim.claim_value);
    let path_length = u32::try_from(claim.claim_path.len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let siblings = claim
        .claim_path
        .iter()
        .map(|sibling| pb::ZkInputBytes32 {
            value: sibling.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })
        .collect();
    let claim_opening = pb::ZkInputMerkleClaimProof {
        envelope_hash: bytes32(claim.envelope_hash),
        merkle_root: bytes32(claim.claims_root),
        claim_salt: MessageField::some(pb::ZkInputBytes16 {
            value: claim.claim_salt.to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        leaf_index: claim.claim_index,
        path: MessageField::some(pb::ZkInputMerklePath {
            path_length,
            siblings,
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    };
    let operation = pb::ZkPersonaCredentialEvidenceSelectedClaimProveOperation {
        mode: EnumValue::from(mode),
        circuit_ref: MessageField::some(circuit_ref_to_proto(
            stage.source_ref(token.credential_hash_algorithm),
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(ZkProofSuite::PRODUCTION)),
        issuer_public_key: key(token.issuer_key.x, token.issuer_key.y),
        holder_public_key: key(token.holder_key.x, token.holder_key.y),
        token_nonce: bytes32(token.token_nonce),
        evidence_valid_from_unix: token.proof_window.valid_from_unix(),
        evidence_valid_until_unix: token.proof_window.valid_until_unix(),
        disclosure: MessageField::some(pb::ZkInputClaimDisclosure {
            credential_binding: bytes32(credential_binding),
            value_length: u32::try_from(claim.claim_value.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            value: bytes64(*padded_value),
            claim_name_hash: bytes32(claim.claim_name_hash),
            __buffa_unknown_fields: Default::default(),
        }),
        claim_opening: MessageField::some(claim_opening),
        subject_public_key: key(claim.subject_x, claim.subject_y),
        issuer_subject_binding_signature: bytes64(claim.issuer_subject_binding_signature),
        persona_public_key: key(claim.persona_x, claim.persona_y),
        subject_persona_link_signature: bytes64(claim.subject_persona_link_signature),
        persona_token_authorization_signature: match claim.persona_token_authorization_signature {
            Some(signature) => bytes64(signature),
            None => MessageField::none(),
        },
        __buffa_unknown_fields: Default::default(),
    };
    Ok(ZkSensitiveProviderRequest::new(
        pb::ZkProviderOperationRequest {
            operation: Some(
                pb::zk_provider_operation_request::Operation::ProvePersonaCredentialEvidenceSelectedClaim(Box::new(
                    operation,
                )),
            ),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

/// Admit only an exact response to the typed selected-claim request. The
/// caller must additionally verify the proof under the pinned circuit VK.
pub fn accept_persona_credential_evidence_selected_claim_prove_response(
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
#[path = "persona_credential_evidence_selected_claim_builder/tests.rs"]
mod tests;
