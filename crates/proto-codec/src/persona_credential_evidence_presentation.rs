// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Complete verifier-side prepared presentation admission.
//!
//! The caller constructs `ZkPersonaCredentialEvidenceVerifierRequest` from an authenticated
//! direct or OpenID4VP request and supplies an independently authenticated,
//! rollback-protected shared issuer status feed. Presentation-supplied request
//! and status fields never become authorities by themselves.

#[cfg(any(feature = "native", feature = "wasm"))]
use buffa::{DecodeOptions, EnumValue, Message};
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_zk_api::persona_evidence::{
    ZkPersonaCredentialEvidenceReplayChallenge, ZkPersonaCredentialEvidenceReplayError,
    ZkPersonaCredentialEvidenceReplayReason, ZkPersonaCredentialEvidenceReplayStore,
};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    issuer_status::ZkIssuerStatusAuthority,
    keys::ZkIssuerPublicKey,
    persona_evidence::{ZkPersonaCredentialEvidenceMode, ZkVerifiedPersonaCredentialEvidence},
};
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_zk_api::{
    errors::ZkError,
    persona_evidence::{
        verify_persona_credential_evidence_with, ZkPersonaCredentialEvidenceStageVerifier,
        ZkPersonaCredentialEvidenceVerifyRequest,
        PERSONA_CREDENTIAL_EVIDENCE_V1_MAX_RAW_PUBLIC_INPUT_BYTES,
    },
    proofs::{ZkProofSuite, MAX_PROOF_BYTES},
};
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
#[cfg(any(feature = "native", feature = "wasm"))]
use subtle::ConstantTimeEq;
use thiserror::Error;
#[cfg(any(feature = "native", feature = "wasm"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "native", feature = "wasm"))]
mod build;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use build::{
    build_persona_credential_evidence_presentation,
    build_persona_credential_evidence_presentation_with_signature,
    persona_credential_evidence_signing_digest, ZkPersonaCredentialEvidenceHolderSigner,
    ZkPersonaCredentialEvidenceProofSetRef, ZkPersonaCredentialEvidenceSignerError,
};

#[cfg(any(feature = "native", feature = "wasm"))]
use crate::persona_credential_evidence_auth::ZkPersonaCredentialEvidenceVerifierRequest;
#[cfg(any(feature = "native", feature = "wasm"))]
use crate::{
    domain::{credential_hash_algorithm_from_proto, proof_suite_from_proto},
    persona_credential_evidence_auth::{
        decode_persona_credential_evidence_presentation_auth, ZkPersonaCredentialEvidenceAuthError,
    },
    persona_credential_evidence_proof_set::canonical_credential_evidence_bytes,
    persona_credential_evidence_stage_proof::persona_credential_evidence_stage_proof_from_proto,
};

#[cfg(any(feature = "native", feature = "wasm"))]
const MAX_PREPARED_PRESENTATION_BYTES: usize = (5 * MAX_PROOF_BYTES)
    + (5 * PERSONA_CREDENTIAL_EVIDENCE_V1_MAX_RAW_PUBLIC_INPUT_BYTES)
    + (32 * 1024);
#[cfg(any(feature = "native", feature = "wasm"))]
const PREPARED_PRESENTATION_RECURSION_LIMIT: u32 = 10;
#[cfg(any(feature = "native", feature = "wasm"))]
const HOLDER_SIGNATURE_BYTES: usize = 64;

/// Stable, non-sensitive reason for rejecting a prepared presentation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ZkPersonaCredentialEvidencePresentationReason {
    /// The protobuf has unknown, duplicate, malformed, or oversized fields.
    #[error("invalid prepared presentation encoding")]
    InvalidEncoding,
    /// The presentation does not match the verifier's selected mode or request.
    #[error("prepared presentation policy mismatch")]
    PolicyMismatch,
    /// The independently authenticated request is malformed or outside its time window.
    #[error("prepared presentation request rejected")]
    RequestRejected,
    /// A proof, issuer, status, claim, or proof-window check failed.
    #[error("prepared presentation evidence rejected")]
    EvidenceRejected,
    /// Live P-256 holder authentication failed.
    #[error("prepared presentation holder authentication failed")]
    HolderAuthenticationFailed,
    /// The holder's signing provider could not complete the live signature.
    #[error("prepared presentation holder signing failed")]
    HolderSigningFailed,
    /// The verifier challenge could not be consumed exactly once.
    #[error("prepared presentation nonce replayed")]
    NonceReplay,
    /// Durable replay state could not be read or committed safely.
    #[error("prepared presentation replay store unavailable")]
    ReplayStoreUnavailable,
}

/// Typed presentation error without proof bytes, claims, or request metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("prepared presentation rejected: {reason}")]
pub struct ZkPersonaCredentialEvidencePresentationError {
    reason: ZkPersonaCredentialEvidencePresentationReason,
}

impl ZkPersonaCredentialEvidencePresentationError {
    /// Stable reason suitable for deterministic FFI mapping.
    #[must_use]
    pub const fn reason(self) -> ZkPersonaCredentialEvidencePresentationReason {
        self.reason
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn rejected(
    reason: ZkPersonaCredentialEvidencePresentationReason,
) -> ZkPersonaCredentialEvidencePresentationError {
    ZkPersonaCredentialEvidencePresentationError { reason }
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn evidence_rejected(_error: ZkError) -> ZkPersonaCredentialEvidencePresentationError {
    rejected(ZkPersonaCredentialEvidencePresentationReason::EvidenceRejected)
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn authentication_rejected(
    _error: ZkPersonaCredentialEvidenceAuthError,
) -> ZkPersonaCredentialEvidencePresentationError {
    rejected(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed)
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn request_rejected(
    _error: ZkPersonaCredentialEvidenceAuthError,
) -> ZkPersonaCredentialEvidencePresentationError {
    rejected(ZkPersonaCredentialEvidencePresentationReason::RequestRejected)
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn replay_rejected(
    error: ZkPersonaCredentialEvidenceReplayError,
) -> ZkPersonaCredentialEvidencePresentationError {
    match error.reason() {
        ZkPersonaCredentialEvidenceReplayReason::AlreadyConsumed => {
            rejected(ZkPersonaCredentialEvidencePresentationReason::NonceReplay)
        }
        ZkPersonaCredentialEvidenceReplayReason::InvalidChallenge => {
            rejected(ZkPersonaCredentialEvidencePresentationReason::RequestRejected)
        }
        ZkPersonaCredentialEvidenceReplayReason::StoreUnavailable => {
            rejected(ZkPersonaCredentialEvidencePresentationReason::ReplayStoreUnavailable)
        }
    }
}

/// Prepared presentation accepted under the caller's authenticated request,
/// trusted status feed, holder key, and durable nonce-consumption policy.
/// This type can only be constructed by the complete verifier boundary.
pub struct AcceptedPersonaCredentialEvidencePresentation {
    evidence: ZkVerifiedPersonaCredentialEvidence,
}

impl AcceptedPersonaCredentialEvidencePresentation {
    /// Authenticated evidence whose holder key signed the accepted request.
    #[must_use]
    pub const fn evidence(&self) -> &ZkVerifiedPersonaCredentialEvidence {
        &self.evidence
    }

    /// Transfer the fully accepted evidence to a protocol verifier after the
    /// current status, holder signature, and replay checks have succeeded.
    #[must_use]
    pub fn into_evidence(self) -> ZkVerifiedPersonaCredentialEvidence {
        self.evidence
    }
}

/// Verifier-selected claim, issuer, status, and mode policy.
pub struct ZkPersonaCredentialEvidencePresentationPolicy<'a> {
    /// Only this mode may satisfy the verifier request.
    pub mode: ZkPersonaCredentialEvidenceMode,
    /// Only this issuer credential hash lane may satisfy the verifier request.
    pub credential_hash_algorithm: ZkCredentialHashAlgorithm,
    /// Trusted issuer keys for this selected claim.
    pub trusted_issuers: &'a [ZkIssuerPublicKey],
    /// Source that authenticates the issuer's current shared status feed.
    pub status_authority: &'a dyn ZkIssuerStatusAuthority,
    /// Hash of the exact requested claim name.
    pub expected_claim_name_hash: &'a [u8; 32],
    /// Public claim result required by policy.
    pub expected_claim_value: &'a [u8],
    /// Trusted verifier time in Unix seconds.
    pub now_unix: u64,
}

/// Verify a canonical prepared presentation and consume the live challenge.
/// Private-mode wallet reservation is a separate holder-side requirement.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn verify_persona_credential_evidence_presentation_with(
    verifier: &dyn ZkPersonaCredentialEvidenceStageVerifier,
    nonce_consumer: &dyn ZkPersonaCredentialEvidenceReplayStore,
    presentation_bytes: &[u8],
    authenticated_request: &ZkPersonaCredentialEvidenceVerifierRequest,
    policy: ZkPersonaCredentialEvidencePresentationPolicy<'_>,
) -> Result<
    AcceptedPersonaCredentialEvidencePresentation,
    ZkPersonaCredentialEvidencePresentationError,
> {
    authenticated_request
        .validate_at(policy.now_unix)
        .map_err(request_rejected)?;
    if presentation_bytes.len() > MAX_PREPARED_PRESENTATION_BYTES {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding,
        ));
    }
    let mut wire = DecodeOptions::new()
        .with_recursion_limit(PREPARED_PRESENTATION_RECURSION_LIMIT)
        .with_unknown_field_limit(0)
        .with_element_memory_limit(MAX_PREPARED_PRESENTATION_BYTES)
        .with_max_message_size(MAX_PREPARED_PRESENTATION_BYTES)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidencePresentation>(presentation_bytes)
        .map_err(|_| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    // The canonicality copy contains private-mode token proofs and must be
    // wiped even when the verifier rejects the presentation.
    if Zeroizing::new(wire.encode_to_vec()).as_slice() != presentation_bytes {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding,
        ));
    }
    let mode = profile_from_proto(wire.mode)?;
    if mode != policy.mode {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch,
        ));
    }
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(wire.credential_hash_algorithm)
            .map_err(evidence_rejected)?;
    if credential_hash_algorithm != policy.credential_hash_algorithm {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch,
        ));
    }
    let proof_suite = proof_suite_from_proto(wire.proof_suite).map_err(evidence_rejected)?;
    if proof_suite != ZkProofSuite::PRODUCTION {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch,
        ));
    }
    let verified_request = authenticated_request.encode().map_err(request_rejected)?;
    let request_wire = wire
        .verifier_request
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    if !bool::from(
        Zeroizing::new(request_wire.encode_to_vec())
            .as_slice()
            .ct_eq(verified_request.as_slice()),
    ) {
        return Err(rejected(
            ZkPersonaCredentialEvidencePresentationReason::PolicyMismatch,
        ));
    }
    let issuer_wire = wire
        .issuer_envelope
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let root_wire = wire
        .claim_root
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let validity_wire = wire
        .signed_validity
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let claim_wire = wire
        .selected_claim
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let evidence_canonical =
        canonical_credential_evidence_bytes(&issuer_wire, &root_wire, &validity_wire, &claim_wire);
    let issuer = persona_credential_evidence_stage_proof_from_proto(issuer_wire)
        .map_err(evidence_rejected)?;
    let root =
        persona_credential_evidence_stage_proof_from_proto(root_wire).map_err(evidence_rejected)?;
    let validity = persona_credential_evidence_stage_proof_from_proto(validity_wire)
        .map_err(evidence_rejected)?;
    let claim = persona_credential_evidence_stage_proof_from_proto(claim_wire)
        .map_err(evidence_rejected)?;
    let status_wire = wire
        .current_state
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let status_canonical = Zeroizing::new(status_wire.encode_to_vec());
    let status = persona_credential_evidence_stage_proof_from_proto(status_wire)
        .map_err(evidence_rejected)?;
    let request = ZkPersonaCredentialEvidenceVerifyRequest::try_new(
        mode,
        credential_hash_algorithm,
        proof_suite,
        &issuer,
        &root,
        &validity,
        &claim,
        &status,
        policy.trusted_issuers,
        policy.status_authority,
        policy.expected_claim_name_hash,
        policy.expected_claim_value,
        policy.now_unix,
    )
    .map_err(evidence_rejected)?;
    let verified =
        verify_persona_credential_evidence_with(verifier, request).map_err(evidence_rejected)?;
    let auth_wire = wire
        .auth
        .take()
        .ok_or_else(|| rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding))?;
    let auth_canonical = Zeroizing::new(auth_wire.encode_to_vec());
    let auth = decode_persona_credential_evidence_presentation_auth(&auth_canonical)
        .map_err(authentication_rejected)?;
    auth.validate_verified_packages(
        mode,
        &evidence_canonical,
        &status_canonical,
        authenticated_request,
    )
    .map_err(authentication_rejected)?;
    let signature =
        <[u8; HOLDER_SIGNATURE_BYTES]>::try_from(wire.holder_signature_p256_raw.as_slice())
            .map_err(|_| {
                rejected(ZkPersonaCredentialEvidencePresentationReason::HolderAuthenticationFailed)
            })?;
    let holder_key = verified.holder_key();
    auth.verify_holder_signature(&holder_key.x, &holder_key.y, &signature)
        .map_err(authentication_rejected)?;
    let challenge = ZkPersonaCredentialEvidenceReplayChallenge::try_new(
        &authenticated_request.nonce,
        &authenticated_request.audience_sha256,
        authenticated_request.expires_at_unix,
    )
    .map_err(replay_rejected)?;
    nonce_consumer
        .consume(&challenge, policy.now_unix)
        .map_err(replay_rejected)?;
    Ok(AcceptedPersonaCredentialEvidencePresentation { evidence: verified })
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn profile_from_proto(
    value: EnumValue<pb::ZkPersonaCredentialEvidenceMode>,
) -> Result<ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidencePresentationError> {
    match value.as_known() {
        Some(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1) => {
            Ok(ZkPersonaCredentialEvidenceMode::PublicPersonaV1)
        }
        Some(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1) => {
            Ok(ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1)
        }
        _ => Err(rejected(ZkPersonaCredentialEvidencePresentationReason::InvalidEncoding)),
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test-only fixture construction and assertions fail at the exact unexpected result"
)]
#[path = "persona_credential_evidence_presentation/tests.rs"]
mod tests;
