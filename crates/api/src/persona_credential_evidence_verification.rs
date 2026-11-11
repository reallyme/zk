// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Backend-neutral verification of prepared credential and status stages.
//!
//! The result authenticates credential and current-state evidence only. A
//! complete presentation additionally requires an authenticated verifier
//! request, a live holder signature, nonce consumption, and, for private mode,
//! one-time wallet token reservation.

use subtle::ConstantTimeEq;

use crate::{
    artifacts::ZkArtifactSetIdentity,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::MAX_TRUSTED_ISSUERS,
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusAuthority,
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        check_persona_credential_evidence_v1_joins, ZkPersonaCredentialEvidenceHolderPublicKey,
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRawPublicInputs,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};

/// One proof package with the exact source circuit, suite, and manifest digest.
pub struct ZkPersonaCredentialEvidenceStageProof {
    mode: ZkPersonaCredentialEvidenceMode,
    proof_suite: ZkProofSuite,
    artifact_set_identity_sha256: ZkArtifactSetIdentity,
    proof_bytes: ZkProofBytes,
    public_inputs: ZkPersonaCredentialEvidenceRawPublicInputs,
}

impl ZkPersonaCredentialEvidenceStageProof {
    /// Reject metadata that could route the proof to another stage or VK.
    pub fn try_from_parts(
        mode: ZkPersonaCredentialEvidenceMode,
        proof_suite: ZkProofSuite,
        artifact_set_identity_sha256: ZkArtifactSetIdentity,
        proof_bytes: ZkProofBytes,
        public_inputs: ZkPersonaCredentialEvidenceRawPublicInputs,
    ) -> Result<Self, ZkError> {
        proof_suite.require_zero_knowledge()?;
        if artifact_set_identity_sha256.is_zero() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if !stage_matches_profile(mode, public_inputs.stage()) {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Ok(Self {
            mode,
            proof_suite,
            artifact_set_identity_sha256,
            proof_bytes,
            public_inputs,
        })
    }

    /// Persona mode declared by this proof package.
    #[must_use]
    pub const fn mode(&self) -> ZkPersonaCredentialEvidenceMode {
        self.mode
    }

    /// Exact ZK-masked suite declared by this proof package.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Hash of the pinned manifest that selects the artifact and VK.
    #[must_use]
    pub const fn artifact_set_identity_sha256(&self) -> ZkArtifactSetIdentity {
        self.artifact_set_identity_sha256
    }

    /// Owned proof bytes passed to the injected backend.
    #[must_use]
    pub const fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    /// Canonical raw public-input owner for this source circuit.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkPersonaCredentialEvidenceRawPublicInputs {
        &self.public_inputs
    }
}

fn stage_matches_profile(
    mode: ZkPersonaCredentialEvidenceMode,
    stage: ZkPersonaCredentialEvidenceSourceStage,
) -> bool {
    matches!(
        (mode, stage),
        (
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        ) | (
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
        ) | (_, ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope)
            | (_, ZkPersonaCredentialEvidenceSourceStage::ClaimRoot)
            | (_, ZkPersonaCredentialEvidenceSourceStage::SignedValidity)
            | (_, ZkPersonaCredentialEvidenceSourceStage::CurrentState)
    )
}

/// Verifier-owned policy for one selected claim and a current status feed.
pub struct ZkPersonaCredentialEvidenceVerifyRequest<'a> {
    mode: ZkPersonaCredentialEvidenceMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    issuer_envelope: &'a ZkPersonaCredentialEvidenceStageProof,
    claim_root: &'a ZkPersonaCredentialEvidenceStageProof,
    signed_validity: &'a ZkPersonaCredentialEvidenceStageProof,
    selected_claim: &'a ZkPersonaCredentialEvidenceStageProof,
    current_state: &'a ZkPersonaCredentialEvidenceStageProof,
    trusted_issuers: &'a [ZkIssuerPublicKey],
    status_authority: &'a dyn ZkIssuerStatusAuthority,
    expected_claim_name_hash: &'a [u8; 32],
    expected_claim_value: &'a [u8],
    verification_time_unix: u64,
}

impl<'a> ZkPersonaCredentialEvidenceVerifyRequest<'a> {
    /// Build a bounded request from independently authenticated verifier
    /// policy and issuer status. The injected authority must verify signature,
    /// issuer identity, freshness, and rollback before returning a feed.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        mode: ZkPersonaCredentialEvidenceMode,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        issuer_envelope: &'a ZkPersonaCredentialEvidenceStageProof,
        claim_root: &'a ZkPersonaCredentialEvidenceStageProof,
        signed_validity: &'a ZkPersonaCredentialEvidenceStageProof,
        selected_claim: &'a ZkPersonaCredentialEvidenceStageProof,
        current_state: &'a ZkPersonaCredentialEvidenceStageProof,
        trusted_issuers: &'a [ZkIssuerPublicKey],
        status_authority: &'a dyn ZkIssuerStatusAuthority,
        expected_claim_name_hash: &'a [u8; 32],
        expected_claim_value: &'a [u8],
        verification_time_unix: u64,
    ) -> Result<Self, ZkError> {
        proof_suite.require_zero_knowledge()?;
        if trusted_issuers.is_empty() || trusted_issuers.len() > MAX_TRUSTED_ISSUERS {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        if expected_claim_name_hash.iter().all(|byte| *byte == 0)
            || expected_claim_value.is_empty()
            || expected_claim_value.len() > 64
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        let expected_claim_stage = match mode {
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
                ZkPersonaCredentialEvidenceSourceStage::PublicClaim
            }
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
                ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
            }
        };
        if issuer_envelope.mode() != mode
            || claim_root.mode() != mode
            || signed_validity.mode() != mode
            || issuer_envelope.proof_suite() != proof_suite
            || claim_root.proof_suite() != proof_suite
            || signed_validity.proof_suite() != proof_suite
            || issuer_envelope.public_inputs().circuit_ref()
                != ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
                    .source_ref(credential_hash_algorithm)
            || claim_root.public_inputs().circuit_ref()
                != ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
                    .source_ref(credential_hash_algorithm)
            || signed_validity.public_inputs().circuit_ref()
                != ZkPersonaCredentialEvidenceSourceStage::SignedValidity
                    .source_ref(credential_hash_algorithm)
            || selected_claim.mode() != mode
            || current_state.mode() != mode
            || selected_claim.proof_suite() != proof_suite
            || current_state.proof_suite() != proof_suite
            || selected_claim.public_inputs().circuit_ref()
                != expected_claim_stage.source_ref(credential_hash_algorithm)
            || current_state.public_inputs().circuit_ref()
                != ZkPersonaCredentialEvidenceSourceStage::CurrentState
                    .source_ref(credential_hash_algorithm)
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Ok(Self {
            mode,
            credential_hash_algorithm,
            proof_suite,
            issuer_envelope,
            claim_root,
            signed_validity,
            selected_claim,
            current_state,
            trusted_issuers,
            status_authority,
            expected_claim_name_hash,
            expected_claim_value,
            verification_time_unix,
        })
    }

    /// Issuer envelope and hidden subject proof.
    #[must_use]
    pub const fn issuer_envelope(&self) -> &'a ZkPersonaCredentialEvidenceStageProof {
        self.issuer_envelope
    }

    /// Issuer-authenticated claim root proof.
    #[must_use]
    pub const fn claim_root(&self) -> &'a ZkPersonaCredentialEvidenceStageProof {
        self.claim_root
    }

    /// Issuer-signed validity and status-pointer proof.
    #[must_use]
    pub const fn signed_validity(&self) -> &'a ZkPersonaCredentialEvidenceStageProof {
        self.signed_validity
    }

    /// Exact claim proof selected by verifier policy.
    #[must_use]
    pub const fn selected_claim(&self) -> &'a ZkPersonaCredentialEvidenceStageProof {
        self.selected_claim
    }

    /// Exact current-status proof selected by verifier policy.
    #[must_use]
    pub const fn current_state(&self) -> &'a ZkPersonaCredentialEvidenceStageProof {
        self.current_state
    }
}

/// Backend verifier that resolves each exact circuit and manifest to its
/// pinned VK, then verifies the raw proof and field stream.
pub trait ZkPersonaCredentialEvidenceStageVerifier: Send + Sync {
    /// Verify one exact prepared credential or current-state proof package.
    fn verify_persona_credential_evidence_stage_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<(), ZkError>;
}

/// Verified proof-stage context for subsequent live holder authentication.
pub struct ZkVerifiedPersonaCredentialEvidence {
    mode: ZkPersonaCredentialEvidenceMode,
    holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
    proof_window: ZkPersonaCredentialEvidenceValidityWindow,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
}

impl ZkVerifiedPersonaCredentialEvidence {
    /// Key that must sign the canonical live request authentication.
    #[must_use]
    pub const fn holder_key(&self) -> ZkPersonaCredentialEvidenceHolderPublicKey {
        self.holder_key
    }

    /// Public or one-time private prepared mode.
    #[must_use]
    pub const fn mode(&self) -> ZkPersonaCredentialEvidenceMode {
        self.mode
    }

    /// Public interval authenticated by all prepared proof stages.
    #[must_use]
    pub const fn proof_window(&self) -> ZkPersonaCredentialEvidenceValidityWindow {
        self.proof_window
    }

    /// Hash lane authenticated by every exact source proof.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Proof suite authenticated by the injected verifier.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }
}

/// Verify four prepared facts and current status, including every exact join.
/// This never mints a complete presentation acceptance without live auth.
pub fn verify_persona_credential_evidence_with(
    verifier: &dyn ZkPersonaCredentialEvidenceStageVerifier,
    request: ZkPersonaCredentialEvidenceVerifyRequest<'_>,
) -> Result<ZkVerifiedPersonaCredentialEvidence, ZkError> {
    let claim = request.selected_claim.public_inputs();
    let state = request.current_state.public_inputs();
    claim.validate_claim(
        request.expected_claim_name_hash,
        request.expected_claim_value,
    )?;
    let claim_join = claim.join(request.proof_suite)?;
    let issuer_join = request
        .issuer_envelope
        .public_inputs()
        .join(request.proof_suite)?;
    let root_join = request
        .claim_root
        .public_inputs()
        .join(request.proof_suite)?;
    let validity_join = request
        .signed_validity
        .public_inputs()
        .join(request.proof_suite)?;
    let state_join = state.join(request.proof_suite)?;
    if !request.trusted_issuers.iter().any(|key| {
        bool::from(key.x.ct_eq(&claim_join.issuer_key.x))
            && bool::from(key.y.ct_eq(&claim_join.issuer_key.y))
    }) {
        return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
    }
    for proof in [
        request.issuer_envelope,
        request.claim_root,
        request.signed_validity,
        request.selected_claim,
        request.current_state,
    ] {
        verifier.verify_persona_credential_evidence_stage_proof(proof)?;
    }
    for joined in [&issuer_join, &root_join, &validity_join, &state_join] {
        check_persona_credential_evidence_v1_joins(
            &claim_join,
            joined,
            request.verification_time_unix,
        )
        .map_err(|_| ZkError::new(ZkErrorReason::BindingMismatch))?;
    }
    if request
        .signed_validity
        .public_inputs()
        .status_list_pointer()?
        != state.status_list_pointer()?
    {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let status_pointer = state.status_list_pointer()?;
    let authenticated_feed = request.status_authority.current_feed_for_issuer(
        &claim_join.issuer_key,
        &status_pointer,
        request.verification_time_unix,
    )?;
    state.validate_status_feed(&authenticated_feed)?;
    Ok(ZkVerifiedPersonaCredentialEvidence {
        mode: request.mode,
        holder_key: claim_join.holder_key,
        proof_window: claim_join.proof_window,
        credential_hash_algorithm: request.credential_hash_algorithm,
        proof_suite: request.proof_suite,
    })
}

#[cfg(test)]
#[path = "persona_credential_evidence_verification/tests.rs"]
mod tests;
