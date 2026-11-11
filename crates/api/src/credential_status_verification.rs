// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer validity and current-status evidence for a request-bound claim.
//!
//! The four-stage claim bundle and the issuer-status proof use the same
//! request-scoped CREDB1 commitment. Neither proof may be accepted alone as a
//! currently valid credential. This module joins both verified proofs to an
//! independently authenticated issuer status feed.

#[path = "credential_status_verification/verified_statement.rs"]
mod verified_statement;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    artifacts::ZkArtifactSetIdentity,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkClaimProofBundle, ZkClaimProofBundleKind,
        ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver, ZkClaimProofBundleWitness,
        ZkPresentationBoundClaimBundleVerifier, ZkPresentationBoundClaimBundleVerifyRequest,
        ZkPresentationBoundClaimStatement,
    },
    common_root::ZkCommonCredentialRootRawPublicInputs,
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer},
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding, ZkWitness},
};

/// Largest allowed delay between producing a request-bound status proof and
/// checking it. The current issuer feed is authenticated separately at the
/// verifier's clock, so an old proof cannot pin an old status root.
pub const MAX_REQUEST_BOUND_STATUS_PROOF_AGE_SECONDS: u64 = 5 * 60;

/// Public fields from the exact issuer-status source circuit. These fields are
/// claims until the backend verifies the matching proof and pinned artifact.
pub struct ZkIssuerCredentialStatusStatement {
    issuer: ZkIssuerPublicKey,
    expiry_unix: u64,
    credential_binding: [u8; 32],
    status_feed: ZkIssuerStatusFeed,
    status_validation_time_unix: u64,
}

impl ZkIssuerCredentialStatusStatement {
    pub(crate) const fn from_parts(
        issuer: ZkIssuerPublicKey,
        expiry_unix: u64,
        credential_binding: [u8; 32],
        status_feed: ZkIssuerStatusFeed,
        status_validation_time_unix: u64,
    ) -> Self {
        Self {
            issuer,
            expiry_unix,
            credential_binding,
            status_feed,
            status_validation_time_unix,
        }
    }

    /// Issuer key claimed by the proof's public inputs.
    #[must_use]
    pub const fn issuer(&self) -> ZkIssuerPublicKey {
        self.issuer
    }

    /// Request-scoped credential commitment claimed by the proof.
    #[must_use]
    pub const fn credential_binding(&self) -> &[u8; 32] {
        &self.credential_binding
    }

    /// Issuer-signed status-list identity claimed by the proof.
    #[must_use]
    pub fn status_pointer(&self) -> ZkIssuerStatusListPointer {
        ZkIssuerStatusListPointer {
            list_id: self.status_feed.list_id,
            url_hash: self.status_feed.url_hash,
            purpose: self.status_feed.purpose,
        }
    }

    fn validate_against(
        &self,
        claim: &ZkPresentationBoundClaimStatement,
        current_feed: &ZkIssuerStatusFeed,
        verification_time_unix: u64,
        expected_status_purpose: crate::issuer_status::ZkIssuerStatusPurpose,
    ) -> Result<(), ZkError> {
        self.validate_claim_binding(claim)?;
        let age = verification_time_unix
            .checked_sub(self.status_validation_time_unix)
            .ok_or(ZkError::new(ZkErrorReason::PresentationExpired))?;
        if self.status_validation_time_unix == 0 || age > MAX_REQUEST_BOUND_STATUS_PROOF_AGE_SECONDS
        {
            return Err(ZkError::new(ZkErrorReason::PresentationExpired));
        }
        if self.status_feed.purpose != expected_status_purpose
            || self.status_feed.purpose != current_feed.purpose
            || self.status_feed.length != current_feed.length
            || !bool::from(self.status_feed.root.ct_eq(&current_feed.root))
            || !bool::from(self.status_feed.list_id.ct_eq(&current_feed.list_id))
            || !bool::from(self.status_feed.url_hash.ct_eq(&current_feed.url_hash))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    fn validate_claim_binding(
        &self,
        claim: &ZkPresentationBoundClaimStatement,
    ) -> Result<(), ZkError> {
        if self.issuer != claim.issuer()
            || self.expiry_unix != claim.presentation_expiry_unix()
            || !bool::from(self.credential_binding.ct_eq(&claim.credential_binding()))
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }
}

impl Drop for ZkIssuerCredentialStatusStatement {
    fn drop(&mut self) {
        self.credential_binding.zeroize();
    }
}

/// Raw proof package for the shared issuer-signed validity/status circuit.
/// Its exact source ref is checked before the backend receives it.
pub struct ZkIssuerCredentialStatusProof {
    proof_suite: ZkProofSuite,
    artifact_set_identity_sha256: ZkArtifactSetIdentity,
    proof_bytes: ZkProofBytes,
    public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

impl ZkIssuerCredentialStatusProof {
    /// Validate the source circuit, suite and artifact metadata.
    pub fn try_from_parts(
        proof_suite: ZkProofSuite,
        artifact_set_identity_sha256: ZkArtifactSetIdentity,
        proof_bytes: ZkProofBytes,
        public_inputs: ZkCommonCredentialRootRawPublicInputs,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        if artifact_set_identity_sha256.is_zero() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let circuit_ref = public_inputs.circuit_ref();
        if circuit_ref
            != ZkCircuitRef::new(
                circuit_ref.credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::IssuerCredentialStatus,
            )
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Ok(Self {
            proof_suite,
            artifact_set_identity_sha256,
            proof_bytes,
            public_inputs,
        })
    }

    /// Exact backend suite.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Pinned artifact manifest digest.
    #[must_use]
    pub const fn artifact_set_identity_sha256(&self) -> ZkArtifactSetIdentity {
        self.artifact_set_identity_sha256
    }

    /// Bounded proof bytes.
    #[must_use]
    pub const fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    /// Canonical raw field stream.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        &self.public_inputs
    }
}

/// Linked-library backend boundary for the exact issuer-status circuit.
pub trait ZkIssuerCredentialStatusVerifier: Send + Sync {
    /// Verify proof bytes against the exact pinned artifact and public inputs.
    fn verify_issuer_credential_status(
        &self,
        proof: &ZkIssuerCredentialStatusProof,
    ) -> Result<(), ZkError>;
}

/// Injected prover for the exact issuer validity and hidden-index status
/// circuit. Open-stack wallets depend on this trait, never on a BB backend.
pub trait ZkIssuerCredentialStatusProver: Send + Sync {
    /// Prove and verify one pinned fifth stage for the active request.
    fn prove_issuer_credential_status(
        &self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        witness: &ZkWitness,
        session_binding: ZkSessionBinding,
    ) -> Result<ZkIssuerCredentialStatusProof, ZkError>;
}

/// Owned, structurally complete direct/private claim with issuer validity and
/// current-status proof. Transport adapters must admit both pieces together.
pub struct ZkStatusQualifiedClaimProofBundle {
    claim_proof_bundle: ZkClaimProofBundle,
    issuer_credential_status: ZkIssuerCredentialStatusProof,
}

impl ZkStatusQualifiedClaimProofBundle {
    /// Enforce the shared suite, hash lane, and active request before storing
    /// a bundle or handing it to a verifier.
    pub fn try_from_parts(
        claim_proof_bundle: ZkClaimProofBundle,
        issuer_credential_status: ZkIssuerCredentialStatusProof,
    ) -> Result<Self, ZkError> {
        if claim_proof_bundle.proof_suite() != issuer_credential_status.proof_suite() {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let first_stage = claim_proof_bundle
            .stage_proofs()
            .first()
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        if first_stage.proof().circuit_ref().credential_hash_algorithm
            != issuer_credential_status
                .public_inputs()
                .circuit_ref()
                .credential_hash_algorithm
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        issuer_credential_status
            .public_inputs()
            .validate_session_binding(claim_proof_bundle.session_binding())?;
        let claimed = claim_proof_bundle.decode_claimed_statement()?;
        let status_claim = issuer_credential_status
            .public_inputs()
            .issuer_credential_status_statement()?;
        if status_claim.issuer() != claimed.issuer()
            || status_claim.expiry_unix != claimed.presentation_expiry_unix()
            || !bool::from(
                status_claim
                    .credential_binding()
                    .ct_eq(&claimed.credential_binding()),
            )
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(Self {
            claim_proof_bundle,
            issuer_credential_status,
        })
    }

    /// Four-stage request-bound claim evidence.
    #[must_use]
    pub const fn claim_proof_bundle(&self) -> &ZkClaimProofBundle {
        &self.claim_proof_bundle
    }

    /// Fifth proof over issuer-signed validity and current status.
    #[must_use]
    pub const fn issuer_credential_status(&self) -> &ZkIssuerCredentialStatusProof {
        &self.issuer_credential_status
    }
}

/// Prove all four claim stages and the issuer validity/status stage as one
/// typed unit. A product wallet supplies witnesses from its authenticated
/// selected record and current status opening; the backend resolves pinned
/// artifacts. Neither proof is exposed to a presentation adapter until the
/// credential and session joins pass.
pub fn prove_status_qualified_claim_proof_bundle_with(
    claim_proof_bundle_prover: &dyn ZkClaimProofBundleProver,
    status_prover: &dyn ZkIssuerCredentialStatusProver,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    claim_proof_bundle_witness: &ZkClaimProofBundleWitness,
    status_witness: &ZkWitness,
    session_binding: ZkSessionBinding,
) -> Result<ZkStatusQualifiedClaimProofBundle, ZkError> {
    let expected_status_ref = ZkCircuitRef::new(
        credential_hash_algorithm,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::IssuerCredentialStatus,
    );
    if status_witness.circuit_ref() != expected_status_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let request = ZkClaimProofBundleProveRequest::try_new(
        bundle_kind,
        credential_hash_algorithm,
        ZkProofSuite::PRODUCTION,
        claim_proof_bundle_witness,
        session_binding,
    )?;
    let bundle = claim_proof_bundle_prover.prove_claim_proof_bundle(request)?;
    let status = status_prover.prove_issuer_credential_status(
        credential_hash_algorithm,
        status_witness,
        session_binding,
    )?;
    ZkStatusQualifiedClaimProofBundle::try_from_parts(bundle, status)
}

/// Verifier policy and complete evidence for one direct or private claim.
pub struct ZkStatusQualifiedClaimProofBundleVerifyRequest<'a> {
    bundle_request: ZkPresentationBoundClaimBundleVerifyRequest<'a>,
    status_proof: &'a ZkIssuerCredentialStatusProof,
    status_authority: &'a dyn ZkIssuerStatusAuthority,
    expected_status_purpose: crate::issuer_status::ZkIssuerStatusPurpose,
}

impl<'a> ZkStatusQualifiedClaimProofBundleVerifyRequest<'a> {
    /// Require exact suite, hash lane, and active-session public inputs before
    /// any network-backed status lookup is allowed.
    pub fn try_new(
        bundle_request: ZkPresentationBoundClaimBundleVerifyRequest<'a>,
        status_proof: &'a ZkIssuerCredentialStatusProof,
        status_authority: &'a dyn ZkIssuerStatusAuthority,
        expected_status_purpose: crate::issuer_status::ZkIssuerStatusPurpose,
    ) -> Result<Self, ZkError> {
        if status_proof.proof_suite() != bundle_request.expected_proof_suite() {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let first_stage = bundle_request
            .bundle()
            .stage_proofs()
            .first()
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        let expected_credential_hash_algorithm =
            first_stage.proof().circuit_ref().credential_hash_algorithm;
        if status_proof
            .public_inputs()
            .circuit_ref()
            .credential_hash_algorithm
            != expected_credential_hash_algorithm
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        status_proof
            .public_inputs()
            .validate_session_binding(bundle_request.expected_binding())?;
        Ok(Self {
            bundle_request,
            status_proof,
            status_authority,
            expected_status_purpose,
        })
    }

    /// Selected source hash lane for the fifth proof.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.status_proof
            .public_inputs()
            .circuit_ref()
            .credential_hash_algorithm
    }
}

/// Complete result minted only after both proof verifiers, all joins, and an
/// independently authenticated current issuer feed succeed.
pub struct ZkStatusQualifiedClaimProofBundleVerification {
    bundle_kind: ZkClaimProofBundleKind,
    proof_suite: ZkProofSuite,
    status_purpose: crate::issuer_status::ZkIssuerStatusPurpose,
    statement: ZkVerifiedClaimStatement,
}

impl ZkStatusQualifiedClaimProofBundleVerification {
    /// Issuer-authenticated claim that is valid at the verifier clock and
    /// active in the selected issuer status feed.
    #[must_use]
    pub const fn statement(&self) -> &ZkVerifiedClaimStatement {
        &self.statement
    }

    /// Source bundle_kind that established the request-bound claim.
    #[must_use]
    pub const fn bundle_kind(&self) -> crate::claim_bundle::ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Exact suite under which all five proofs were verified.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Issuer status purpose whose current list was checked. A credential
    /// subject to another purpose needs separate evidence for that purpose.
    #[must_use]
    pub const fn status_purpose(&self) -> crate::issuer_status::ZkIssuerStatusPurpose {
        self.status_purpose
    }
}

/// Verify all five proofs, the exact shared credential commitment, and the
/// current issuer feed. The authority must authenticate signature, issuer,
/// freshness, and a durable rollback floor before returning a feed.
pub fn verify_status_qualified_claim_proof_bundle_with(
    bundle_verifier: &dyn ZkPresentationBoundClaimBundleVerifier,
    status_verifier: &dyn ZkIssuerCredentialStatusVerifier,
    request: ZkStatusQualifiedClaimProofBundleVerifyRequest<'_>,
) -> Result<ZkStatusQualifiedClaimProofBundleVerification, ZkError> {
    let bundle =
        verify_presentation_bound_claim_bundle_with(bundle_verifier, request.bundle_request)?;
    status_verifier.verify_issuer_credential_status(request.status_proof)?;
    let status = request
        .status_proof
        .public_inputs()
        .issuer_credential_status_statement()?;
    // Reject a valid proof borrowed from another credential before consulting
    // an authority that may persist a newer status-list rollback floor.
    status.validate_claim_binding(bundle.statement())?;
    let pointer = status.status_pointer();
    if pointer.purpose != request.expected_status_purpose {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let current_feed = request.status_authority.current_feed_for_issuer(
        &bundle.statement().issuer(),
        &pointer,
        request.bundle_request.verification_time_unix(),
    )?;
    status.validate_against(
        bundle.statement(),
        &current_feed,
        request.bundle_request.verification_time_unix(),
        request.expected_status_purpose,
    )?;
    // Keep the stronger capability private to this boundary: four-proof
    // evidence cannot be promoted by a caller or a transport decoder.
    Ok(ZkStatusQualifiedClaimProofBundleVerification {
        bundle_kind: bundle.bundle_kind(),
        proof_suite: bundle.proof_suite(),
        status_purpose: request.expected_status_purpose,
        statement: ZkVerifiedClaimStatement {
            presentation: bundle.into_statement(),
        },
    })
}

/// Credential claim verified against issuer trust, signed validity, current
/// status, and the active presentation binding at the verifier's clock.
///
/// Only status-qualified verification constructs this type. It does not consume
/// a session nonce; the protocol must atomically consume the active session
/// before granting access. The contained sensitive bytes retain their
/// zeroizing owner and are redacted from diagnostics.
///
/// ```compile_fail
/// use reallyme_zk_api::claim_bundle::{
///     ZkPresentationBoundClaimBundleVerification, ZkVerifiedClaimStatement,
/// };
/// fn accept(_: &ZkVerifiedClaimStatement) {}
/// fn incorrect(evidence: &ZkPresentationBoundClaimBundleVerification) {
///     accept(evidence.statement());
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ZkVerifiedClaimStatement {
    presentation: ZkPresentationBoundClaimStatement,
}
