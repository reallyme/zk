// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitId, ZkCircuitRef},
    claim_bundle::{ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimedStatement},
    common_root::ZkCommonCredentialRootPersonaMode,
    errors::ZkError,
    issuer_status::ZkIssuerStatusPurpose,
    persona_evidence::ZkPersonaCredentialEvidenceStageProof,
    proofs::{ZkProof, ZkProofSuite},
};
use reallyme_zk_artifacts::{Digest32, ProductionArtifactManifest};
use zeroize::{Zeroize, Zeroizing};

use crate::common_credential_root::{
    ZkCommonCredentialRootPresentation, ZkCommonCredentialRootRawProofPackage,
};
use crate::persona_credential_evidence_stage_proof::ZkPersonaCredentialEvidenceStageVerificationReport;

use super::{ZkStageWitnessReleaseReport, ZkStageWitnessReport};

/// Untrusted provider report claiming successful complete-bundle verification.
///
/// This is transport data, not an API verification capability. Callers must
/// correlate it to the exact request and independently invoke their injected
/// `ZkPresentationBoundClaimBundleVerifier` before obtaining a verified domain value.
#[derive(PartialEq, Eq)]
pub struct ZkClaimProofBundleVerificationReport {
    /// Claimed production profile.
    pub bundle_kind: ZkClaimProofBundleKind,
    /// Claimed number of verified stages.
    pub verified_stage_count: u8,
    /// Claimed proof suite.
    pub proof_suite: ZkProofSuite,
    /// Structurally validated but unverified public statement.
    pub statement: ZkClaimedStatement,
    /// Presentation-scoped link commitment. Reused verifier inputs can make
    /// this value correlatable, so callers must treat it as sensitive.
    pub session_link_commitment: [u8; 32],
}

impl core::fmt::Debug for ZkClaimProofBundleVerificationReport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkClaimProofBundleVerificationReport")
            .field("profile", &self.bundle_kind)
            .field("verified_stage_count", &self.verified_stage_count)
            .field("proof_suite", &self.proof_suite)
            .field("statement", &"<redacted>")
            .field("session_link_commitment", &"<redacted>")
            .finish()
    }
}

impl Drop for ZkClaimProofBundleVerificationReport {
    fn drop(&mut self) {
        self.session_link_commitment.zeroize();
    }
}

/// Provider report for a five-proof status-qualified verification.
///
/// Like every decoded report this is an untrusted claim until the adapter has
/// matched it to the request it sent. It is distinct from the four-proof
/// report so the two cannot be confused by a consumer.
#[derive(PartialEq, Eq)]
pub struct ZkStatusQualifiedClaimProofBundleVerificationReport {
    /// Bundle kind reported by the provider.
    pub bundle_kind: ZkClaimProofBundleKind,
    /// Number of proofs the provider reports it verified.
    pub verified_proof_count: u8,
    /// Suite reported by the provider.
    pub proof_suite: ZkProofSuite,
    /// Issuer status purpose whose current list was checked.
    pub status_purpose: ZkIssuerStatusPurpose,
    /// Public statement reported by the provider.
    pub statement: ZkClaimedStatement,
    /// Session-link commitment reported by the provider.
    pub session_link_commitment: [u8; 32],
}

impl core::fmt::Debug for ZkStatusQualifiedClaimProofBundleVerificationReport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkStatusQualifiedClaimProofBundleVerificationReport")
            .field("bundle_kind", &self.bundle_kind)
            .field("verified_proof_count", &self.verified_proof_count)
            .field("proof_suite", &self.proof_suite)
            .field("status_purpose", &self.status_purpose)
            .field("statement", &"<redacted>")
            .field("session_link_commitment", &"<redacted>")
            .finish()
    }
}

impl Drop for ZkStatusQualifiedClaimProofBundleVerificationReport {
    fn drop(&mut self) {
        self.session_link_commitment.zeroize();
    }
}

/// Untrusted provider report claiming successful diagnostic-stage verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkStageVerificationReport {
    /// Claimed semantic circuit identifier.
    pub circuit_id: ZkCircuitId,
    /// Claimed exact source circuit.
    pub circuit_ref: Option<ZkCircuitRef>,
    /// Claimed proof suite.
    pub proof_suite: ZkProofSuite,
}

/// Untrusted provider report claiming successful common-credential-root verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootVerificationReport {
    /// Claimed common-credential-root profile.
    pub persona_mode: ZkCommonCredentialRootPersonaMode,
    /// Claimed number of verified proof slots.
    pub verified_proof_count: u8,
    /// Claimed proof suite.
    pub proof_suite: ZkProofSuite,
}

/// One validated success value from the canonical provider response.
pub enum ZkProviderOperationResult {
    /// Complete production proof bundle.
    ClaimProofBundle(ZkClaimProofBundle),
    /// Successful complete-bundle verification.
    ClaimProofBundleVerification(Box<ZkClaimProofBundleVerificationReport>),
    /// Five-proof status-qualified verification report.
    StatusQualifiedClaimProofBundleVerification(
        Box<ZkStatusQualifiedClaimProofBundleVerificationReport>,
    ),
    /// One exact diagnostic stage proof.
    StageProof(ZkProof),
    /// Successful exact stage verification.
    StageVerification(ZkStageVerificationReport),
    /// Exact hash-pinned artifact manifest.
    ArtifactManifest(Box<ProductionArtifactManifest>),
    /// Native-owned stage witness handle plus public statement.
    StageWitness(Box<ZkStageWitnessReport>),
    /// Native-owned stage witness handle release confirmation.
    StageWitnessRelease(ZkStageWitnessReleaseReport),
    /// Successful common-credential-root presentation verification.
    CommonCredentialRootVerification(ZkCommonCredentialRootVerificationReport),
    /// One common-credential-root source-stage proof package.
    CommonCredentialRootStageProof(ZkCommonCredentialRootRawProofPackage),
    /// Complete common-credential-root presentation in canonical proof-slot order.
    CommonCredentialRootPresentation(Box<ZkCommonCredentialRootPresentation>),
    /// Backend report for one prepared source proof. Higher-level policy must
    /// still authenticate and join the complete presentation.
    PersonaCredentialEvidenceStageVerification(ZkPersonaCredentialEvidenceStageVerificationReport),
    /// Newly proved prepared stage; caller must validate its joins and policy.
    PersonaCredentialEvidenceStageProof(ZkPersonaCredentialEvidenceStageProof),
    /// Challenge for a protected holder key, before verifier acceptance.
    PersonaCredentialEvidencePresentationSigningChallenge(Zeroizing<[u8; 32]>),
    /// Structurally decoded signed transport bytes; still requires full verification.
    PersonaCredentialEvidencePresentation(Zeroizing<Vec<u8>>),
}

/// Validated canonical provider response outcome.
pub enum ZkProviderOperationOutcome {
    /// Typed successful result.
    Success(Box<ZkProviderOperationResult>),
    /// Typed privacy-safe expected failure.
    Failure(ZkError),
}

/// Canonically decoded provider response bound to one exact request digest.
pub struct DecodedOperationResponse {
    pub(super) request_sha256: Digest32,
    pub(super) outcome: ZkProviderOperationOutcome,
}

impl DecodedOperationResponse {
    /// SHA-256 of the exact canonical request bytes named by this response.
    #[must_use]
    pub const fn request_sha256(&self) -> Digest32 {
        self.request_sha256
    }

    /// Consumes the response and returns its typed result or failure.
    #[must_use]
    pub fn into_outcome(self) -> ZkProviderOperationOutcome {
        self.outcome
    }
}
