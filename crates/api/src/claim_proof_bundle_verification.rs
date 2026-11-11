// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkCompatibilitySuiteAcknowledgement,
    },
    errors::{ZkError, ZkErrorReason},
    keys::{ZkIssuerPublicKey, ZkPersonaPublicKey},
    proofs::{ZkProofSuite, ZkSessionBinding},
};
use zeroize::Zeroize;

/// Maximum issuer keys accepted from one verifier trust policy.
pub const MAX_TRUSTED_ISSUERS: usize = 64;

/// Default maximum lifetime of one presentation proof.
///
/// This limits replay exposure for the holder-chosen presentation expiry. It
/// does not claim that the underlying credential has an issuer-signed validity
/// interval or revocation proof.
pub const MAX_PRESENTATION_LIFETIME_SECONDS: u64 = 5 * 60;

/// Request passed to an injected production bundle verifier.
#[derive(Debug, Clone, Copy)]
pub struct ZkPresentationBoundClaimBundleVerifyRequest<'a> {
    /// Proof bundle to verify.
    bundle: &'a ZkClaimProofBundle,
    /// Exact suite selected by verifier policy.
    expected_proof_suite: ZkProofSuite,
    /// Binding expected for the active verifier session.
    expected_binding: ZkSessionBinding,
    /// Exact issuer keys trusted for this verification context.
    trusted_issuers: &'a [ZkIssuerPublicKey],
    /// Trusted verifier clock as a Unix timestamp.
    verification_time_unix: u64,
}

impl<'a> ZkPresentationBoundClaimBundleVerifyRequest<'a> {
    /// Builds a bounded, fail-closed production verification request.
    pub fn try_new(
        bundle: &'a ZkClaimProofBundle,
        expected_proof_suite: ZkProofSuite,
        expected_binding: ZkSessionBinding,
        trusted_issuers: &'a [ZkIssuerPublicKey],
        verification_time_unix: u64,
    ) -> Result<Self, ZkError> {
        expected_proof_suite.require_production()?;
        Self::try_new_with_suite_policy(
            bundle,
            expected_proof_suite,
            expected_binding,
            trusted_issuers,
            verification_time_unix,
        )
    }

    /// Builds an explicitly acknowledged compatibility verification request.
    pub fn try_new_compatibility(
        bundle: &'a ZkClaimProofBundle,
        expected_proof_suite: ZkProofSuite,
        expected_binding: ZkSessionBinding,
        trusted_issuers: &'a [ZkIssuerPublicKey],
        verification_time_unix: u64,
        _acknowledgement: ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if expected_proof_suite == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(
            bundle,
            expected_proof_suite,
            expected_binding,
            trusted_issuers,
            verification_time_unix,
        )
    }

    fn try_new_with_suite_policy(
        bundle: &'a ZkClaimProofBundle,
        expected_proof_suite: ZkProofSuite,
        expected_binding: ZkSessionBinding,
        trusted_issuers: &'a [ZkIssuerPublicKey],
        verification_time_unix: u64,
    ) -> Result<Self, ZkError> {
        if trusted_issuers.is_empty() {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        if trusted_issuers.len() > MAX_TRUSTED_ISSUERS {
            return Err(ZkError::new(ZkErrorReason::PublicKeyTooLarge));
        }
        if verification_time_unix == 0 {
            return Err(ZkError::new(ZkErrorReason::PresentationExpired));
        }
        if bundle.proof_suite() != expected_proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        validate_expected_binding_for_bundle(bundle, expected_binding)?;
        if bundle.session_binding() != expected_binding {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        let statement = bundle.decode_claimed_statement()?;
        if !trusted_issuers.contains(&statement.issuer()) {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        validate_presentation_expiry(statement.presentation_expiry_unix(), verification_time_unix)?;
        Ok(Self {
            bundle,
            expected_proof_suite,
            expected_binding,
            trusted_issuers,
            verification_time_unix,
        })
    }

    /// Proof bundle to verify.
    #[must_use]
    pub const fn bundle(&self) -> &'a ZkClaimProofBundle {
        self.bundle
    }

    /// Exact suite selected by verifier policy.
    #[must_use]
    pub const fn expected_proof_suite(&self) -> ZkProofSuite {
        self.expected_proof_suite
    }

    /// Binding expected for the active verifier session.
    #[must_use]
    pub const fn expected_binding(&self) -> ZkSessionBinding {
        self.expected_binding
    }

    /// Exact issuer keys trusted for this context.
    #[must_use]
    pub const fn trusted_issuers(&self) -> &'a [ZkIssuerPublicKey] {
        self.trusted_issuers
    }

    /// Trusted verifier clock.
    #[must_use]
    pub const fn verification_time_unix(&self) -> u64 {
        self.verification_time_unix
    }
}

fn validate_expected_binding_for_bundle(
    bundle: &ZkClaimProofBundle,
    expected_binding: ZkSessionBinding,
) -> Result<(), ZkError> {
    for stage_proof in bundle.stage_proofs() {
        expected_binding.validate_for_circuit(stage_proof.proof().circuit_ref())?;
    }
    Ok(())
}

fn validate_presentation_expiry(
    expiry_unix: u64,
    verification_time_unix: u64,
) -> Result<(), ZkError> {
    let remaining_lifetime = expiry_unix
        .checked_sub(verification_time_unix)
        .ok_or(ZkError::new(ZkErrorReason::PresentationExpired))?;
    if remaining_lifetime == 0 {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    if remaining_lifetime > MAX_PRESENTATION_LIFETIME_SECONDS {
        return Err(ZkError::new(ZkErrorReason::PresentationExpiryTooFar));
    }
    Ok(())
}

/// Public claim statement decoded from a structurally complete bundle.
///
/// The fixed-width claim value is deliberately omitted from `Debug` to keep
/// disclosed identity data out of incidental diagnostics.
#[derive(PartialEq, Eq)]
pub struct ZkClaimedStatement {
    issuer: ZkIssuerPublicKey,
    persona: Option<ZkPersonaPublicKey>,
    credential_binding: [u8; 32],
    claim_name_hash: [u8; 32],
    claim_value: [u8; 64],
    claim_value_length: u8,
    presentation_expiry_unix: u64,
}

impl ZkClaimedStatement {
    /// Validates one untrusted, fixed-width disclosed statement.
    pub fn try_from_parts(
        issuer: ZkIssuerPublicKey,
        persona: Option<ZkPersonaPublicKey>,
        credential_binding: [u8; 32],
        claim_name_hash: [u8; 32],
        claim_value: [u8; 64],
        claim_value_length: u32,
        presentation_expiry_unix: u64,
    ) -> Result<Self, ZkError> {
        let claim_value_length = usize::try_from(claim_value_length)
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        if claim_value_length == 0 || claim_value_length > claim_value.len() {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        if claim_value[claim_value_length..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        let claim_value_length = u8::try_from(claim_value_length)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        Ok(Self {
            issuer,
            persona,
            credential_binding,
            claim_name_hash,
            claim_value,
            claim_value_length,
            presentation_expiry_unix,
        })
    }

    /// Issuer key claimed by this unverified statement.
    ///
    /// Only a `ZkPresentationBoundClaimBundleVerification` establishes that the complete bundle was
    /// verified and the issuer admitted by verifier policy.
    #[must_use]
    pub const fn issuer(&self) -> ZkIssuerPublicKey {
        self.issuer
    }

    /// Public persona key for the intentionally public persona bundle_kind.
    #[must_use]
    pub const fn persona(&self) -> Option<ZkPersonaPublicKey> {
        self.persona
    }

    /// Redacted credential/root commitment for same-credential composition.
    #[must_use]
    pub const fn credential_binding(&self) -> [u8; 32] {
        self.credential_binding
    }

    /// Hash of the disclosed claim name.
    #[must_use]
    pub const fn claim_name_hash(&self) -> [u8; 32] {
        self.claim_name_hash
    }

    /// Disclosed claim bytes without zero padding.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        &self.claim_value[..usize::from(self.claim_value_length)]
    }

    /// Presentation expiry claimed by this unverified statement.
    ///
    /// The verifier clock check occurs when constructing the bundle verification
    /// request; this accessor alone carries no validity assertion.
    #[must_use]
    pub const fn presentation_expiry_unix(&self) -> u64 {
        self.presentation_expiry_unix
    }
}

impl core::fmt::Debug for ZkClaimedStatement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkClaimedStatement")
            .field("issuer", &self.issuer)
            .field("persona", &self.persona)
            .field("credential_binding", &"<redacted>")
            .field("claim_name_hash", &"<redacted>")
            .field("claim_value", &"<redacted>")
            .field("claim_value_length", &self.claim_value_length)
            .field("presentation_expiry_unix", &self.presentation_expiry_unix)
            .finish()
    }
}

impl Drop for ZkClaimedStatement {
    fn drop(&mut self) {
        self.credential_binding.zeroize();
        self.claim_name_hash.zeroize();
        self.claim_value.zeroize();
        self.claim_value_length.zeroize();
    }
}

/// Claim evidence bound to a trusted issuer and active presentation request.
///
/// This type does not establish issuer-signed credential validity or current
/// status. Credential acceptance must consume `ZkVerifiedClaimStatement` from
/// the status-qualified verification boundary instead.
#[derive(PartialEq, Eq)]
pub struct ZkPresentationBoundClaimStatement {
    claimed: ZkClaimedStatement,
    session_link_commitment: [u8; 32],
}

impl ZkPresentationBoundClaimStatement {
    pub(crate) const fn from_claimed(
        claimed: ZkClaimedStatement,
        session_link_commitment: [u8; 32],
    ) -> Self {
        Self {
            claimed,
            session_link_commitment,
        }
    }

    /// Issuer key proven by the complete bundle and admitted by trust policy.
    #[must_use]
    pub const fn issuer(&self) -> ZkIssuerPublicKey {
        self.claimed.issuer()
    }

    /// Public persona key for the intentionally public persona bundle_kind.
    #[must_use]
    pub const fn persona(&self) -> Option<ZkPersonaPublicKey> {
        self.claimed.persona()
    }

    /// Redacted credential/root commitment for same-credential composition.
    ///
    /// This binds issuer key, credential envelope, credential root, and active
    /// verifier request. It does not prove reserved claim-name uniqueness or
    /// revocation status; verifier policy must establish those separately.
    #[must_use]
    pub const fn credential_binding(&self) -> [u8; 32] {
        self.claimed.credential_binding()
    }

    /// Hash of the disclosed claim name.
    #[must_use]
    pub const fn claim_name_hash(&self) -> [u8; 32] {
        self.claimed.claim_name_hash()
    }

    /// Disclosed claim bytes without zero padding.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        self.claimed.claim_value()
    }

    /// Presentation expiry checked against the verifier clock.
    #[must_use]
    pub const fn presentation_expiry_unix(&self) -> u64 {
        self.claimed.presentation_expiry_unix()
    }

    /// Redacted commitment used to compare the verified session link without
    /// exposing subject or private-persona key material.
    ///
    /// For persona presentations this is a persona/session continuity signal, not
    /// proof that two distinct credential subject keys identify the same
    /// underlying person. Callers that need that stronger assertion must use a
    /// proof composition that establishes it directly.
    #[must_use]
    pub const fn session_link_commitment(&self) -> [u8; 32] {
        self.session_link_commitment
    }

    /// Requires two independently verified statements to carry the same
    /// session link commitment.
    ///
    /// This is intentionally narrower than an identity-equivalence predicate:
    /// credential-subject claim bundles establish subject continuity, while
    /// private-persona claim bundles establish only the same hidden persona
    /// continuity authorized for the active verifier session.
    pub fn require_same_session_link(&self, other: &Self) -> Result<(), ZkError> {
        if self.session_link_commitment != other.session_link_commitment {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    /// Requires two independently verified statements to come from the same
    /// credential commitment in this active presentation.
    ///
    /// This is the correct join handle when application policy wants to pair a
    /// business claim with another disclosed leaf, such as issuer-signed
    /// validity metadata. It intentionally does not claim Merkle-key
    /// uniqueness or revocation; those remain issuer/bundle_kind policy.
    pub fn require_same_credential_binding(&self, other: &Self) -> Result<(), ZkError> {
        if self.credential_binding() != other.credential_binding() {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }
}

impl Drop for ZkPresentationBoundClaimStatement {
    fn drop(&mut self) {
        self.session_link_commitment.zeroize();
    }
}

impl core::fmt::Debug for ZkPresentationBoundClaimStatement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkPresentationBoundClaimStatement")
            .field("issuer", &self.issuer())
            .field("persona", &self.persona())
            .field("credential_binding", &"<redacted>")
            .field("claim_name_hash", &"<redacted>")
            .field("claim_value", &"<redacted>")
            .field("session_link_commitment", &"<redacted>")
            .field("presentation_expiry_unix", &self.presentation_expiry_unix())
            .finish()
    }
}

#[cfg(test)]
mod tests;

/// Four-proof presentation evidence, without credential validity or status.
///
/// This result cannot satisfy a credential-acceptance boundary:
///
/// ```compile_fail
/// use reallyme_zk_api::claim_bundle::{
///     ZkPresentationBoundClaimBundleVerification,
///     ZkStatusQualifiedClaimProofBundleVerification,
/// };
/// fn accept(_: &ZkStatusQualifiedClaimProofBundleVerification) {}
/// fn incorrect(evidence: &ZkPresentationBoundClaimBundleVerification) {
///     accept(evidence);
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ZkPresentationBoundClaimBundleVerification {
    bundle_kind: ZkClaimProofBundleKind,
    verified_stage_count: u8,
    proof_suite: ZkProofSuite,
    statement: ZkPresentationBoundClaimStatement,
}

impl ZkPresentationBoundClaimBundleVerification {
    /// Builds a successful bundle verification result.
    #[must_use]
    pub(crate) const fn from_verified(
        bundle_kind: ZkClaimProofBundleKind,
        verified_stage_count: u8,
        proof_suite: ZkProofSuite,
        statement: ZkPresentationBoundClaimStatement,
    ) -> Self {
        Self {
            bundle_kind,
            verified_stage_count,
            proof_suite,
            statement,
        }
    }

    /// Verified production bundle_kind.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Number of verified production stages.
    #[must_use]
    pub const fn verified_stage_count(&self) -> u8 {
        self.verified_stage_count
    }

    /// Exact suite used to verify every stage.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Typed public statement established by the complete bundle.
    #[must_use]
    pub const fn statement(&self) -> &ZkPresentationBoundClaimStatement {
        &self.statement
    }

    pub(crate) fn into_statement(self) -> ZkPresentationBoundClaimStatement {
        self.statement
    }
}
