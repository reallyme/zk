// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only access to the status-qualified claim capability. Its private
//! representation and construction remain in the verification boundary.

use super::ZkVerifiedClaimStatement;
use crate::{errors::ZkError, keys::ZkIssuerPublicKey};

impl ZkVerifiedClaimStatement {
    /// Issuer admitted by the verifier's trust policy.
    #[must_use]
    pub const fn issuer(&self) -> ZkIssuerPublicKey {
        self.presentation.issuer()
    }

    /// Public persona key, when exposed by the selected bundle kind.
    #[must_use]
    pub const fn persona(&self) -> Option<crate::keys::ZkPersonaPublicKey> {
        self.presentation.persona()
    }

    /// Request-scoped commitment shared by the claim and status proofs.
    #[must_use]
    pub const fn credential_binding(&self) -> [u8; 32] {
        self.presentation.credential_binding()
    }

    /// Hash of the verified claim name.
    #[must_use]
    pub const fn claim_name_hash(&self) -> [u8; 32] {
        self.presentation.claim_name_hash()
    }

    /// Verified disclosed claim bytes without padding.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        self.presentation.claim_value()
    }

    /// Presentation expiry checked against the verifier's clock.
    #[must_use]
    pub const fn presentation_expiry_unix(&self) -> u64 {
        self.presentation.presentation_expiry_unix()
    }

    /// Presentation-scoped subject or persona continuity commitment.
    #[must_use]
    pub const fn session_link_commitment(&self) -> [u8; 32] {
        self.presentation.session_link_commitment()
    }

    /// Require the same session link without asserting identity equivalence.
    pub fn require_same_session_link(&self, other: &Self) -> Result<(), ZkError> {
        self.presentation
            .require_same_session_link(&other.presentation)
    }

    /// Require the same credential commitment within the active presentation.
    pub fn require_same_credential_binding(&self, other: &Self) -> Result<(), ZkError> {
        self.presentation
            .require_same_credential_binding(&other.presentation)
    }
}
