// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral, durable replay boundary for prepared presentations.

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A verifier-authenticated challenge, independent of its transport encoding.
/// The protocol adapter validates the full request before constructing this
/// value. Both the nonce and audience digest are erased when it is dropped.
pub struct ZkPersonaCredentialEvidenceReplayChallenge {
    nonce: [u8; 32],
    audience_sha256: [u8; 32],
    expires_at_unix: u64,
}

impl ZkPersonaCredentialEvidenceReplayChallenge {
    /// Construct a challenge from a validated verifier request.
    pub fn try_new(
        nonce: &[u8; 32],
        audience_sha256: &[u8; 32],
        expires_at_unix: u64,
    ) -> Result<Self, ZkPersonaCredentialEvidenceReplayError> {
        if nonce.iter().all(|byte| *byte == 0)
            || audience_sha256.iter().all(|byte| *byte == 0)
            || expires_at_unix == 0
        {
            return Err(ZkPersonaCredentialEvidenceReplayError::invalid_challenge());
        }
        Ok(Self {
            nonce: *nonce,
            audience_sha256: *audience_sha256,
            expires_at_unix,
        })
    }

    /// Single-use nonce from the authenticated request.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Digest of the authenticated verifier identity and origin.
    #[must_use]
    pub const fn audience_sha256(&self) -> &[u8; 32] {
        &self.audience_sha256
    }

    /// Exclusive expiry of the authenticated request.
    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl Drop for ZkPersonaCredentialEvidenceReplayChallenge {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.audience_sha256.zeroize();
        self.expires_at_unix.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceReplayChallenge {}

/// Stable replay-store rejection with no challenge or request contents.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ZkPersonaCredentialEvidenceReplayReason {
    /// The authenticated request supplied an invalid or expired challenge.
    #[error("invalid prepared challenge")]
    InvalidChallenge,
    /// This verifier has already accepted the audience-scoped nonce.
    #[error("prepared challenge already consumed")]
    AlreadyConsumed,
    /// Durable replay state cannot be safely read or committed.
    #[error("prepared replay store unavailable")]
    StoreUnavailable,
}

/// Typed replay error suitable for deterministic adapter mapping.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("prepared replay rejected: {reason}")]
pub struct ZkPersonaCredentialEvidenceReplayError {
    reason: ZkPersonaCredentialEvidenceReplayReason,
}

impl ZkPersonaCredentialEvidenceReplayError {
    /// Return the non-sensitive reason.
    #[must_use]
    pub const fn reason(self) -> ZkPersonaCredentialEvidenceReplayReason {
        self.reason
    }

    /// Invalid or expired challenge.
    #[must_use]
    pub const fn invalid_challenge() -> Self {
        Self {
            reason: ZkPersonaCredentialEvidenceReplayReason::InvalidChallenge,
        }
    }

    /// Audience-scoped nonce previously consumed.
    #[must_use]
    pub const fn already_consumed() -> Self {
        Self {
            reason: ZkPersonaCredentialEvidenceReplayReason::AlreadyConsumed,
        }
    }

    /// Durable state is unavailable or uncertain.
    #[must_use]
    pub const fn store_unavailable() -> Self {
        Self {
            reason: ZkPersonaCredentialEvidenceReplayReason::StoreUnavailable,
        }
    }
}

/// Atomic, restart-safe challenge consumption after proof and signature checks.
/// Stores that prune expired nonces must retain a durable high-water clock so
/// a clock rollback cannot revive a previously consumed challenge.
pub trait ZkPersonaCredentialEvidenceReplayStore: Send + Sync {
    /// Persist acceptance before returning success; reject later reuse.
    fn consume(
        &self,
        challenge: &ZkPersonaCredentialEvidenceReplayChallenge,
        now_unix: u64,
    ) -> Result<(), ZkPersonaCredentialEvidenceReplayError>;
}

#[cfg(test)]
#[path = "persona_credential_evidence_replay/tests.rs"]
mod tests;
