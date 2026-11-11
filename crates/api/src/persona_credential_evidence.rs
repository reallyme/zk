// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Presentation modes for persona credential evidence.

use thiserror::Error;

/// Proof statement selected by a persona credential evidence presentation.
///
/// Each mode requires an issuer-authenticated credential, a bounded proof
/// window, current credential status, and a live signature by the exact key
/// exposed in the verified proof. The private mode additionally requires
/// one-time wallet reservation before the key or proof may leave the wallet.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ZkPersonaCredentialEvidenceMode {
    /// Reusable evidence exposing the stable public persona key.
    PublicPersonaV1,
    /// One-time evidence exposing a fresh key authorized by a hidden persona.
    PrivatePersonaOneTimeV1,
}

impl ZkPersonaCredentialEvidenceMode {
    /// Parse the one canonical mode identifier admitted by ZK policy.
    /// Protocol adapters use this registry instead of maintaining their own
    /// spelling table for the same cryptographic statement.
    #[must_use]
    pub fn from_identifier(identifier: &str) -> Option<Self> {
        match identifier {
            "persona_credential_evidence_public_persona_v1" => Some(Self::PublicPersonaV1),
            "persona_credential_evidence_private_persona_one_time_v1" => {
                Some(Self::PrivatePersonaOneTimeV1)
            }
            _ => None,
        }
    }

    /// Stable protocol identifier for policy and artifact manifests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicPersonaV1 => "persona_credential_evidence_public_persona_v1",
            Self::PrivatePersonaOneTimeV1 => {
                "persona_credential_evidence_private_persona_one_time_v1"
            }
        }
    }
}

/// Public, half-open interval during which a prepared proof may be used.
/// This wallet-selected interval is independent of the issuer's signed
/// credential-validity interval. The circuit must prove its containment in
/// the issuer interval; host checks alone cannot establish that fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZkPersonaCredentialEvidenceValidityWindow {
    valid_from_unix: u64,
    valid_until_unix: u64,
}

/// Stable reason for refusing a prepared proof window.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ZkPersonaCredentialEvidenceValidityWindowReason {
    /// The half-open interval is empty or reversed.
    #[error("invalid prepared proof interval")]
    InvalidInterval,
    /// The interval extends beyond issuer-signed credential validity.
    #[error("prepared proof interval outside credential validity")]
    OutsideIssuerValidity,
    /// The verifier's trusted time is outside the prepared interval.
    #[error("prepared proof outside its usable interval")]
    NotCurrent,
}

/// Typed prepared-window error with no credential attributes or timestamps.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("prepared proof window rejected: {reason}")]
pub struct ZkPersonaCredentialEvidenceValidityWindowError {
    reason: ZkPersonaCredentialEvidenceValidityWindowReason,
}

impl ZkPersonaCredentialEvidenceValidityWindowError {
    /// Return the stable non-sensitive rejection reason.
    #[must_use]
    pub const fn reason(self) -> ZkPersonaCredentialEvidenceValidityWindowReason {
        self.reason
    }
}

impl ZkPersonaCredentialEvidenceValidityWindow {
    /// Construct a wallet-selected interval with an exclusive upper bound.
    pub fn try_new(
        valid_from_unix: u64,
        valid_until_unix: u64,
    ) -> Result<Self, ZkPersonaCredentialEvidenceValidityWindowError> {
        if valid_from_unix >= valid_until_unix {
            return Err(ZkPersonaCredentialEvidenceValidityWindowError {
                reason: ZkPersonaCredentialEvidenceValidityWindowReason::InvalidInterval,
            });
        }
        Ok(Self {
            valid_from_unix,
            valid_until_unix,
        })
    }

    /// Check the interval against the issuer-signed validity bounds. The same
    /// comparison must also be enforced inside the prepared proof circuit.
    pub fn validate_issuer_bounds(
        self,
        issuer_valid_from_unix: u64,
        issuer_valid_until_unix: u64,
    ) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
        if issuer_valid_from_unix >= issuer_valid_until_unix {
            return Err(ZkPersonaCredentialEvidenceValidityWindowError {
                reason: ZkPersonaCredentialEvidenceValidityWindowReason::InvalidInterval,
            });
        }
        if self.valid_from_unix < issuer_valid_from_unix
            || self.valid_until_unix > issuer_valid_until_unix
        {
            return Err(ZkPersonaCredentialEvidenceValidityWindowError {
                reason: ZkPersonaCredentialEvidenceValidityWindowReason::OutsideIssuerValidity,
            });
        }
        Ok(())
    }

    /// Check the verifier's trusted request time against the public window.
    pub fn validate_at(
        self,
        request_time_unix: u64,
    ) -> Result<(), ZkPersonaCredentialEvidenceValidityWindowError> {
        if request_time_unix < self.valid_from_unix || request_time_unix >= self.valid_until_unix {
            return Err(ZkPersonaCredentialEvidenceValidityWindowError {
                reason: ZkPersonaCredentialEvidenceValidityWindowReason::NotCurrent,
            });
        }
        Ok(())
    }

    /// Inclusive lower bound of the evidence validity interval.
    #[must_use]
    pub const fn valid_from_unix(self) -> u64 {
        self.valid_from_unix
    }

    /// Exclusive upper bound of the evidence validity interval.
    #[must_use]
    pub const fn valid_until_unix(self) -> u64 {
        self.valid_until_unix
    }
}

#[cfg(test)]
#[path = "persona_credential_evidence/tests.rs"]
mod tests;
