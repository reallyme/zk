// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public-input joins for the persona-credential-evidence credential and status stages.
//!
//! This is a transcript precheck, not proof or issuer-status verification.
//! A verifier must authenticate every proof, its trusted status snapshot, and
//! the holder's live request signature before accepting a presentation.

use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    circuits::ZkCredentialHashAlgorithm,
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceValidityWindow,
    },
    proofs::ZkProofSuite,
};

const FIELD_BYTES: usize = 32;

/// Public values independently authenticated by every prepared proof stage.
///
/// Although public to the verifier, the token key, nonce, and join can be
/// sensitive in the wallet's memory before disclosure, so they are wiped.
pub struct ZkPersonaCredentialEvidenceStageJoin {
    /// Commitment hash lane selected by the verified source proof.
    pub credential_hash_algorithm: ZkCredentialHashAlgorithm,
    /// Exact proof suite selected by the verified source proof.
    pub proof_suite: ZkProofSuite,
    /// Issuer key authenticated by every prepared source circuit.
    pub issuer_key: ZkIssuerPublicKey,
    /// Public holder key joined across every prepared source circuit.
    pub holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
    /// Independent token nonce authenticated by every prepared source circuit.
    pub token_nonce: [u8; FIELD_BYTES],
    /// Wallet-selected half-open proof interval.
    pub proof_window: ZkPersonaCredentialEvidenceValidityWindow,
    /// Token-specific commitment to the same hidden issuer credential.
    pub credential_binding: [u8; FIELD_BYTES],
}

impl Zeroize for ZkPersonaCredentialEvidenceStageJoin {
    fn zeroize(&mut self) {
        self.issuer_key.x.zeroize();
        self.issuer_key.y.zeroize();
        self.holder_key.x.zeroize();
        self.holder_key.y.zeroize();
        self.token_nonce.zeroize();
        self.credential_binding.zeroize();
    }
}

impl Drop for ZkPersonaCredentialEvidenceStageJoin {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceStageJoin {}

/// Stable failure reason for a prepared proof-stage join.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ZkPersonaCredentialEvidenceJoinReason {
    /// At least one public input is empty or reserved.
    #[error("invalid prepared proof public input")]
    InvalidInput,
    /// A witness-revealing compatibility suite cannot serve this mode.
    #[error("prepared proof requires a zero-knowledge suite")]
    UnsupportedSuite,
    /// The authenticated proof stages describe different token contexts.
    #[error("prepared proof stages do not join")]
    Mismatch,
    /// The verifier's trusted time is outside the common proof window.
    #[error("prepared proof window is not current")]
    NotCurrent,
}

/// Typed prepared-join failure with no public inputs in its display text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("prepared proof join rejected: {reason}")]
pub struct ZkPersonaCredentialEvidenceJoinError {
    reason: ZkPersonaCredentialEvidenceJoinReason,
}

impl ZkPersonaCredentialEvidenceJoinError {
    /// Return a stable, non-sensitive reason.
    #[must_use]
    pub const fn reason(self) -> ZkPersonaCredentialEvidenceJoinReason {
        self.reason
    }
}

/// Require any pair of prepared stages to refer to one token.
///
/// The caller must obtain each value from a successfully verified source proof.
/// Matching unchecked, caller-supplied values confers no credential authority.
pub fn check_persona_credential_evidence_v1_joins(
    claim: &ZkPersonaCredentialEvidenceStageJoin,
    current_state: &ZkPersonaCredentialEvidenceStageJoin,
    request_time_unix: u64,
) -> Result<(), ZkPersonaCredentialEvidenceJoinError> {
    for stage in [claim, current_state] {
        stage.proof_suite.require_zero_knowledge().map_err(|_| {
            ZkPersonaCredentialEvidenceJoinError {
                reason: ZkPersonaCredentialEvidenceJoinReason::UnsupportedSuite,
            }
        })?;
        if stage.token_nonce.iter().all(|byte| *byte == 0)
            || stage.credential_binding.iter().all(|byte| *byte == 0)
            || (stage.holder_key.x.iter().all(|byte| *byte == 0)
                && stage.holder_key.y.iter().all(|byte| *byte == 0))
        {
            return Err(ZkPersonaCredentialEvidenceJoinError {
                reason: ZkPersonaCredentialEvidenceJoinReason::InvalidInput,
            });
        }
    }
    let equal = claim.credential_hash_algorithm == current_state.credential_hash_algorithm
        && claim.proof_suite == current_state.proof_suite
        && bool::from(claim.issuer_key.x.ct_eq(&current_state.issuer_key.x))
        && bool::from(claim.issuer_key.y.ct_eq(&current_state.issuer_key.y))
        && bool::from(claim.holder_key.x.ct_eq(&current_state.holder_key.x))
        && bool::from(claim.holder_key.y.ct_eq(&current_state.holder_key.y))
        && bool::from(claim.token_nonce.ct_eq(&current_state.token_nonce))
        && bool::from(
            claim
                .credential_binding
                .ct_eq(&current_state.credential_binding),
        )
        && claim.proof_window == current_state.proof_window;
    if !equal {
        return Err(ZkPersonaCredentialEvidenceJoinError {
            reason: ZkPersonaCredentialEvidenceJoinReason::Mismatch,
        });
    }
    claim
        .proof_window
        .validate_at(request_time_unix)
        .map_err(|_| ZkPersonaCredentialEvidenceJoinError {
            reason: ZkPersonaCredentialEvidenceJoinReason::NotCurrent,
        })
}

#[cfg(test)]
#[path = "persona_credential_evidence_joins/tests.rs"]
mod tests;
