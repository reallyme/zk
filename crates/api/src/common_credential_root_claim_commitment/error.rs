// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Fixed, non-sensitive reason for a rejected issuance commitment.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootClaimCommitmentReason {
    /// The ordered claim set is outside the circuit's admitted tree size.
    #[error("invalid claim count")]
    InvalidClaimCount,
    /// A claim name is empty, reserved, or appears more than once.
    #[error("invalid claim name")]
    InvalidClaimName,
    /// A claim value cannot fit the circuit's bounded raw-byte input.
    #[error("invalid claim value length")]
    InvalidValueLength,
    /// A claim salt is the reserved all-zero value.
    #[error("invalid claim salt")]
    InvalidSalt,
    /// The issuer signed a different tree than the holder prepared.
    #[error("issuer claim root mismatch")]
    IssuerRootMismatch,
    /// The wallet did not supply a usable opaque reserved-lineage leaf.
    #[error("invalid lineage leaf")]
    InvalidLineageLeaf,
    /// A decrypted wallet opening is malformed or belongs to another tree.
    #[error("invalid private claim opening")]
    InvalidOpening,
    /// A checked size or index conversion failed.
    #[error("claim tree size exceeded")]
    SizeExceeded,
    /// The selected cryptographic hash rejected a bounded transcript.
    #[error("claim transcript hash failed")]
    HashFailed,
}

/// Typed failure from common-credential-root claim commitment construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("common-credential-root claim commitment failed: {reason}")]
pub struct ZkCommonCredentialRootClaimCommitmentError {
    pub(super) reason: ZkCommonCredentialRootClaimCommitmentReason,
}

impl ZkCommonCredentialRootClaimCommitmentError {
    /// Stable reason without claim contents or private material.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootClaimCommitmentReason {
        self.reason
    }
}
