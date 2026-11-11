// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed transcript for ReallyMe's global active-root status snapshots.

use crypto_sha2_256::digest as sha256;
use thiserror::Error;

use crate::{
    common_credential_root_joins::normalize_common_credential_root_p256_signature_low_s,
    keys::ZkStatusAuthorityPublicKey,
};

mod verification;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use verification::verify_root_status_snapshot;
pub use verification::{
    ZkRootStatusTrustPolicy, ZkRootStatusVerificationError, ZkRootStatusVerificationReason,
    ZkVerifiedRootStatusSnapshot,
};

const STATUS_SNAPSHOT_DOMAIN: &[u8; 8] = b"RMRSTAT1";
const FIELD_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const TRANSCRIPT_BYTES: usize = STATUS_SNAPSHOT_DOMAIN.len() + FIELD_BYTES + 8 + 8 + 8;
const ROOT_START: usize = STATUS_SNAPSHOT_DOMAIN.len();
const ISSUED_START: usize = ROOT_START + FIELD_BYTES;
const EXPIRES_START: usize = ISSUED_START + 8;
const SEQUENCE_START: usize = EXPIRES_START + 8;

/// Stable reason for rejecting an active-root snapshot before signature verification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkRootStatusSnapshotReason {
    /// A required field is absent or uses a reserved value.
    #[error("invalid root status snapshot field")]
    InvalidField,
    /// The signed validity interval is empty or inverted.
    #[error("invalid root status snapshot interval")]
    InvalidInterval,
}

/// Typed root status snapshot validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("root status snapshot rejected: {reason}")]
pub struct ZkRootStatusSnapshotError {
    reason: ZkRootStatusSnapshotReason,
}

impl ZkRootStatusSnapshotError {
    /// Return a stable, non-sensitive failure reason.
    #[must_use]
    pub const fn reason(self) -> ZkRootStatusSnapshotReason {
        self.reason
    }
}

/// Signed, public ReallyMe active-attestation Merkle root.
///
/// Construction checks shape only. The verifier must check the signature
/// against its pinned status-authority key, freshness, and sequence before
/// admitting this root as a common-credential-root proof policy input.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkRootStatusSnapshot {
    status_root: [u8; FIELD_BYTES],
    issued_unix: u64,
    expires_unix: u64,
    sequence: u64,
    signer: ZkStatusAuthorityPublicKey,
    signature: [u8; SIGNATURE_BYTES],
}

impl ZkRootStatusSnapshot {
    /// Admit the exact v1 fields of a signed active-root snapshot.
    pub fn try_from_parts(
        status_root: [u8; FIELD_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        sequence: u64,
        signer: ZkStatusAuthorityPublicKey,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ZkRootStatusSnapshotError> {
        let normalized =
            normalize_common_credential_root_p256_signature_low_s(signature).map_err(|_| {
                ZkRootStatusSnapshotError {
                    reason: ZkRootStatusSnapshotReason::InvalidField,
                }
            })?;
        if normalized != signature {
            return Err(ZkRootStatusSnapshotError {
                reason: ZkRootStatusSnapshotReason::InvalidField,
            });
        }
        Self::try_from_canonical_parts(
            status_root,
            issued_unix,
            expires_unix,
            sequence,
            signer,
            signature,
        )
    }

    /// Admit status-authority signer output by canonicalizing P-256 low-S.
    ///
    /// Use this only at the authority boundary before publishing. Decoded
    /// protocol artifacts must use `try_from_parts`, which rejects high-S
    /// signatures instead of rewriting them after the fact.
    pub fn try_from_authority_signed_parts(
        status_root: [u8; FIELD_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        sequence: u64,
        signer: ZkStatusAuthorityPublicKey,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ZkRootStatusSnapshotError> {
        let signature =
            normalize_common_credential_root_p256_signature_low_s(signature).map_err(|_| {
                ZkRootStatusSnapshotError {
                    reason: ZkRootStatusSnapshotReason::InvalidField,
                }
            })?;
        Self::try_from_canonical_parts(
            status_root,
            issued_unix,
            expires_unix,
            sequence,
            signer,
            signature,
        )
    }

    fn try_from_canonical_parts(
        status_root: [u8; FIELD_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        sequence: u64,
        signer: ZkStatusAuthorityPublicKey,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ZkRootStatusSnapshotError> {
        if status_root.iter().all(|byte| *byte == 0)
            || (signer.x.iter().all(|byte| *byte == 0) && signer.y.iter().all(|byte| *byte == 0))
            || signature.iter().all(|byte| *byte == 0)
            || sequence == 0
        {
            return Err(ZkRootStatusSnapshotError {
                reason: ZkRootStatusSnapshotReason::InvalidField,
            });
        }
        if issued_unix == 0 || expires_unix <= issued_unix {
            return Err(ZkRootStatusSnapshotError {
                reason: ZkRootStatusSnapshotReason::InvalidInterval,
            });
        }
        Ok(Self {
            status_root,
            issued_unix,
            expires_unix,
            sequence,
            signer,
            signature,
        })
    }

    /// Hash the fixed-width transcript signed as P-256 ECDSA over SHA-256.
    ///
    /// This is a prehash: signing and verification must use digest APIs,
    /// without hashing the returned bytes a second time.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; FIELD_BYTES] {
        Self::signing_digest_for_fields(
            self.status_root,
            self.issued_unix,
            self.expires_unix,
            self.sequence,
        )
    }

    /// Hash authority-owned fields before the snapshot has been signed.
    ///
    /// Issuers use this transcript to sign; verifiers recompute the same digest
    /// from the decoded snapshot. Signature bytes are deliberately excluded.
    #[must_use]
    pub fn signing_digest_for_fields(
        status_root: [u8; FIELD_BYTES],
        issued_unix: u64,
        expires_unix: u64,
        sequence: u64,
    ) -> [u8; FIELD_BYTES] {
        let mut transcript = [0_u8; TRANSCRIPT_BYTES];
        transcript[..ROOT_START].copy_from_slice(STATUS_SNAPSHOT_DOMAIN);
        transcript[ROOT_START..ISSUED_START].copy_from_slice(&status_root);
        transcript[ISSUED_START..EXPIRES_START].copy_from_slice(&issued_unix.to_be_bytes());
        transcript[EXPIRES_START..SEQUENCE_START].copy_from_slice(&expires_unix.to_be_bytes());
        transcript[SEQUENCE_START..].copy_from_slice(&sequence.to_be_bytes());
        sha256(&transcript).into_bytes()
    }

    /// The active-set root committed by the authority signature.
    #[must_use]
    pub const fn status_root(&self) -> [u8; FIELD_BYTES] {
        self.status_root
    }

    /// Snapshot publication time.
    #[must_use]
    pub const fn issued_unix(&self) -> u64 {
        self.issued_unix
    }

    /// Exclusive snapshot expiry time.
    #[must_use]
    pub const fn expires_unix(&self) -> u64 {
        self.expires_unix
    }

    /// Monotonic authority sequence for rollback detection.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Claimed signer; deployments must compare it to a pinned authority key.
    #[must_use]
    pub const fn signer(&self) -> ZkStatusAuthorityPublicKey {
        self.signer
    }

    /// Fixed-width P-256 ECDSA signature in `r || s` format.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
}

#[cfg(test)]
#[path = "common_credential_root_status_snapshot/tests.rs"]
mod tests;
