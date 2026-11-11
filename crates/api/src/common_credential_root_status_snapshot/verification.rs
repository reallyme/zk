// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authority and freshness checks shared by OpenID4VP and direct Identity use.

use thiserror::Error;

use super::ZkRootStatusSnapshot;
#[cfg(any(feature = "native", feature = "wasm"))]
use crate::common_credential_root_joins::normalize_common_credential_root_p256_signature_low_s;
use crate::keys::ZkStatusAuthorityPublicKey;

#[cfg(any(feature = "native", feature = "wasm"))]
const P256_SEC1_UNCOMPRESSED_BYTES: usize = 65;
#[cfg(any(feature = "native", feature = "wasm"))]
const P256_SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;
const P256_COORDINATE_BYTES: usize = 32;
#[cfg(any(feature = "native", feature = "wasm"))]
const P256_X_END: usize = 1 + P256_COORDINATE_BYTES;
#[cfg(any(feature = "native", feature = "wasm"))]
const P256_Y_END: usize = P256_X_END + P256_COORDINATE_BYTES;

/// Deployment-owned trust and rollback policy for ReallyMe active-root status.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkRootStatusTrustPolicy {
    /// Pinned status-authority key, independent of the attestation signer.
    pub authority: ZkStatusAuthorityPublicKey,
    /// Durable monotonic sequence floor maintained by the verifier deployment.
    pub minimum_sequence: u64,
    /// Maximum accepted age at both policy creation and proof verification.
    pub maximum_age_seconds: u64,
}

/// Stable reason for rejecting a signed active-root snapshot.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkRootStatusVerificationReason {
    /// The snapshot claims a different authority or the policy has no age bound.
    #[error("root status authority policy mismatch")]
    AuthorityPolicy,
    /// The snapshot sequence is below the deployment's durable rollback floor.
    #[error("root status sequence rollback")]
    SequenceRollback,
    /// The signature is malformed, noncanonical, or invalid for the pinned key.
    #[error("root status signature invalid")]
    SignatureInvalid,
    /// The snapshot is future-dated, expired, or older than permitted.
    #[error("root status snapshot stale")]
    Stale,
}

/// Typed, non-sensitive active-root verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("root status verification failed: {reason}")]
pub struct ZkRootStatusVerificationError {
    reason: ZkRootStatusVerificationReason,
}

impl ZkRootStatusVerificationError {
    /// Return a stable error reason for FFI and protocol mapping.
    #[must_use]
    pub const fn reason(self) -> ZkRootStatusVerificationReason {
        self.reason
    }
}

/// Snapshot whose signature was checked against a pinned status authority.
///
/// The signed root is public. This type has no public constructor so a holder
/// cannot turn an arbitrary Merkle root into trusted verifier policy material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkVerifiedRootStatusSnapshot {
    root: [u8; P256_COORDINATE_BYTES],
    issued_unix: u64,
    expires_unix: u64,
    sequence: u64,
    maximum_age_seconds: u64,
}

impl ZkVerifiedRootStatusSnapshot {
    /// Root bound by the verified authority signature.
    #[must_use]
    pub const fn root(self) -> [u8; P256_COORDINATE_BYTES] {
        self.root
    }

    /// Issuance time authenticated by the status authority signature.
    #[must_use]
    pub const fn issued_unix(self) -> u64 {
        self.issued_unix
    }

    /// Exclusive expiry authenticated by the status authority signature.
    #[must_use]
    pub const fn expires_unix(self) -> u64 {
        self.expires_unix
    }

    /// Signed authority sequence, for advancing the verifier's rollback floor.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Digest of the exact authority-signed root, interval, and sequence.
    /// Persist this with the sequence so two different signed snapshots at the
    /// same sequence cannot both be admitted after a restart or race.
    #[must_use]
    pub fn signing_digest(self) -> [u8; P256_COORDINATE_BYTES] {
        ZkRootStatusSnapshot::signing_digest_for_fields(
            self.root,
            self.issued_unix,
            self.expires_unix,
            self.sequence,
        )
    }

    /// Recheck the signed validity interval and deployment age bound at use.
    pub fn validate_at(self, now_unix: u64) -> Result<(), ZkRootStatusVerificationError> {
        let age = now_unix
            .checked_sub(self.issued_unix)
            .ok_or_else(|| error(ZkRootStatusVerificationReason::Stale))?;
        if now_unix >= self.expires_unix || age > self.maximum_age_seconds {
            return Err(error(ZkRootStatusVerificationReason::Stale));
        }
        Ok(())
    }
}

/// Verify the signed snapshot before admitting its root to proof policy.
///
/// A deployment must persist and advance `minimum_sequence` independently of
/// the holder. Signature verification alone cannot detect an older valid root.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn verify_root_status_snapshot(
    snapshot: ZkRootStatusSnapshot,
    trust: ZkRootStatusTrustPolicy,
    now_unix: u64,
) -> Result<ZkVerifiedRootStatusSnapshot, ZkRootStatusVerificationError> {
    if snapshot.signer() != trust.authority || trust.maximum_age_seconds == 0 {
        return Err(error(ZkRootStatusVerificationReason::AuthorityPolicy));
    }
    if snapshot.sequence() < trust.minimum_sequence {
        return Err(error(ZkRootStatusVerificationReason::SequenceRollback));
    }
    let normalized_signature =
        normalize_common_credential_root_p256_signature_low_s(*snapshot.signature())
            .map_err(|_| error(ZkRootStatusVerificationReason::SignatureInvalid))?;
    if normalized_signature != *snapshot.signature() {
        return Err(error(ZkRootStatusVerificationReason::SignatureInvalid));
    }

    let mut public_key = [0_u8; P256_SEC1_UNCOMPRESSED_BYTES];
    public_key[0] = P256_SEC1_UNCOMPRESSED_PREFIX;
    public_key[1..P256_X_END].copy_from_slice(&trust.authority.x);
    public_key[P256_X_END..P256_Y_END].copy_from_slice(&trust.authority.y);
    let signature_der = crypto_p256::p256_ecdsa_jose_signature_to_der(snapshot.signature())
        .map_err(|_| error(ZkRootStatusVerificationReason::SignatureInvalid))?;
    // The typed owner makes the prehashed verification contract explicit and
    // zeroizes the status digest when verification leaves this scope.
    let digest = crypto_p256::P256Sha256Digest::new(snapshot.signing_digest());
    crypto_p256::verify_p256_sha256_digest_low_s_der(&signature_der, &digest, &public_key)
        .map_err(|_| error(ZkRootStatusVerificationReason::SignatureInvalid))?;

    let verified = ZkVerifiedRootStatusSnapshot {
        root: snapshot.status_root(),
        issued_unix: snapshot.issued_unix(),
        expires_unix: snapshot.expires_unix(),
        sequence: snapshot.sequence(),
        maximum_age_seconds: trust.maximum_age_seconds,
    };
    verified.validate_at(now_unix)?;
    Ok(verified)
}

const fn error(reason: ZkRootStatusVerificationReason) -> ZkRootStatusVerificationError {
    ZkRootStatusVerificationError { reason }
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
