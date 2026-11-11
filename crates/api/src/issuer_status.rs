// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared issuer status contracts; signature and freshness policy are adapter responsibilities.

use crate::{
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const FIELD_BYTES: usize = 32;

/// Issuer status purpose authenticated in both credential and status list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkIssuerStatusPurpose {
    /// A set bit means irrevocable credential revocation.
    Revocation,
    /// A set bit means temporary credential suspension.
    Suspension,
}

impl ZkIssuerStatusPurpose {
    /// Reject unspecified and unknown circuit-purpose values at the boundary.
    pub fn try_from_wire_value(value: u8) -> Result<Self, ZkError> {
        match value {
            1 => Ok(Self::Revocation),
            2 => Ok(Self::Suspension),
            _ => Err(ZkError::new(ZkErrorReason::InvalidProofEncoding)),
        }
    }

    /// Canonical issuer-signed purpose code used in the status circuit.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Revocation => 1,
            Self::Suspension => 2,
        }
    }
}

/// Public issuer-status feed fields that the verifier must match to an
/// independently authenticated current snapshot.
#[derive(PartialEq, Eq)]
pub struct ZkIssuerStatusFeed {
    /// Public issuer status Merkle root.
    pub root: [u8; FIELD_BYTES],
    /// Number of entries in the signed list.
    pub length: u64,
    /// Signed issuer list identifier.
    pub list_id: [u8; FIELD_BYTES],
    /// Signed digest of the list location.
    pub url_hash: [u8; FIELD_BYTES],
    /// Circuit status-purpose code, one or two.
    pub purpose: ZkIssuerStatusPurpose,
}

/// Issuer-signed list locator extracted from a verified current-state proof.
/// The current root and length must be fetched from the status authority.
#[derive(PartialEq, Eq)]
pub struct ZkIssuerStatusListPointer {
    /// Signed list identifier.
    pub list_id: [u8; FIELD_BYTES],
    /// Signed digest of the list location.
    pub url_hash: [u8; FIELD_BYTES],
    /// Signed status-purpose code.
    pub purpose: ZkIssuerStatusPurpose,
}

impl Zeroize for ZkIssuerStatusListPointer {
    fn zeroize(&mut self) {
        self.list_id.zeroize();
        self.url_hash.zeroize();
    }
}

impl Drop for ZkIssuerStatusListPointer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkIssuerStatusListPointer {}

impl Zeroize for ZkIssuerStatusFeed {
    fn zeroize(&mut self) {
        self.root.zeroize();
        self.length.zeroize();
        self.list_id.zeroize();
        self.url_hash.zeroize();
    }
}

impl Drop for ZkIssuerStatusFeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkIssuerStatusFeed {}

/// Independently authenticate the issuer's current shared status feed.
///
/// Implementations check the list signature and issuer identity, signed
/// freshness, and a durable monotonic rollback floor. The verified proof's
/// list pointer selects the expected feed; it is never an authority for a
/// network destination or a status root by itself.
pub trait ZkIssuerStatusAuthority: Send + Sync {
    /// Return the current authenticated feed for the credential issuer.
    fn current_feed_for_issuer(
        &self,
        issuer_key: &ZkIssuerPublicKey,
        status_pointer: &ZkIssuerStatusListPointer,
        verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError>;
}

/// Issuer credential-status proof and backend injection contracts.
pub use crate::credential_status_verification::{
    ZkIssuerCredentialStatusProof, ZkIssuerCredentialStatusProver,
    ZkIssuerCredentialStatusStatement, ZkIssuerCredentialStatusVerifier,
};

#[cfg(test)]
mod tests;
