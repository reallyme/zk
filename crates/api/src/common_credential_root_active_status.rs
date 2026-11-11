// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native admission of the exact active-attestation path proved by v1 Noir.

use crypto_sha2_256::digest as sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::common_root::ZkVerifiedRootStatusSnapshot;

const LEAF_DOMAIN: &[u8; 6] = b"RMSTL2";
const NODE_DOMAIN: &[u8; 6] = b"RMSTN1";
const HASH_BYTES: usize = 32;
/// Maximum Merkle depth admitted by the common-credential-root v1 status circuit.
pub const COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH: usize = 20;
/// Maximum number of leaves admitted by the common-credential-root v1 status circuit.
pub const COMMON_CREDENTIAL_ROOT_V1_STATUS_LEAVES: u32 = 1_048_576;

/// Stable reason for rejecting a holder-private active-status opening.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootActiveStatusReason {
    /// The index, depth, or attestation identifier cannot enter the v1 circuit.
    #[error("invalid active-status opening")]
    InvalidOpening,
    /// The signed active-root snapshot is no longer current.
    #[error("active-status snapshot stale")]
    StaleSnapshot,
    /// The attestation is absent from the signed active set.
    #[error("attestation absent from active set")]
    RootMismatch,
}

/// Typed, non-sensitive failure while admitting an active-status witness.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("common-credential-root active-status admission failed: {reason}")]
pub struct ZkCommonCredentialRootActiveStatusError {
    reason: ZkCommonCredentialRootActiveStatusReason,
}

impl ZkCommonCredentialRootActiveStatusError {
    /// Return a stable reason without exposing the hidden attestation ID.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootActiveStatusReason {
        self.reason
    }
}

/// Check a holder-private Merkle opening against a signed, authority-verified root.
///
/// This duplicates the root-status circuit's `RMSTL2`/`RMSTN1` transcript so
/// the wallet can reject an invalid witness before expensive proving. It does
/// not replace the in-circuit check or the verifier's signed-snapshot policy.
pub fn verify_common_credential_root_active_status_membership(
    snapshot: ZkVerifiedRootStatusSnapshot,
    now_unix: u64,
    attestation_id: &[u8; HASH_BYTES],
    status_index: u32,
    siblings: &[[u8; HASH_BYTES]],
) -> Result<(), ZkCommonCredentialRootActiveStatusError> {
    snapshot
        .validate_at(now_unix)
        .map_err(|_| error(ZkCommonCredentialRootActiveStatusReason::StaleSnapshot))?;
    let depth = u32::try_from(siblings.len())
        .map_err(|_| error(ZkCommonCredentialRootActiveStatusReason::InvalidOpening))?;
    if attestation_id.iter().all(|byte| *byte == 0)
        || status_index >= COMMON_CREDENTIAL_ROOT_V1_STATUS_LEAVES
        || siblings.len() > COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH
        || (status_index >> depth) != 0
    {
        return Err(error(
            ZkCommonCredentialRootActiveStatusReason::InvalidOpening,
        ));
    }

    let mut leaf = Zeroizing::new([0_u8; LEAF_DOMAIN.len() + HASH_BYTES]);
    leaf[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    leaf[LEAF_DOMAIN.len()..].copy_from_slice(attestation_id);
    let mut current = Zeroizing::new(sha256(leaf.as_slice()).into_bytes());
    let mut node = Zeroizing::new([0_u8; NODE_DOMAIN.len() + 2 * HASH_BYTES]);
    node[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    for (level, sibling) in siblings.iter().enumerate() {
        let shift = u32::try_from(level)
            .map_err(|_| error(ZkCommonCredentialRootActiveStatusReason::InvalidOpening))?;
        let (left, right) = if (status_index >> shift) & 1 == 0 {
            (current.as_slice(), sibling.as_slice())
        } else {
            (sibling.as_slice(), current.as_slice())
        };
        node[NODE_DOMAIN.len()..NODE_DOMAIN.len() + HASH_BYTES].copy_from_slice(left);
        node[NODE_DOMAIN.len() + HASH_BYTES..].copy_from_slice(right);
        *current = sha256(node.as_slice()).into_bytes();
    }
    if !bool::from(current.as_slice().ct_eq(&snapshot.root())) {
        return Err(error(
            ZkCommonCredentialRootActiveStatusReason::RootMismatch,
        ));
    }
    Ok(())
}

const fn error(
    reason: ZkCommonCredentialRootActiveStatusReason,
) -> ZkCommonCredentialRootActiveStatusError {
    ZkCommonCredentialRootActiveStatusError { reason }
}

#[cfg(test)]
#[path = "common_credential_root_active_status/tests.rs"]
mod tests;
