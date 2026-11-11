// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical active-attestation tree shared by the authority and wallet.
//!
//! Publishing the whole ordered set lets a holder compute a current path
//! without querying the authority for its private attestation identifier.

use crypto_sha2_256::digest as sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::common_root::{
    verify_common_credential_root_active_status_membership, ZkVerifiedRootStatusSnapshot,
    COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH,
};

const HASH_BYTES: usize = 32;
const LEAF_DOMAIN: &[u8; 6] = b"RMSTL2";
const NODE_DOMAIN: &[u8; 6] = b"RMSTN1";
const MAX_LEAVES: usize = 1_usize << COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH;
type ActiveSetPath = Zeroizing<Vec<[u8; HASH_BYTES]>>;

/// Stable reason for rejecting a published active set or requested opening.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootActiveSetReason {
    /// The set is unordered, duplicated, or contains a reserved ID.
    #[error("invalid active-attestation set")]
    InvalidSet,
    /// The set exceeds the v1 circuit's bounded capacity.
    #[error("active-attestation set too large")]
    Capacity,
    /// The requested attestation is not active in this set.
    #[error("attestation is not active")]
    NotActive,
    /// This set is not the one signed in the current authority snapshot.
    #[error("active-attestation snapshot mismatch")]
    SnapshotMismatch,
}

/// Typed active-set failure without identifiers or Merkle nodes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("active-attestation set rejected: {reason}")]
pub struct ZkCommonCredentialRootActiveSetError {
    reason: ZkCommonCredentialRootActiveSetReason,
}

impl ZkCommonCredentialRootActiveSetError {
    /// Return a stable reason for wallet and status-authority adapters.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootActiveSetReason {
        self.reason
    }
}

/// Canonically ordered attestation IDs from one published active-set version.
///
/// This type authenticates no publication by itself. The wallet must compare
/// its derived root to a separately signature-verified authority snapshot.
pub struct ZkCommonCredentialRootActiveSet {
    ids: Zeroizing<Vec<[u8; HASH_BYTES]>>,
    root: [u8; HASH_BYTES],
}

impl ZeroizeOnDrop for ZkCommonCredentialRootActiveSet {}

/// Private membership witness derived from the whole published set.
pub struct ZkCommonCredentialRootActiveSetOpening {
    index: u32,
    siblings: ActiveSetPath,
}

impl ZeroizeOnDrop for ZkCommonCredentialRootActiveSetOpening {}

impl ZkCommonCredentialRootActiveSetOpening {
    /// Private leaf position consumed by the v1 status circuit.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Private sibling path consumed by the v1 status circuit.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; HASH_BYTES]] {
        self.siblings.as_slice()
    }
}

impl ZkCommonCredentialRootActiveSet {
    /// Admit a strictly ascending, unique list of active IDs.
    ///
    /// Missing leaves are padded to the next power of two with the leaf hash
    /// of the reserved zero identifier. This makes odd-size and empty trees
    /// canonical. An empty tree cannot produce a valid membership opening.
    pub fn try_from_sorted_ids(
        ids: &[[u8; HASH_BYTES]],
    ) -> Result<Self, ZkCommonCredentialRootActiveSetError> {
        if ids.len() > MAX_LEAVES {
            return Err(error(ZkCommonCredentialRootActiveSetReason::Capacity));
        }
        if ids.iter().any(|id| id.iter().all(|byte| *byte == 0))
            || ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(error(ZkCommonCredentialRootActiveSetReason::InvalidSet));
        }
        let mut owned = Zeroizing::new(Vec::new());
        owned
            .try_reserve_exact(ids.len())
            .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::Capacity))?;
        owned.extend_from_slice(ids);
        let root = build_tree(ids, None)?.0;
        Ok(Self { ids: owned, root })
    }

    /// Root for publication in a signed ReallyMe status snapshot.
    #[must_use]
    pub const fn root(&self) -> [u8; HASH_BYTES] {
        self.root
    }

    /// Number of active IDs encoded by this tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether the signed active set contains no attestations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Ordered identifiers committed by the signed publication root.
    ///
    /// These bytes are for bulk publication, never a per-holder lookup API.
    #[must_use]
    pub fn sorted_ids(&self) -> &[[u8; HASH_BYTES]] {
        self.ids.as_slice()
    }

    /// Derive one private path only after matching a trusted current snapshot.
    pub fn open_against(
        &self,
        snapshot: ZkVerifiedRootStatusSnapshot,
        now_unix: u64,
        attestation_id: &[u8; HASH_BYTES],
    ) -> Result<ZkCommonCredentialRootActiveSetOpening, ZkCommonCredentialRootActiveSetError> {
        if snapshot.validate_at(now_unix).is_err() || !bool::from(self.root.ct_eq(&snapshot.root()))
        {
            return Err(error(
                ZkCommonCredentialRootActiveSetReason::SnapshotMismatch,
            ));
        }
        let index = self
            .ids
            .binary_search(attestation_id)
            .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::NotActive))?;
        let (derived, siblings) = build_tree(self.ids.as_slice(), Some(index))?;
        if !bool::from(derived.ct_eq(&self.root)) {
            return Err(error(
                ZkCommonCredentialRootActiveSetReason::SnapshotMismatch,
            ));
        }
        let index = u32::try_from(index)
            .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::Capacity))?;
        let opening = ZkCommonCredentialRootActiveSetOpening { index, siblings };
        verify_common_credential_root_active_status_membership(
            snapshot,
            now_unix,
            attestation_id,
            opening.index,
            opening.siblings(),
        )
        .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::SnapshotMismatch))?;
        Ok(opening)
    }
}

fn build_tree(
    ids: &[[u8; HASH_BYTES]],
    selected: Option<usize>,
) -> Result<([u8; HASH_BYTES], ActiveSetPath), ZkCommonCredentialRootActiveSetError> {
    let width = ids
        .len()
        .max(1)
        .checked_next_power_of_two()
        .ok_or_else(|| error(ZkCommonCredentialRootActiveSetReason::Capacity))?;
    let empty = leaf(&[0_u8; HASH_BYTES]);
    let mut level = Zeroizing::new(Vec::new());
    level
        .try_reserve_exact(width)
        .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::Capacity))?;
    for id in ids {
        level.push(leaf(id));
    }
    level.resize(width, empty);
    let mut position = selected;
    let mut siblings = Zeroizing::new(Vec::new());
    siblings
        .try_reserve_exact(COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH)
        .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::Capacity))?;
    while level.len() > 1 {
        if let Some(index) = position.as_mut() {
            siblings.push(
                *level
                    .get(*index ^ 1)
                    .ok_or_else(|| error(ZkCommonCredentialRootActiveSetReason::Capacity))?,
            );
            *index >>= 1;
        }
        let mut next = Zeroizing::new(Vec::new());
        next.try_reserve_exact(level.len() / 2)
            .map_err(|_| error(ZkCommonCredentialRootActiveSetReason::Capacity))?;
        for pair in level.as_chunks::<2>().0 {
            next.push(node(&pair[0], &pair[1]));
        }
        level = next;
    }
    let root = *level
        .first()
        .ok_or_else(|| error(ZkCommonCredentialRootActiveSetReason::InvalidSet))?;
    Ok((root, siblings))
}

fn leaf(id: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = Zeroizing::new([0_u8; LEAF_DOMAIN.len() + HASH_BYTES]);
    preimage[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    preimage[LEAF_DOMAIN.len()..].copy_from_slice(id);
    sha256(preimage.as_slice()).into_bytes()
}

fn node(left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = Zeroizing::new([0_u8; NODE_DOMAIN.len() + 2 * HASH_BYTES]);
    preimage[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    preimage[NODE_DOMAIN.len()..NODE_DOMAIN.len() + HASH_BYTES].copy_from_slice(left);
    preimage[NODE_DOMAIN.len() + HASH_BYTES..].copy_from_slice(right);
    sha256(preimage.as_slice()).into_bytes()
}

const fn error(
    reason: ZkCommonCredentialRootActiveSetReason,
) -> ZkCommonCredentialRootActiveSetError {
    ZkCommonCredentialRootActiveSetError { reason }
}

#[cfg(test)]
#[path = "common_credential_root_active_set/tests.rs"]
mod tests;
