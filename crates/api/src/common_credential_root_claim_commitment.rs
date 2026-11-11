// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact lane-specific claim transcripts consumed by common-credential-root v1 circuits.
//!
//! SSI's general claim tree uses a different canonical value encoding. This
//! builder owns the circuit transcript so an issuer can commit to the same
//! ordered leaves for which the wallet later constructs private witnesses.

use crypto_sha2_256::digest as sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    circuits::ZkCredentialHashAlgorithm, common_root::ZkCommonCredentialRootDerivedLineage,
};

mod error;
mod issuer;
mod transcript;

pub use error::{
    ZkCommonCredentialRootClaimCommitmentError, ZkCommonCredentialRootClaimCommitmentReason,
};

pub use issuer::{
    verify_common_credential_root_poseidon2_issuer_claims_root,
    verify_common_credential_root_sha256_issuer_claims_root,
    ZkCommonCredentialRootApprovedIssuerRoot,
};

use transcript::{
    append_claim, empty_subtree_digests, opening_claim_digest, opening_leaf_digest, parent_digest,
};

const LINEAGE_NAME: &str = "reallyme.lineage.v1";
const CLAIM_DOMAIN: &[u8; 4] = b"CLM1";
const LEAF_DOMAIN: &[u8; 5] = b"LEAF1";
const NODE_DOMAIN: &[u8; 5] = b"NODE1";
const HASH_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const LINEAGE_VALUE_BYTES: usize = 64;
const MAX_CLAIM_VALUE_BYTES: usize = 64;
// Claim names are hashed outside the circuit. Bound untrusted path work.
const MAX_CLAIM_NAME_BYTES: usize = 256;
const MIN_LEAVES: usize = 2;
/// Fixed height of every claim tree. The circuits accept only paths of
/// exactly this length, so a digest in a leaf position can never stand for a
/// subtree of additional claims.
const CLAIM_TREE_DEPTH: usize = 6;
const MAX_LEAVES: usize = 1 << CLAIM_TREE_DEPTH;
const MAX_INNER_PREIMAGE_BYTES: usize = 4 + 4 + MAX_CLAIM_VALUE_BYTES + SALT_BYTES;

/// A claim supplied to the issuer in explicit leaf order. The lineage leaf is
/// inserted at index zero by the builder and must not appear in this slice.
pub struct ZkCommonCredentialRootClaim<'a> {
    /// Canonical UTF-8 claim name used by the credential persona_mode.
    pub name: &'a str,
    /// Raw, already canonicalized claim bytes disclosed by the selected proof.
    pub value: &'a [u8],
    /// Fresh nonzero claim salt, kept private by the wallet.
    pub salt: &'a [u8; SALT_BYTES],
}

pub(super) fn invalid(
    reason: ZkCommonCredentialRootClaimCommitmentReason,
) -> ZkCommonCredentialRootClaimCommitmentError {
    ZkCommonCredentialRootClaimCommitmentError { reason }
}

/// Holder-private opening for exactly one issuer-committed leaf.
pub struct ZkCommonCredentialRootClaimOpening {
    name_hash: [u8; HASH_BYTES],
    value: Vec<u8>,
    salt: [u8; SALT_BYTES],
    leaf_index: u32,
    siblings: Vec<[u8; HASH_BYTES]>,
}

impl ZkCommonCredentialRootClaimOpening {
    /// Restore one opening from an encrypted wallet record. The complete tree
    /// and issuer-root checks run in `restore_verified` before use.
    pub fn restore(
        name_hash: [u8; HASH_BYTES],
        value: Vec<u8>,
        salt: [u8; SALT_BYTES],
        leaf_index: u32,
        siblings: Vec<[u8; HASH_BYTES]>,
    ) -> Self {
        Self {
            name_hash,
            value,
            salt,
            leaf_index,
            siblings,
        }
    }

    /// SHA-256 of the canonical UTF-8 claim name.
    #[must_use]
    pub const fn name_hash(&self) -> [u8; HASH_BYTES] {
        self.name_hash
    }

    /// Raw committed value bytes; keep the owner private until witness use.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Private 16-byte claim salt.
    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_BYTES] {
        &self.salt
    }

    /// Original leaf index before odd-leaf duplication.
    #[must_use]
    pub const fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    /// Sibling digests from leaf to root. These are private witness material.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; HASH_BYTES]] {
        &self.siblings
    }
}

impl Zeroize for ZkCommonCredentialRootClaimOpening {
    fn zeroize(&mut self) {
        self.name_hash.zeroize();
        self.value.zeroize();
        self.salt.zeroize();
        self.leaf_index.zeroize();
        self.siblings.zeroize();
    }
}

impl Drop for ZkCommonCredentialRootClaimOpening {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootClaimOpening {}

/// Public root and corresponding private openings. The first opening is the
/// reserved lineage leaf, followed by caller claims in their supplied order.
pub struct ZkCommonCredentialRootClaimsCommitment {
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    root: [u8; HASH_BYTES],
    openings: Vec<ZkCommonCredentialRootClaimOpening>,
}

impl Zeroize for ZkCommonCredentialRootClaimsCommitment {
    fn zeroize(&mut self) {
        self.root.zeroize();
        self.openings.zeroize();
    }
}

impl Drop for ZkCommonCredentialRootClaimsCommitment {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootClaimsCommitment {}

impl ZkCommonCredentialRootClaimsCommitment {
    /// Reconstitute private openings only after decrypting wallet-owned
    /// storage. Each path is checked against the issuer-authenticated root;
    /// positional and lineage constraints prevent path substitution.
    pub fn restore_verified(
        issuer_root: [u8; HASH_BYTES],
        openings: Vec<ZkCommonCredentialRootClaimOpening>,
    ) -> Result<Self, ZkCommonCredentialRootClaimCommitmentError> {
        Self::restore_verified_for_lane(ZkCredentialHashAlgorithm::Sha256, issuer_root, openings)
    }

    /// Restore private openings under the exact issuer-authenticated hash lane.
    /// A stored Poseidon2 opening must never be reinterpreted as SHA-256.
    pub fn restore_verified_for_lane(
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        issuer_root: [u8; HASH_BYTES],
        openings: Vec<ZkCommonCredentialRootClaimOpening>,
    ) -> Result<Self, ZkCommonCredentialRootClaimCommitmentError> {
        if !(MIN_LEAVES..=MAX_LEAVES).contains(&openings.len()) {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimCount,
            ));
        }
        let lineage_hash = sha256(LINEAGE_NAME.as_bytes()).into_bytes();
        for (position, opening) in openings.iter().enumerate() {
            let expected_index = u32::try_from(position)
                .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
            if opening.leaf_index != expected_index
                || opening.salt.iter().all(|byte| *byte == 0)
                || opening.value.is_empty()
                || opening.value.len() > MAX_CLAIM_VALUE_BYTES
                || (position == 0
                    && (opening.name_hash != lineage_hash
                        || opening.value.len() != LINEAGE_VALUE_BYTES))
                || (position != 0 && opening.name_hash == lineage_hash)
                || openings[..position]
                    .iter()
                    .any(|earlier| earlier.name_hash == opening.name_hash)
            {
                return Err(invalid(
                    ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening,
                ));
            }
            verify_opening(
                credential_hash_algorithm,
                issuer_root,
                opening,
                openings.len(),
            )?;
        }
        Ok(Self {
            credential_hash_algorithm,
            root: issuer_root,
            openings,
        })
    }

    /// Exact issuer-signed credential hash lane.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Issuer-signed Merkle root for the selected common-credential-root lane.
    #[must_use]
    pub const fn root(&self) -> [u8; HASH_BYTES] {
        self.root
    }

    /// Accept the issuer's authenticated claim root before retaining private
    /// openings for later proofs. A valid credential signature alone does not
    /// show that the wallet still holds openings for that particular root.
    pub fn verify_issuer_root(
        &self,
        issuer_root: &[u8; HASH_BYTES],
    ) -> Result<(), ZkCommonCredentialRootClaimCommitmentError> {
        if self.root != *issuer_root {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::IssuerRootMismatch,
            ));
        }
        Ok(())
    }

    /// Ordered private openings retained by the holder.
    #[must_use]
    pub fn openings(&self) -> &[ZkCommonCredentialRootClaimOpening] {
        &self.openings
    }

    /// Salted lineage claim digest sent to issuers during ZK issuance.
    ///
    /// This is the `CLM1` digest of the reserved lineage opening, not the
    /// finished leaf. The issuer derives the `LEAF1` lineage leaf from it and
    /// recomputes the approved-claim root, while the holder keeps the lineage
    /// context, tag, and salt private for later proofs.
    pub fn opaque_lineage_claim_digest(
        &self,
    ) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
        let opening = self
            .openings
            .first()
            .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening))?;
        opening_claim_digest(self.credential_hash_algorithm, opening)
    }
}

fn verify_opening(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    issuer_root: [u8; HASH_BYTES],
    opening: &ZkCommonCredentialRootClaimOpening,
    leaf_count: usize,
) -> Result<(), ZkCommonCredentialRootClaimCommitmentError> {
    let mut digest = opening_leaf_digest(credential_hash_algorithm, opening)?;
    let mut index = usize::try_from(opening.leaf_index)
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    let mut width = leaf_count;
    let mut siblings = opening.siblings.iter();
    // Every opening spans the full fixed depth. A position beyond the issued
    // leaves at any level must hold the canonical empty subtree.
    for empty in empty_subtree_digests(credential_hash_algorithm)?.iter() {
        let sibling = siblings
            .next()
            .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening))?;
        if (index ^ 1) >= width && sibling != empty {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening,
            ));
        }
        digest = if index % 2 == 0 {
            parent_digest(credential_hash_algorithm, &digest, sibling)?
        } else {
            parent_digest(credential_hash_algorithm, sibling, &digest)?
        };
        index /= 2;
        width = width.div_ceil(2);
    }
    if siblings.next().is_some() || digest != issuer_root {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening,
        ));
    }
    Ok(())
}

/// Build the exact `CLM1`/`LEAF1`/`NODE1` SHA-256 commitment used by the
/// common-credential-root lineage and selected-claim circuits.
///
/// The caller must derive and check the context hash and lineage tag from the
/// holder's private root before issuance. The issuer signs the resulting root
/// in its SSI envelope; the wallet retains these openings for proving.
pub fn build_common_credential_root_sha256_claims_commitment(
    lineage: &ZkCommonCredentialRootDerivedLineage,
    lineage_salt: &[u8; SALT_BYTES],
    claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootClaimCommitmentError> {
    build_from_parts(&lineage.context_hash(), lineage.tag(), lineage_salt, claims)
}

/// Build the exact Poseidon2 `CLM1`/`LEAF1`/`NODE1` tree for v1 issuance.
/// Claim-name hashes remain SHA-256 in both lanes, as fixed by the circuit.
pub fn build_common_credential_root_poseidon2_claims_commitment(
    lineage: &ZkCommonCredentialRootDerivedLineage,
    lineage_salt: &[u8; SALT_BYTES],
    claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootClaimCommitmentError> {
    build_from_parts_for_lane(
        ZkCredentialHashAlgorithm::Poseidon2,
        &lineage.context_hash(),
        lineage.tag(),
        lineage_salt,
        claims,
    )
}

fn build_from_parts(
    context_hash: &[u8; HASH_BYTES],
    lineage_tag: &[u8; HASH_BYTES],
    lineage_salt: &[u8; SALT_BYTES],
    claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootClaimCommitmentError> {
    build_from_parts_for_lane(
        ZkCredentialHashAlgorithm::Sha256,
        context_hash,
        lineage_tag,
        lineage_salt,
        claims,
    )
}

fn build_from_parts_for_lane(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    context_hash: &[u8; HASH_BYTES],
    lineage_tag: &[u8; HASH_BYTES],
    lineage_salt: &[u8; SALT_BYTES],
    claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootClaimCommitmentError> {
    let leaf_count = claims
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    if !(MIN_LEAVES..=MAX_LEAVES).contains(&leaf_count) {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimCount,
        ));
    }
    if lineage_salt.iter().all(|byte| *byte == 0) {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidSalt,
        ));
    }

    let mut lineage_value = Zeroizing::new([0_u8; LINEAGE_VALUE_BYTES]);
    lineage_value[..HASH_BYTES].copy_from_slice(context_hash);
    lineage_value[HASH_BYTES..].copy_from_slice(lineage_tag);
    let mut leaves = Zeroizing::new(Vec::new());
    leaves
        .try_reserve_exact(leaf_count)
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    let mut openings = Vec::new();
    openings
        .try_reserve_exact(leaf_count)
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    append_claim(
        credential_hash_algorithm,
        LINEAGE_NAME,
        lineage_value.as_slice(),
        lineage_salt,
        &mut leaves,
        &mut openings,
    )?;
    for (position, claim) in claims.iter().enumerate() {
        if claim.name.is_empty()
            || claim.name.len() > MAX_CLAIM_NAME_BYTES
            || claim.name == LINEAGE_NAME
            || claims[..position]
                .iter()
                .any(|previous| previous.name == claim.name)
        {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName,
            ));
        }
        append_claim(
            credential_hash_algorithm,
            claim.name,
            claim.value,
            claim.salt,
            &mut leaves,
            &mut openings,
        )?;
    }

    let mut indexes: Vec<usize> = (0..leaf_count).collect();
    // The tree always has the fixed depth: positions beyond the issued leaves
    // hold the canonical empty subtree for that level.
    for empty in empty_subtree_digests(credential_hash_algorithm)?.iter() {
        for (opening, index) in openings.iter_mut().zip(&mut indexes) {
            let sibling = leaves.get(*index ^ 1).unwrap_or(empty);
            opening.siblings.push(*sibling);
            *index /= 2;
        }
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(leaves.len().div_ceil(2))
            .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
        for pair in leaves.chunks(2) {
            let left = *pair.first().ok_or_else(|| {
                invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded)
            })?;
            let right = pair.get(1).unwrap_or(empty);
            parents.push(parent_digest(credential_hash_algorithm, &left, right)?);
        }
        leaves.zeroize();
        *leaves = parents;
    }
    if leaves.len() != 1 {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded,
        ));
    }
    let root = leaves
        .first()
        .copied()
        .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    leaves.zeroize();
    Ok(ZkCommonCredentialRootClaimsCommitment {
        credential_hash_algorithm,
        root,
        openings,
    })
}

#[cfg(test)]
#[path = "common_credential_root_claim_commitment/tests.rs"]
mod tests;
