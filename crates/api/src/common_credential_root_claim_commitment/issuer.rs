// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer-side reconstruction of the exact common-credential-root claim transcript.

use zeroize::{Zeroize, Zeroizing};

use crate::circuits::ZkCredentialHashAlgorithm;

use super::transcript::{
    claim_leaf_digest, empty_subtree_digests, lineage_leaf_digest_from_claim_digest, parent_digest,
};
use super::{
    invalid, ZkCommonCredentialRootClaim, ZkCommonCredentialRootClaimCommitmentError,
    ZkCommonCredentialRootClaimCommitmentReason, HASH_BYTES, LINEAGE_NAME, MAX_CLAIM_NAME_BYTES,
    MAX_CLAIM_VALUE_BYTES, MAX_LEAVES, MIN_LEAVES,
};

/// Root material approved by an issuer-side reconstruction of the ZK transcript.
///
/// The constructor is private to this module so production issuance code can
/// require this owner instead of accepting caller-supplied root bytes. This
/// keeps envelope signing behind the same claim/value/salt/lineage check used
/// by the common-credential-root circuits.
#[derive(Eq, PartialEq)]
pub struct ZkCommonCredentialRootApprovedIssuerRoot {
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    root: [u8; HASH_BYTES],
}

impl Drop for ZkCommonCredentialRootApprovedIssuerRoot {
    fn drop(&mut self) {
        self.root.zeroize();
    }
}

impl core::fmt::Debug for ZkCommonCredentialRootApprovedIssuerRoot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootApprovedIssuerRoot")
            .field("credential_hash_algorithm", &self.credential_hash_algorithm)
            .field("root", &"<redacted>")
            .finish()
    }
}

impl ZkCommonCredentialRootApprovedIssuerRoot {
    /// Hash lane used by the checked transcript.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Approved common-credential-root claim commitment root.
    #[must_use]
    pub const fn root(&self) -> [u8; HASH_BYTES] {
        self.root
    }
}

/// Check a proposed root against facts independently approved by the issuer.
///
/// The issuer obtains each claim's canonical name and value from its own
/// issuance decision, and the corresponding salt from the wallet. For the
/// reserved lineage slot the wallet supplies only the salted `CLM1` claim
/// digest; the issuer applies the `LEAF1` domain and reserved lineage name
/// hash itself. Every leaf under the signed root is therefore a
/// domain-separated leaf constructed by the issuer, so the wallet can neither
/// substitute an unapproved claim nor place a subtree of additional claims in
/// the lineage slot. The digest reveals nothing beyond the leaf it produces,
/// and the private lineage value stays with the wallet.
pub fn verify_common_credential_root_sha256_issuer_claims_root(
    proposed_root: [u8; HASH_BYTES],
    opaque_lineage_claim_digest: [u8; HASH_BYTES],
    approved_claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootApprovedIssuerRoot, ZkCommonCredentialRootClaimCommitmentError> {
    verify_issuer_claims_root(
        ZkCredentialHashAlgorithm::Sha256,
        proposed_root,
        opaque_lineage_claim_digest,
        approved_claims,
    )
}

/// Recompute a proposed Poseidon2 issuer root from the wallet's salted lineage
/// claim digest and issuer-approved facts. The issuer never receives the
/// private lineage value.
pub fn verify_common_credential_root_poseidon2_issuer_claims_root(
    proposed_root: [u8; HASH_BYTES],
    opaque_lineage_claim_digest: [u8; HASH_BYTES],
    approved_claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootApprovedIssuerRoot, ZkCommonCredentialRootClaimCommitmentError> {
    verify_issuer_claims_root(
        ZkCredentialHashAlgorithm::Poseidon2,
        proposed_root,
        opaque_lineage_claim_digest,
        approved_claims,
    )
}

fn verify_issuer_claims_root(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proposed_root: [u8; HASH_BYTES],
    opaque_lineage_claim_digest: [u8; HASH_BYTES],
    approved_claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<ZkCommonCredentialRootApprovedIssuerRoot, ZkCommonCredentialRootClaimCommitmentError> {
    let leaf_count = approved_claims
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    if !(MIN_LEAVES..=MAX_LEAVES).contains(&leaf_count) {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimCount,
        ));
    }
    if opaque_lineage_claim_digest.iter().all(|byte| *byte == 0) {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidLineageLeaf,
        ));
    }
    let mut leaves = Zeroizing::new(Vec::new());
    leaves
        .try_reserve_exact(leaf_count)
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    leaves.push(lineage_leaf_digest_from_claim_digest(
        credential_hash_algorithm,
        &opaque_lineage_claim_digest,
    )?);
    for (position, claim) in approved_claims.iter().enumerate() {
        if claim.name.is_empty()
            || claim.name.len() > MAX_CLAIM_NAME_BYTES
            || claim.name == LINEAGE_NAME
            || approved_claims[..position]
                .iter()
                .any(|previous| previous.name == claim.name)
        {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName,
            ));
        }
        if claim.value.is_empty() || claim.value.len() > MAX_CLAIM_VALUE_BYTES {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::InvalidValueLength,
            ));
        }
        if claim.salt.iter().all(|byte| *byte == 0) {
            return Err(invalid(
                ZkCommonCredentialRootClaimCommitmentReason::InvalidSalt,
            ));
        }
        leaves.push(claim_leaf_digest(
            credential_hash_algorithm,
            claim.name,
            claim.value,
            claim.salt,
        )?);
    }
    // Reconstruct the fixed-depth tree: positions beyond the approved leaves
    // hold the canonical empty subtree for that level.
    for empty in empty_subtree_digests(credential_hash_algorithm)?.iter() {
        let mut parents = Zeroizing::new(Vec::new());
        parents
            .try_reserve_exact(leaves.len().div_ceil(2))
            .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
        for pair in leaves.chunks(2) {
            let left = pair.first().ok_or_else(|| {
                invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded)
            })?;
            let right = pair.get(1).unwrap_or(empty);
            parents.push(parent_digest(credential_hash_algorithm, left, right)?);
        }
        leaves.zeroize();
        *leaves = core::mem::take(&mut *parents);
    }
    if leaves.len() != 1 || leaves.first().copied() != Some(proposed_root) {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::IssuerRootMismatch,
        ));
    }
    Ok(ZkCommonCredentialRootApprovedIssuerRoot {
        credential_hash_algorithm,
        root: proposed_root,
    })
}
