// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_poseidon2::hash_bytes as poseidon2_hash_bytes;
use crypto_sha2_256::digest as sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::circuits::ZkCredentialHashAlgorithm;

use super::{
    invalid, ZkCommonCredentialRootClaimCommitmentError,
    ZkCommonCredentialRootClaimCommitmentReason, ZkCommonCredentialRootClaimOpening, CLAIM_DOMAIN,
    CLAIM_TREE_DEPTH, HASH_BYTES, LEAF_DOMAIN, LINEAGE_NAME, MAX_CLAIM_VALUE_BYTES,
    MAX_INNER_PREIMAGE_BYTES, NODE_DOMAIN, SALT_BYTES,
};

pub(super) fn append_claim(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    name: &str,
    value: &[u8],
    salt: &[u8; SALT_BYTES],
    leaves: &mut Vec<[u8; HASH_BYTES]>,
    openings: &mut Vec<ZkCommonCredentialRootClaimOpening>,
) -> Result<(), ZkCommonCredentialRootClaimCommitmentError> {
    if value.is_empty() || value.len() > MAX_CLAIM_VALUE_BYTES {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidValueLength,
        ));
    }
    if salt.iter().all(|byte| *byte == 0) {
        return Err(invalid(
            ZkCommonCredentialRootClaimCommitmentReason::InvalidSalt,
        ));
    }
    let name_hash = sha256(name.as_bytes()).into_bytes();
    leaves.push(claim_leaf_digest(
        credential_hash_algorithm,
        name,
        value,
        salt,
    )?);
    let leaf_index = u32::try_from(openings.len())
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    let mut owned_value = Vec::new();
    owned_value
        .try_reserve_exact(value.len())
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    owned_value.extend_from_slice(value);
    openings.push(ZkCommonCredentialRootClaimOpening {
        name_hash,
        value: owned_value,
        salt: *salt,
        leaf_index,
        siblings: Vec::new(),
    });
    Ok(())
}

pub(super) fn claim_leaf_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    name: &str,
    value: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    let name_hash = sha256(name.as_bytes()).into_bytes();
    leaf_digest_from_name_hash(credential_hash_algorithm, &name_hash, value, salt)
}

pub(super) fn opening_leaf_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    opening: &ZkCommonCredentialRootClaimOpening,
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    leaf_digest_from_name_hash(
        credential_hash_algorithm,
        &opening.name_hash,
        &opening.value,
        &opening.salt,
    )
}

/// Salted `CLM1` digest of one opening. For the reserved lineage opening this
/// is the only lineage-derived value an issuer receives.
pub(super) fn opening_claim_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    opening: &ZkCommonCredentialRootClaimOpening,
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    claim_digest(credential_hash_algorithm, &opening.value, &opening.salt)
}

/// Reserved lineage leaf computed by the issuer from the wallet's salted
/// lineage claim digest.
///
/// The issuer applies the `LEAF1` domain and the reserved lineage name hash
/// itself, so every leaf under the signed root is a domain-separated leaf
/// whose structure the issuer produced. A wallet-supplied interior node
/// cannot occupy the lineage slot.
pub(super) fn lineage_leaf_digest_from_claim_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    lineage_claim_digest: &[u8; HASH_BYTES],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    let name_hash = sha256(LINEAGE_NAME.as_bytes()).into_bytes();
    leaf_digest_from_claim_digest(credential_hash_algorithm, &name_hash, lineage_claim_digest)
}

// Issuer root reconstruction and restored wallet openings must use the same
// transcript implementation; a difference here would let issuance and proving
// disagree about which claim the issuer authenticated.
fn leaf_digest_from_name_hash(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    name_hash: &[u8; HASH_BYTES],
    value: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    let inner = Zeroizing::new(claim_digest(credential_hash_algorithm, value, salt)?);
    leaf_digest_from_claim_digest(credential_hash_algorithm, name_hash, &inner)
}

fn leaf_digest_from_claim_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    name_hash: &[u8; HASH_BYTES],
    inner: &[u8; HASH_BYTES],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    let mut preimage = Zeroizing::new([0_u8; LEAF_DOMAIN.len() + HASH_BYTES + HASH_BYTES]);
    preimage[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    preimage[LEAF_DOMAIN.len()..LEAF_DOMAIN.len() + HASH_BYTES].copy_from_slice(name_hash);
    preimage[LEAF_DOMAIN.len() + HASH_BYTES..].copy_from_slice(inner);
    digest(credential_hash_algorithm, preimage.as_slice())
}

fn claim_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    value: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    let value_len = u32::try_from(value.len())
        .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    let used = CLAIM_DOMAIN
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .and_then(|length| length.checked_add(SALT_BYTES))
        .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    let mut preimage = Zeroizing::new([0_u8; MAX_INNER_PREIMAGE_BYTES]);
    preimage[..CLAIM_DOMAIN.len()].copy_from_slice(CLAIM_DOMAIN);
    preimage[CLAIM_DOMAIN.len()..CLAIM_DOMAIN.len() + 4].copy_from_slice(&value_len.to_be_bytes());
    let value_start = CLAIM_DOMAIN.len() + 4;
    let value_end = value_start
        .checked_add(value.len())
        .ok_or_else(|| invalid(ZkCommonCredentialRootClaimCommitmentReason::SizeExceeded))?;
    preimage[value_start..value_end].copy_from_slice(value);
    preimage[value_end..used].copy_from_slice(salt);
    digest(credential_hash_algorithm, &preimage[..used])
}

/// Digests of empty claim subtrees, indexed by height.
///
/// An empty leaf is 32 zero bytes, which is not the digest of any `LEAF1`
/// preimage and therefore cannot be opened as a claim. Height `k` is the node
/// over two empty subtrees of height `k - 1`. Entry `k` is the sibling used at
/// level `k` wherever the issued leaves do not reach.
pub(super) fn empty_subtree_digests(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<[[u8; HASH_BYTES]; CLAIM_TREE_DEPTH], ZkCommonCredentialRootClaimCommitmentError> {
    let mut digests = [[0_u8; HASH_BYTES]; CLAIM_TREE_DEPTH];
    let mut below = [0_u8; HASH_BYTES];
    for digest in digests.iter_mut().skip(1) {
        below = parent_digest(credential_hash_algorithm, &below, &below)?;
        *digest = below;
    }
    Ok(digests)
}

pub(super) fn parent_digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    left: &[u8; HASH_BYTES],
    right: &[u8; HASH_BYTES],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    let mut preimage = [0_u8; NODE_DOMAIN.len() + HASH_BYTES + HASH_BYTES];
    preimage[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    preimage[NODE_DOMAIN.len()..NODE_DOMAIN.len() + HASH_BYTES].copy_from_slice(left);
    preimage[NODE_DOMAIN.len() + HASH_BYTES..].copy_from_slice(right);
    let result = digest(credential_hash_algorithm, &preimage);
    preimage.zeroize();
    result
}

fn digest(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    preimage: &[u8],
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootClaimCommitmentError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => Ok(sha256(preimage).into_bytes()),
        ZkCredentialHashAlgorithm::Poseidon2 => poseidon2_hash_bytes(preimage)
            .map(crypto_poseidon2::Poseidon2Digest::into_bytes)
            .map_err(|_| invalid(ZkCommonCredentialRootClaimCommitmentReason::HashFailed)),
    }
}
