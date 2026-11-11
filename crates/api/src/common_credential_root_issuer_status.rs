// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical Merkle commitment to an issuer's signed status bitstring.
//!
//! A verifier authenticates the SSI status list before computing this root.
//! The holder opens only the 256-bit chunk containing its private status index
//! in a circuit; the status index itself never becomes a verifier input.

use crypto_sha2_256::digest as sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const LEAF_DOMAIN: &[u8; 6] = b"RMCSL1";
const NODE_DOMAIN: &[u8; 6] = b"RMCSN1";
const EMPTY_DOMAIN: &[u8; 6] = b"RMCSE1";
const ROOT_DOMAIN: &[u8; 6] = b"RMCSR1";
const HASH_BYTES: usize = 32;
const STATUS_BITS_PER_BYTE: u64 = 8;
const STATUS_BITS_PER_CHUNK: u64 = 256;
const MAX_STATUS_ENTRIES: u64 = 1_000_000;
/// Fixed chunk width consumed by the issuer-status circuit.
pub const COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES: usize = 32;
/// Maximum Merkle path depth for one million status entries.
pub const COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH: usize = 12;

/// Stable reason for rejecting an issuer-status commitment or private opening.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootIssuerStatusReason {
    /// The signed bitstring length, tail bits, or private index is invalid.
    #[error("invalid issuer-status bitstring")]
    InvalidBitstring,
    /// A bounded calculation or allocation could not be completed.
    #[error("issuer-status capacity exceeded")]
    Capacity,
    /// The selected credential is revoked or suspended in this list.
    #[error("issuer credential inactive")]
    Inactive,
    /// The private opening does not match the authenticated list root.
    #[error("issuer-status root mismatch")]
    RootMismatch,
}

/// Typed issuer-status failure without credential or list contents.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("common-credential-root issuer-status admission failed: {reason}")]
pub struct ZkCommonCredentialRootIssuerStatusError {
    reason: ZkCommonCredentialRootIssuerStatusReason,
}

impl ZkCommonCredentialRootIssuerStatusError {
    /// Stable reason safe for FFI mapping and logs.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootIssuerStatusReason {
        self.reason
    }
}

/// One private status chunk and its path into an authenticated list root.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZkCommonCredentialRootIssuerStatusOpening {
    chunk: [u8; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES],
    siblings: Vec<[u8; HASH_BYTES]>,
}

impl ZkCommonCredentialRootIssuerStatusOpening {
    /// Copy the fixed-size private chunk into a witness owner.
    #[must_use]
    pub const fn chunk(&self) -> &[u8; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES] {
        &self.chunk
    }

    /// Borrow the private Merkle siblings for witness construction.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; HASH_BYTES]] {
        self.siblings.as_slice()
    }
}

/// Derive the root from a signature-verified SSI status list's raw bitstring.
///
/// The signature, list identifier, purpose, and freshness remain verifier
/// policy checks. This operation authenticates no list by itself.
pub fn common_credential_root_issuer_status_root(
    encoded_list: &[u8],
    length: u64,
) -> Result<[u8; HASH_BYTES], ZkCommonCredentialRootIssuerStatusError> {
    let (root, _) = build(encoded_list, length, None)?;
    Ok(root)
}

/// Derive a private opening after the wallet authenticates the current list.
pub fn common_credential_root_issuer_status_opening(
    encoded_list: &[u8],
    length: u64,
    index: u64,
) -> Result<
    ([u8; HASH_BYTES], ZkCommonCredentialRootIssuerStatusOpening),
    ZkCommonCredentialRootIssuerStatusError,
> {
    let (root, opening) = build(encoded_list, length, Some(index))?;
    let opening =
        opening.ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring))?;
    Ok((root, opening))
}

/// Preflight the exact witness opening against a verifier-authenticated root.
///
/// The proving circuit must repeat this check; a wallet-side result is never
/// verifier evidence on its own.
pub fn verify_common_credential_root_issuer_status_opening(
    expected_root: &[u8; HASH_BYTES],
    length: u64,
    index: u64,
    opening: &ZkCommonCredentialRootIssuerStatusOpening,
) -> Result<(), ZkCommonCredentialRootIssuerStatusError> {
    if length == 0 || length > MAX_STATUS_ENTRIES || index >= length {
        return Err(error(
            ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring,
        ));
    }
    let chunk_index = index / STATUS_BITS_PER_CHUNK;
    let leaf_count = length
        .checked_add(STATUS_BITS_PER_CHUNK - 1)
        .and_then(|value| value.checked_div(STATUS_BITS_PER_CHUNK))
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let width = usize::try_from(leaf_count)
        .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?
        .checked_next_power_of_two()
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let depth = width.trailing_zeros();
    let expected_depth = usize::try_from(depth)
        .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    if opening.siblings.len() != expected_depth
        || expected_depth > COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH
        || !selected_bit_clear(&opening.chunk, index)?
    {
        return Err(error(
            ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring,
        ));
    }
    let mut current = leaf(&opening.chunk);
    for (level, sibling) in opening.siblings.iter().enumerate() {
        let level = u32::try_from(level)
            .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
        current = if (chunk_index >> level) & 1 == 0 {
            node(&current, sibling)
        } else {
            node(sibling, &current)
        };
    }
    let derived = root(length, &current);
    if !bool::from(derived.ct_eq(expected_root)) {
        return Err(error(
            ZkCommonCredentialRootIssuerStatusReason::RootMismatch,
        ));
    }
    Ok(())
}

fn build(
    encoded_list: &[u8],
    length: u64,
    index: Option<u64>,
) -> Result<
    (
        [u8; HASH_BYTES],
        Option<ZkCommonCredentialRootIssuerStatusOpening>,
    ),
    ZkCommonCredentialRootIssuerStatusError,
> {
    validate_bitstring(encoded_list, length)?;
    if index.is_some_and(|value| value >= length) {
        return Err(error(
            ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring,
        ));
    }
    let chunk_count = encoded_list
        .len()
        .checked_add(COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES - 1)
        .and_then(|value| value.checked_div(COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES))
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let width = chunk_count
        .checked_next_power_of_two()
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let empty = sha256(EMPTY_DOMAIN).into_bytes();
    let mut level = Vec::new();
    level
        .try_reserve_exact(width)
        .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    for bytes in encoded_list.chunks(COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES) {
        let mut chunk = [0_u8; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES];
        chunk[..bytes.len()].copy_from_slice(bytes);
        level.push(leaf(&chunk));
    }
    level.resize(width, empty);

    let mut selected =
        if let Some(index) = index {
            let chunk_start = usize::try_from(index / STATUS_BITS_PER_CHUNK)
                .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?
                .checked_mul(COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES)
                .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
            let available = encoded_list.len().saturating_sub(chunk_start);
            let copy_len = available.min(COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES);
            let end = chunk_start
                .checked_add(copy_len)
                .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
            let mut chunk = [0_u8; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES];
            chunk[..copy_len].copy_from_slice(encoded_list.get(chunk_start..end).ok_or_else(
                || error(ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring),
            )?);
            if !selected_bit_clear(&chunk, index)? {
                return Err(error(ZkCommonCredentialRootIssuerStatusReason::Inactive));
            }
            let mut siblings = Vec::new();
            siblings
                .try_reserve_exact(COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH)
                .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
            Some((
                chunk,
                siblings,
                usize::try_from(index / STATUS_BITS_PER_CHUNK)
                    .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?,
            ))
        } else {
            None
        };

    while level.len() > 1 {
        if let Some((_, siblings, position)) = &mut selected {
            let sibling_index = *position ^ 1;
            siblings.push(
                *level
                    .get(sibling_index)
                    .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?,
            );
            *position >>= 1;
        }
        let mut next = Vec::new();
        next.try_reserve_exact(level.len() / 2)
            .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
        for pair in level.as_chunks::<2>().0 {
            next.push(node(&pair[0], &pair[1]));
        }
        level = next;
    }
    let top = level
        .first()
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let derived = root(length, top);
    let opening = selected
        .map(|(chunk, siblings, _)| ZkCommonCredentialRootIssuerStatusOpening { chunk, siblings });
    Ok((derived, opening))
}

fn validate_bitstring(
    encoded_list: &[u8],
    length: u64,
) -> Result<(), ZkCommonCredentialRootIssuerStatusError> {
    if length == 0 || length > MAX_STATUS_ENTRIES {
        return Err(error(
            ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring,
        ));
    }
    let bytes = length
        .checked_add(STATUS_BITS_PER_BYTE - 1)
        .and_then(|value| value.checked_div(STATUS_BITS_PER_BYTE))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    if encoded_list.len() != bytes {
        return Err(error(
            ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring,
        ));
    }
    let used_tail_bits = u8::try_from(length % STATUS_BITS_PER_BYTE)
        .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    if used_tail_bits != 0 {
        let tail_mask = u8::MAX
            .checked_shl(u32::from(used_tail_bits))
            .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
        if encoded_list
            .last()
            .is_some_and(|last| last & tail_mask != 0)
        {
            return Err(error(
                ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring,
            ));
        }
    }
    Ok(())
}

fn selected_bit_clear(
    chunk: &[u8; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES],
    index: u64,
) -> Result<bool, ZkCommonCredentialRootIssuerStatusError> {
    let offset = index % STATUS_BITS_PER_CHUNK;
    let byte = usize::try_from(offset / STATUS_BITS_PER_BYTE)
        .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let shift = u32::try_from(offset % STATUS_BITS_PER_BYTE)
        .map_err(|_| error(ZkCommonCredentialRootIssuerStatusReason::Capacity))?;
    let value = chunk
        .get(byte)
        .ok_or_else(|| error(ZkCommonCredentialRootIssuerStatusReason::InvalidBitstring))?;
    Ok(value & (1_u8 << shift) == 0)
}

fn leaf(chunk: &[u8; COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = [0_u8; LEAF_DOMAIN.len() + COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES];
    preimage[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    preimage[LEAF_DOMAIN.len()..].copy_from_slice(chunk);
    sha256(&preimage).into_bytes()
}

fn node(left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = [0_u8; NODE_DOMAIN.len() + 2 * HASH_BYTES];
    preimage[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    preimage[NODE_DOMAIN.len()..NODE_DOMAIN.len() + HASH_BYTES].copy_from_slice(left);
    preimage[NODE_DOMAIN.len() + HASH_BYTES..].copy_from_slice(right);
    sha256(&preimage).into_bytes()
}

fn root(length: u64, top: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = [0_u8; ROOT_DOMAIN.len() + 8 + HASH_BYTES];
    preimage[..ROOT_DOMAIN.len()].copy_from_slice(ROOT_DOMAIN);
    preimage[ROOT_DOMAIN.len()..ROOT_DOMAIN.len() + 8].copy_from_slice(&length.to_be_bytes());
    preimage[ROOT_DOMAIN.len() + 8..].copy_from_slice(top);
    sha256(&preimage).into_bytes()
}

const fn error(
    reason: ZkCommonCredentialRootIssuerStatusReason,
) -> ZkCommonCredentialRootIssuerStatusError {
    ZkCommonCredentialRootIssuerStatusError { reason }
}

#[cfg(test)]
#[path = "common_credential_root_issuer_status/tests.rs"]
mod tests;
