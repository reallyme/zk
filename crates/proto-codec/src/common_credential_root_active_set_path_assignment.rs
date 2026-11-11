// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-private active-set feed and Merkle path assignment.
//!
//! This record is encrypted wallet state. It binds the deployment-selected
//! feed to the locally derived active-set path without adding a feed public
//! input to the v1 circuits.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::common_root::COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FORMAT_VERSION: u32 = 1;
const HASH_BYTES: usize = 32;
const RECURSION_LIMIT: u32 = 16;
const WIRE_OVERHEAD_BYTES: usize = 128;
/// Maximum canonical wallet-private active-set assignment wire size.
pub const MAX_ROOT_ACTIVE_SET_PATH_ASSIGNMENT_BYTES: usize =
    (COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH + 3) * HASH_BYTES + WIRE_OVERHEAD_BYTES;
// Buffa charges each repeated sibling its decoded footprint, which is larger
// than its 32-byte wire payload. Budget exactly one full-depth path so the
// bound rejects surplus siblings without rejecting a maximum-depth assignment.
const STATUS_PATH_ELEMENT_MEMORY_LIMIT: usize =
    COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH * core::mem::size_of::<pb::ZkInputBytes32>();

/// Stable reason for rejecting wallet-private active-set path material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkRootActiveSetPathAssignmentReason {
    /// Protobuf bytes, field widths, sequence, or path shape are invalid.
    #[error("invalid active-set path assignment encoding")]
    InvalidEncoding,
}

/// Typed assignment codec error without IDs, roots, or Merkle nodes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("active-set path assignment rejected: {reason}")]
pub struct ZkRootActiveSetPathAssignmentError {
    reason: ZkRootActiveSetPathAssignmentReason,
}

impl ZkRootActiveSetPathAssignmentError {
    /// Return a stable, non-sensitive failure reason.
    #[must_use]
    pub const fn reason(self) -> ZkRootActiveSetPathAssignmentReason {
        self.reason
    }
}

/// Borrowed wallet-private path material ready for canonical encoding.
pub struct ZkRootActiveSetPathAssignmentRef<'a> {
    /// Deployment-pinned single-feed identifier selected for this wallet.
    pub feed_id: [u8; HASH_BYTES],
    /// Signed active-set root for the path.
    pub active_status_root: [u8; HASH_BYTES],
    /// Monotonic signed status sequence admitted for this path.
    pub sequence: u64,
    /// Private commitment-derived attestation ID opened by the path.
    pub attestation_id: &'a [u8; HASH_BYTES],
    /// Private leaf index in the active set.
    pub status_index: u32,
    /// Private Merkle siblings for the active status circuit.
    pub status_path: &'a [[u8; HASH_BYTES]],
}

/// Decoded wallet-private path material.
pub struct ZkDecodedRootActiveSetPathAssignment {
    feed_id: [u8; HASH_BYTES],
    active_status_root: [u8; HASH_BYTES],
    sequence: u64,
    attestation_id: Zeroizing<[u8; HASH_BYTES]>,
    status_index: u32,
    status_path: Zeroizing<Vec<[u8; HASH_BYTES]>>,
}

impl ZeroizeOnDrop for ZkDecodedRootActiveSetPathAssignment {}

impl ZkDecodedRootActiveSetPathAssignment {
    /// Deployment-pinned single-feed identifier selected for this wallet.
    #[must_use]
    pub const fn feed_id(&self) -> [u8; HASH_BYTES] {
        self.feed_id
    }

    /// Signed active-set root for the path.
    #[must_use]
    pub const fn active_status_root(&self) -> [u8; HASH_BYTES] {
        self.active_status_root
    }

    /// Monotonic signed status sequence admitted for this path.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Private commitment-derived attestation ID opened by the path.
    #[must_use]
    pub fn attestation_id(&self) -> &[u8; HASH_BYTES] {
        &self.attestation_id
    }

    /// Private leaf index in the active set.
    #[must_use]
    pub const fn status_index(&self) -> u32 {
        self.status_index
    }

    /// Private Merkle siblings for the active status circuit.
    #[must_use]
    pub fn status_path(&self) -> &[[u8; HASH_BYTES]] {
        self.status_path.as_slice()
    }
}

struct SensitiveAssignmentMessage(pb::ZkRootActiveSetPathAssignment);

impl Drop for SensitiveAssignmentMessage {
    fn drop(&mut self) {
        self.0.feed_id.zeroize();
        self.0.active_status_root.zeroize();
        self.0.attestation_id.zeroize();
        if let Some(path) = self.0.status_path.as_option_mut() {
            for sibling in &mut path.siblings {
                sibling.value.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for SensitiveAssignmentMessage {}

/// Encode one wallet-private feed/path assignment.
pub fn encode_root_active_set_path_assignment(
    assignment: ZkRootActiveSetPathAssignmentRef<'_>,
) -> Result<Zeroizing<Vec<u8>>, ZkRootActiveSetPathAssignmentError> {
    validate_assignment_shape(
        &assignment.feed_id,
        &assignment.active_status_root,
        assignment.sequence,
        assignment.attestation_id,
        assignment.status_path,
    )?;
    let mut wire = SensitiveAssignmentMessage(pb::ZkRootActiveSetPathAssignment::default());
    wire.0.format_version = FORMAT_VERSION;
    wire.0.feed_id = assignment.feed_id.to_vec();
    wire.0.active_status_root = assignment.active_status_root.to_vec();
    wire.0.sequence = assignment.sequence;
    wire.0.attestation_id = assignment.attestation_id.to_vec();
    wire.0.status_index = assignment.status_index;
    wire.0.status_path = MessageField::some(status_path(assignment.status_path)?);
    let encoded = Zeroizing::new(wire.0.encode_to_vec());
    if encoded.len() > MAX_ROOT_ACTIVE_SET_PATH_ASSIGNMENT_BYTES {
        return Err(invalid());
    }
    Ok(encoded)
}

/// Decode canonical wallet-private feed/path assignment bytes.
pub fn decode_root_active_set_path_assignment(
    bytes: &[u8],
) -> Result<ZkDecodedRootActiveSetPathAssignment, ZkRootActiveSetPathAssignmentError> {
    if bytes.is_empty() || bytes.len() > MAX_ROOT_ACTIVE_SET_PATH_ASSIGNMENT_BYTES {
        return Err(invalid());
    }
    let mut wire = SensitiveAssignmentMessage(
        DecodeOptions::new()
            .with_recursion_limit(RECURSION_LIMIT)
            .with_element_memory_limit(STATUS_PATH_ELEMENT_MEMORY_LIMIT)
            .with_max_message_size(MAX_ROOT_ACTIVE_SET_PATH_ASSIGNMENT_BYTES)
            .with_unknown_field_limit(0)
            .decode_from_slice::<pb::ZkRootActiveSetPathAssignment>(bytes)
            .map_err(|_| invalid())?,
    );
    let canonical = Zeroizing::new(wire.0.encode_to_vec());
    if wire.0.format_version != FORMAT_VERSION || canonical.as_slice() != bytes {
        return Err(invalid());
    }
    let path = wire.0.status_path.take().ok_or_else(invalid)?;
    let status_path = decode_status_path(&path)?;
    let feed_id = fixed::<HASH_BYTES>(&wire.0.feed_id)?;
    let active_status_root = fixed::<HASH_BYTES>(&wire.0.active_status_root)?;
    let attestation_id = fixed::<HASH_BYTES>(&wire.0.attestation_id)?;
    validate_assignment_shape(
        &feed_id,
        &active_status_root,
        wire.0.sequence,
        &attestation_id,
        &status_path,
    )?;
    Ok(ZkDecodedRootActiveSetPathAssignment {
        feed_id,
        active_status_root,
        sequence: wire.0.sequence,
        attestation_id: Zeroizing::new(attestation_id),
        status_index: wire.0.status_index,
        status_path: Zeroizing::new(status_path),
    })
}

fn status_path(
    siblings: &[[u8; HASH_BYTES]],
) -> Result<pb::ZkInputCommonCredentialRootStatusPath, ZkRootActiveSetPathAssignmentError> {
    let path_length = u32::try_from(siblings.len()).map_err(|_| invalid())?;
    let mut path = pb::ZkInputCommonCredentialRootStatusPath {
        path_length,
        ..Default::default()
    };
    path.siblings
        .try_reserve_exact(siblings.len())
        .map_err(|_| invalid())?;
    for sibling in siblings {
        let mut value = pb::ZkInputBytes32::default();
        value.value = sibling.to_vec();
        path.siblings.push(value);
    }
    Ok(path)
}

fn decode_status_path(
    path: &pb::ZkInputCommonCredentialRootStatusPath,
) -> Result<Vec<[u8; HASH_BYTES]>, ZkRootActiveSetPathAssignmentError> {
    let path_length = usize::try_from(path.path_length).map_err(|_| invalid())?;
    if path_length != path.siblings.len() || path_length > COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH {
        return Err(invalid());
    }
    let mut siblings = Vec::new();
    siblings
        .try_reserve_exact(path_length)
        .map_err(|_| invalid())?;
    for sibling in &path.siblings {
        siblings.push(fixed::<HASH_BYTES>(&sibling.value)?);
    }
    Ok(siblings)
}

fn validate_assignment_shape(
    feed_id: &[u8; HASH_BYTES],
    active_status_root: &[u8; HASH_BYTES],
    sequence: u64,
    attestation_id: &[u8; HASH_BYTES],
    status_path: &[[u8; HASH_BYTES]],
) -> Result<(), ZkRootActiveSetPathAssignmentError> {
    if feed_id.iter().all(|byte| *byte == 0)
        || active_status_root.iter().all(|byte| *byte == 0)
        || sequence == 0
        || attestation_id.iter().all(|byte| *byte == 0)
        || status_path.len() > COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH
    {
        return Err(invalid());
    }
    Ok(())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ZkRootActiveSetPathAssignmentError> {
    bytes.try_into().map_err(|_| invalid())
}

const fn invalid() -> ZkRootActiveSetPathAssignmentError {
    ZkRootActiveSetPathAssignmentError {
        reason: ZkRootActiveSetPathAssignmentReason::InvalidEncoding,
    }
}

#[cfg(test)]
#[path = "common_credential_root_active_set_path_assignment/tests.rs"]
mod tests;
