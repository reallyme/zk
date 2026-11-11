// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical protobuf boundary for signed ReallyMe active-root snapshots.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::{
    common_root::ZkRootStatusSnapshot,
    errors::{ZkError, ZkErrorReason},
    keys::ZkStatusAuthorityPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, Zeroizing};

const SNAPSHOT_FORMAT_VERSION: u32 = 1;
/// Maximum canonical signed active-root snapshot wire size.
pub const MAX_ROOT_STATUS_SNAPSHOT_BYTES: usize = 256;
const RECURSION_LIMIT: u32 = 8;

struct SnapshotWire(pb::ZkRootStatusSnapshot);

impl Drop for SnapshotWire {
    fn drop(&mut self) {
        self.0.status_root.zeroize();
        self.0.signature.zeroize();
    }
}

/// Encode a validated snapshot using the canonical Buffa message shape.
pub fn encode_root_status_snapshot(snapshot: &ZkRootStatusSnapshot) -> Result<Vec<u8>, ZkError> {
    let mut wire = SnapshotWire(pb::ZkRootStatusSnapshot::default());
    wire.0.format_version = SNAPSHOT_FORMAT_VERSION;
    wire.0.status_root = snapshot.status_root().to_vec();
    wire.0.issued_unix = snapshot.issued_unix();
    wire.0.expires_unix = snapshot.expires_unix();
    wire.0.sequence = snapshot.sequence();
    wire.0.signer = MessageField::some(pb::ZkP256PublicKey {
        x: snapshot.signer().x.to_vec(),
        y: snapshot.signer().y.to_vec(),
        ..Default::default()
    });
    wire.0.signature = snapshot.signature().to_vec();
    let mut encoded = wire.0.encode_to_vec();
    if encoded.len() > MAX_ROOT_STATUS_SNAPSHOT_BYTES {
        encoded.zeroize();
        return Err(invalid());
    }
    Ok(encoded)
}

/// Decode canonical bytes before separately checking the authority signature.
pub fn decode_root_status_snapshot(bytes: &[u8]) -> Result<ZkRootStatusSnapshot, ZkError> {
    if bytes.is_empty() || bytes.len() > MAX_ROOT_STATUS_SNAPSHOT_BYTES {
        return Err(invalid());
    }
    let mut wire = SnapshotWire(
        DecodeOptions::new()
            .with_recursion_limit(RECURSION_LIMIT)
            .with_element_memory_limit(MAX_ROOT_STATUS_SNAPSHOT_BYTES)
            .with_max_message_size(MAX_ROOT_STATUS_SNAPSHOT_BYTES)
            .with_unknown_field_limit(0)
            .decode_from_slice::<pb::ZkRootStatusSnapshot>(bytes)
            .map_err(|_| invalid())?,
    );
    let canonical = Zeroizing::new(wire.0.encode_to_vec());
    if wire.0.format_version != SNAPSHOT_FORMAT_VERSION || canonical.as_slice() != bytes {
        return Err(invalid());
    }
    let signer = wire.0.signer.take().ok_or_else(invalid)?;
    let signer = ZkStatusAuthorityPublicKey {
        x: fixed::<32>(&signer.x)?,
        y: fixed::<32>(&signer.y)?,
    };
    ZkRootStatusSnapshot::try_from_parts(
        fixed::<32>(&wire.0.status_root)?,
        wire.0.issued_unix,
        wire.0.expires_unix,
        wire.0.sequence,
        signer,
        fixed::<64>(&wire.0.signature)?,
    )
    .map_err(|_| invalid())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ZkError> {
    bytes.try_into().map_err(|_| invalid())
}

fn invalid() -> ZkError {
    ZkError::new(ZkErrorReason::InvalidProofEncoding)
}

#[cfg(test)]
#[path = "common_credential_root_status_snapshot/tests.rs"]
mod tests;
