// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure validation of source-closure identities in the pinned circuit lock.

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
};

use crate::Digest32;

const LOCK_HEADER: &str = "circuit\tpackage\tsource_closure_sha256";
const SHA256_HEX_BYTES: usize = 64;

/// Finds the single source-closure digest for an exact circuit reference.
pub fn common_credential_root_source_closure_from_lock(
    lock_bytes: &[u8],
    circuit_ref: ZkCircuitRef,
) -> Result<Digest32, ZkError> {
    let lock = core::str::from_utf8(lock_bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let mut lines = lock.lines();
    if lines.next() != Some(LOCK_HEADER) {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let name = [
        circuit_ref.credential_hash_algorithm.source_dir(),
        "families",
        circuit_ref.family.source_dir(),
        circuit_ref.stage.source_dir(),
    ]
    .join("/");
    let mut found = None;
    for line in lines {
        let mut fields = line.split('\t');
        let circuit = fields
            .next()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let package = fields
            .next()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let digest = fields
            .next()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        if package.is_empty() || fields.next().is_some() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if circuit == name {
            if found.is_some() {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            found = Some(parse_digest(digest)?);
        }
    }
    found.ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))
}

fn parse_digest(value: &str) -> Result<Digest32, ZkError> {
    if value.len() != SHA256_HEX_BYTES {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut bytes = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        *bytes
            .get_mut(index)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))? = (high << 4) | low;
    }
    Ok(Digest32::from_bytes(bytes))
}

fn hex_nibble(byte: u8) -> Result<u8, ZkError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ZkError::new(ZkErrorReason::ArtifactMismatch)),
    }
}
