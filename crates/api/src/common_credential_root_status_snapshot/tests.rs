// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ZkRootStatusSnapshot, ZkRootStatusSnapshotReason};
use crate::keys::ZkStatusAuthorityPublicKey;
use thiserror::Error;

const LOW_S_SIGNATURE: [u8; 64] = [1; 64];
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Debug, Error)]
#[error("status snapshot test fixture failed")]
struct TestError;

fn snapshot() -> Result<ZkRootStatusSnapshot, super::ZkRootStatusSnapshotError> {
    ZkRootStatusSnapshot::try_from_parts(
        [3; 32],
        1_700_000_000,
        1_700_000_300,
        9,
        ZkStatusAuthorityPublicKey {
            x: [4; 32],
            y: [5; 32],
        },
        LOW_S_SIGNATURE,
    )
}

#[test]
fn snapshot_transcript_matches_independent_sha256_vector(
) -> Result<(), super::ZkRootStatusSnapshotError> {
    let signed = snapshot()?;
    assert_eq!(
        signed.signing_digest(),
        [
            0xf0, 0xc8, 0x06, 0x00, 0x14, 0xab, 0xd4, 0x2e, 0x1c, 0xd0, 0xf8, 0x1f, 0x3e, 0xa8,
            0xbe, 0xfa, 0x9b, 0x0b, 0xa9, 0x4f, 0x3b, 0x54, 0x4b, 0xc4, 0x5b, 0xf9, 0x64, 0x58,
            0x0d, 0xe4, 0xaf, 0x83,
        ]
    );
    assert_eq!(signed.status_root(), [3; 32]);
    assert_eq!(signed.sequence(), 9);
    Ok(())
}

#[test]
fn snapshot_rejects_reserved_and_inverted_fields() {
    let signer = ZkStatusAuthorityPublicKey {
        x: [4; 32],
        y: [5; 32],
    };
    for (root, issued, expires, sequence, signature, expected) in [
        (
            [0; 32],
            1,
            2,
            1,
            LOW_S_SIGNATURE,
            ZkRootStatusSnapshotReason::InvalidField,
        ),
        (
            [3; 32],
            1,
            2,
            0,
            LOW_S_SIGNATURE,
            ZkRootStatusSnapshotReason::InvalidField,
        ),
        (
            [3; 32],
            1,
            2,
            1,
            [0; 64],
            ZkRootStatusSnapshotReason::InvalidField,
        ),
        (
            [3; 32],
            0,
            2,
            1,
            LOW_S_SIGNATURE,
            ZkRootStatusSnapshotReason::InvalidInterval,
        ),
        (
            [3; 32],
            2,
            2,
            1,
            LOW_S_SIGNATURE,
            ZkRootStatusSnapshotReason::InvalidInterval,
        ),
        (
            [3; 32],
            3,
            2,
            1,
            LOW_S_SIGNATURE,
            ZkRootStatusSnapshotReason::InvalidInterval,
        ),
    ] {
        let result = ZkRootStatusSnapshot::try_from_parts(
            root, issued, expires, sequence, signer, signature,
        );
        assert_eq!(
            result.err().map(super::ZkRootStatusSnapshotError::reason),
            Some(expected)
        );
    }
}

#[test]
fn snapshot_rejects_high_s_artifact_signature() -> Result<(), TestError> {
    let signer = ZkStatusAuthorityPublicKey {
        x: [4; 32],
        y: [5; 32],
    };
    let result = ZkRootStatusSnapshot::try_from_parts(
        [3; 32],
        1,
        2,
        1,
        signer,
        high_s_twin(LOW_S_SIGNATURE)?,
    );
    assert_eq!(
        result.err().map(super::ZkRootStatusSnapshotError::reason),
        Some(ZkRootStatusSnapshotReason::InvalidField)
    );
    Ok(())
}

fn high_s_twin(mut signature: [u8; 64]) -> Result<[u8; 64], TestError> {
    let mut borrow = 0_u16;
    for index in (32..64).rev() {
        let minuend = u16::from(P256_ORDER[index - 32]);
        let subtrahend = u16::from(signature[index])
            .checked_add(borrow)
            .ok_or(TestError)?;
        let (value, next_borrow) = if minuend >= subtrahend {
            (minuend.checked_sub(subtrahend).ok_or(TestError)?, 0_u16)
        } else {
            (
                minuend
                    .checked_add(256)
                    .and_then(|value| value.checked_sub(subtrahend))
                    .ok_or(TestError)?,
                1_u16,
            )
        };
        signature[index] = u8::try_from(value).map_err(|_| TestError)?;
        borrow = next_borrow;
    }
    if borrow != 0 {
        return Err(TestError);
    }
    Ok(signature)
}
