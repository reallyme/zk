// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_sha2_256::digest as sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{ZkCommonCredentialRootActiveSet, ZkCommonCredentialRootActiveSetReason};
use crate::{
    common_root::{
        verify_common_credential_root_active_status_membership, verify_root_status_snapshot,
        ZkRootStatusSnapshot, ZkRootStatusTrustPolicy, ZkVerifiedRootStatusSnapshot,
    },
    keys::ZkIssuerPublicKey,
};

const NOW: u64 = 1_800_000_000;

#[derive(Debug, Error)]
#[error("active-set test fixture failed")]
struct TestError;

fn signed_root(root: [u8; 32]) -> Result<ZkVerifiedRootStatusSnapshot, TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
    let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
    let signer = ZkIssuerPublicKey {
        x: point[1..33].try_into().map_err(|_| TestError)?,
        y: point[33..65].try_into().map_err(|_| TestError)?,
    };
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(root, NOW - 1, NOW + 60, 7);
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
        .map_err(|_| TestError)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| TestError)?;
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        root,
        NOW - 1,
        NOW + 60,
        7,
        crate::keys::ZkStatusAuthorityPublicKey::from(crate::keys::ZkP256PublicKey::from(signer)),
        signature,
    )
    .map_err(|_| TestError)?;
    verify_root_status_snapshot(
        snapshot,
        ZkRootStatusTrustPolicy {
            authority: crate::keys::ZkStatusAuthorityPublicKey::from(
                crate::keys::ZkP256PublicKey::from(signer),
            ),
            minimum_sequence: 7,
            maximum_age_seconds: 120,
        },
        NOW,
    )
    .map_err(|_| TestError)
}

fn leaf(id: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0_u8; 38];
    preimage[..6].copy_from_slice(b"RMSTL2");
    preimage[6..].copy_from_slice(id);
    sha256(&preimage).into_bytes()
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0_u8; 70];
    preimage[..6].copy_from_slice(b"RMSTN1");
    preimage[6..38].copy_from_slice(left);
    preimage[38..].copy_from_slice(right);
    sha256(&preimage).into_bytes()
}

#[test]
fn published_tree_opens_only_members_against_the_signed_current_root() -> Result<(), TestError> {
    let ids = [[1_u8; 32], [2_u8; 32], [3_u8; 32]];
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&ids).map_err(|_| TestError)?;
    let expected_root = node(
        &node(&leaf(&ids[0]), &leaf(&ids[1])),
        &node(&leaf(&ids[2]), &leaf(&[0_u8; 32])),
    );
    assert_eq!(set.root(), expected_root);
    assert_eq!(set.len(), 3);
    let snapshot = signed_root(expected_root)?;
    for (expected_index, id) in ids.iter().enumerate() {
        let opening = set.open_against(snapshot, NOW, id).map_err(|_| TestError)?;
        assert_eq!(
            usize::try_from(opening.index()).map_err(|_| TestError)?,
            expected_index
        );
        assert_eq!(opening.siblings().len(), 2);
        assert!(verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            id,
            opening.index(),
            opening.siblings(),
        )
        .is_ok());
    }
    assert_eq!(
        set.open_against(snapshot, NOW, &[4_u8; 32])
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveSetReason::NotActive)
    );
    let wrong_snapshot = signed_root(leaf(&ids[0]))?;
    assert_eq!(
        set.open_against(wrong_snapshot, NOW, &ids[0])
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveSetReason::SnapshotMismatch)
    );
    assert_eq!(
        set.open_against(snapshot, NOW + 60, &ids[0])
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveSetReason::SnapshotMismatch)
    );
    Ok(())
}

#[test]
fn published_set_rejects_ambiguous_ordering_and_revoked_ids() -> Result<(), TestError> {
    for ids in [
        vec![[0_u8; 32]],
        vec![[2_u8; 32], [1_u8; 32]],
        vec![[1_u8; 32], [1_u8; 32]],
    ] {
        assert_eq!(
            ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&ids)
                .err()
                .map(|error| error.reason()),
            Some(ZkCommonCredentialRootActiveSetReason::InvalidSet)
        );
    }
    let without_revoked =
        ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[[1_u8; 32], [3_u8; 32]])
            .map_err(|_| TestError)?;
    let snapshot = signed_root(without_revoked.root())?;
    assert_eq!(
        without_revoked
            .open_against(snapshot, NOW, &[2_u8; 32])
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveSetReason::NotActive)
    );
    let empty = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.root(), leaf(&[0_u8; 32]));
    let empty_snapshot = signed_root(empty.root())?;
    assert_eq!(
        empty
            .open_against(empty_snapshot, NOW, &[1_u8; 32])
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveSetReason::NotActive)
    );
    Ok(())
}
