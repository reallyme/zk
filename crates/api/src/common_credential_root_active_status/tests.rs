// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

use crypto_sha2_256::digest as sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    verify_common_credential_root_active_status_membership,
    ZkCommonCredentialRootActiveStatusReason, COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH,
    COMMON_CREDENTIAL_ROOT_V1_STATUS_LEAVES,
};
use crate::{
    common_root::{
        verify_root_status_snapshot, ZkRootStatusSnapshot, ZkRootStatusSnapshotError,
        ZkRootStatusTrustPolicy, ZkVerifiedRootStatusSnapshot,
    },
    keys::ZkIssuerPublicKey,
};

const NOW: u64 = 1_800_000_000;
const ATTESTATION_ID: [u8; 32] = [0x34; 32];

#[derive(Debug, Error)]
enum TestError {
    #[error("test signer failed")]
    Crypto(#[from] crypto_core::CryptoError),
    #[error("test snapshot failed")]
    Snapshot(#[from] ZkRootStatusSnapshotError),
    #[error("test key shape invalid")]
    PublicKeyShape,
    #[error("test verification failed")]
    Verification,
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

fn signed_root(root: [u8; 32]) -> Result<ZkVerifiedRootStatusSnapshot, TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _owned_secret) = crypto_p256::generate_p256_keypair_from_secret_key(&secret)?;
    let public = crypto_p256::decompress_public_key(&compressed)?;
    let public = <[u8; 65]>::try_from(public.as_slice()).map_err(|_| TestError::PublicKeyShape)?;
    let signer = ZkIssuerPublicKey {
        x: public[1..33]
            .try_into()
            .map_err(|_| TestError::PublicKeyShape)?,
        y: public[33..65]
            .try_into()
            .map_err(|_| TestError::PublicKeyShape)?,
    };
    let issued = NOW - 1;
    let expires = NOW + 60;
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(root, issued, expires, 7);
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der)?;
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        root,
        issued,
        expires,
        7,
        crate::keys::ZkStatusAuthorityPublicKey::from(crate::keys::ZkP256PublicKey::from(signer)),
        signature,
    )?;
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
    .map_err(|_| TestError::Verification)
}

#[test]
fn active_path_matches_signed_root_and_rejects_substitution() -> Result<(), TestError> {
    let sibling_id = [0x56; 32];
    let sibling = leaf(&sibling_id);
    let root = node(&sibling, &leaf(&ATTESTATION_ID));
    let snapshot = signed_root(root)?;
    assert!(verify_common_credential_root_active_status_membership(
        snapshot,
        NOW,
        &ATTESTATION_ID,
        1,
        &[sibling],
    )
    .is_ok());

    let mut wrong_id = ATTESTATION_ID;
    wrong_id[0] ^= 1;
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            &wrong_id,
            1,
            &[sibling]
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::RootMismatch)
    );
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            &ATTESTATION_ID,
            0,
            &[sibling]
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::RootMismatch)
    );
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            &ATTESTATION_ID,
            2,
            &[sibling]
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::InvalidOpening)
    );
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            &ATTESTATION_ID,
            COMMON_CREDENTIAL_ROOT_V1_STATUS_LEAVES,
            &[sibling],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::InvalidOpening)
    );
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            &ATTESTATION_ID,
            0,
            &vec![[0_u8; 32]; COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH + 1],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::InvalidOpening)
    );
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW,
            &[0_u8; 32],
            1,
            &[sibling]
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::InvalidOpening)
    );
    assert_eq!(
        verify_common_credential_root_active_status_membership(
            snapshot,
            NOW + 60,
            &ATTESTATION_ID,
            1,
            &[sibling],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootActiveStatusReason::StaleSnapshot)
    );
    Ok(())
}

#[test]
fn active_path_matches_the_noir_root_status_fixture() -> Result<(), TestError> {
    // From the SHA-256 root_status Prover.toml, independently generated by
    // the circuit fixture builder. This checks the exact leaf transcript.
    let attestation_id = [
        218, 223, 197, 151, 64, 97, 145, 132, 138, 115, 129, 60, 38, 136, 28, 201, 16, 162, 177,
        248, 159, 23, 23, 179, 72, 153, 66, 25, 158, 53, 149, 81,
    ];
    let status_root = [
        178, 7, 157, 208, 174, 153, 222, 190, 153, 162, 54, 113, 43, 85, 5, 3, 175, 205, 96, 234,
        184, 124, 124, 222, 195, 100, 220, 97, 82, 224, 47, 235,
    ];
    let snapshot = signed_root(status_root)?;
    assert!(verify_common_credential_root_active_status_membership(
        snapshot,
        NOW,
        &attestation_id,
        0,
        &[],
    )
    .is_ok());
    Ok(())
}
