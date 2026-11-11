// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

use super::{verify_root_status_snapshot, ZkRootStatusTrustPolicy, ZkRootStatusVerificationReason};
use crate::{
    common_root::{
        normalize_common_credential_root_p256_signature_low_s, ZkRootStatusSnapshot,
        ZkRootStatusSnapshotError, ZkRootStatusSnapshotReason,
    },
    errors::ZkError,
    keys::ZkStatusAuthorityPublicKey,
};
use thiserror::Error;
use zeroize::Zeroizing;

const NOW_UNIX: u64 = 1_700_000_100;
const SEQUENCE: u64 = 7;

#[derive(Debug, Error)]
enum TestError {
    #[error("test signing failed")]
    Crypto(#[from] crypto_core::CryptoError),
    #[error("test snapshot construction failed")]
    Snapshot(#[from] ZkRootStatusSnapshotError),
    #[error("test signature normalization failed")]
    Signature(#[from] ZkError),
    #[error("test high-S twin failed")]
    SignatureMath,
    #[error("test public key length invalid")]
    PublicKeyLength,
}

const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn signed_snapshot(
    status_root: [u8; 32],
    issued_unix: u64,
    expires_unix: u64,
    sequence: u64,
) -> Result<(ZkRootStatusSnapshot, ZkStatusAuthorityPublicKey), TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _owned_secret) = crypto_p256::generate_p256_keypair_from_secret_key(&secret)?;
    let uncompressed = crypto_p256::decompress_public_key(&compressed)?;
    let point =
        <[u8; 65]>::try_from(uncompressed.as_slice()).map_err(|_| TestError::PublicKeyLength)?;
    let mut x = [0_u8; 32];
    let mut y = [0_u8; 32];
    x.copy_from_slice(&point[1..33]);
    y.copy_from_slice(&point[33..65]);
    let signer = ZkStatusAuthorityPublicKey { x, y };
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
    );
    let typed_digest = crypto_p256::P256Sha256Digest::new(digest);
    let signature_der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_ref(), &typed_digest)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&signature_der)?;
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
        signer,
        signature,
    )?;
    Ok((snapshot, signer))
}

fn high_s_twin(mut signature: [u8; 64]) -> Result<[u8; 64], TestError> {
    let low_s = normalize_common_credential_root_p256_signature_low_s(signature)?;
    signature = low_s;
    let mut borrow = 0_u16;
    for index in (32..64).rev() {
        let minuend = u16::from(P256_ORDER[index - 32]);
        let subtrahend = u16::from(signature[index])
            .checked_add(borrow)
            .ok_or(TestError::SignatureMath)?;
        let (value, next_borrow) = if minuend >= subtrahend {
            (
                minuend
                    .checked_sub(subtrahend)
                    .ok_or(TestError::SignatureMath)?,
                0_u16,
            )
        } else {
            (
                minuend
                    .checked_add(256)
                    .and_then(|value| value.checked_sub(subtrahend))
                    .ok_or(TestError::SignatureMath)?,
                1_u16,
            )
        };
        signature[index] = u8::try_from(value).map_err(|_| TestError::SignatureMath)?;
        borrow = next_borrow;
    }
    if borrow != 0 {
        return Err(TestError::SignatureMath);
    }
    Ok(signature)
}

#[test]
fn signed_status_requires_exact_authority_digest_sequence_and_time() -> Result<(), TestError> {
    let (snapshot, signer) = signed_snapshot([0x42; 32], NOW_UNIX - 2, NOW_UNIX + 60, SEQUENCE)?;
    let trust = ZkRootStatusTrustPolicy {
        authority: signer,
        minimum_sequence: SEQUENCE,
        maximum_age_seconds: 30,
    };
    let verified = verify_root_status_snapshot(snapshot, trust, NOW_UNIX);
    assert_eq!(verified.as_ref().map(|value| value.root()), Ok([0x42; 32]));
    assert_eq!(
        verified.as_ref().map(|value| value.sequence()),
        Ok(SEQUENCE)
    );
    assert_eq!(
        verified.as_ref().map(|value| value.signing_digest()),
        Ok(snapshot.signing_digest())
    );
    if let Ok(verified) = verified {
        assert_eq!(
            verified
                .validate_at(NOW_UNIX + 60)
                .map_err(|error| error.reason()),
            Err(ZkRootStatusVerificationReason::Stale)
        );
    }

    let wrong_authority = ZkRootStatusTrustPolicy {
        authority: ZkStatusAuthorityPublicKey {
            x: [1; 32],
            y: [2; 32],
        },
        ..trust
    };
    assert_eq!(
        verify_root_status_snapshot(snapshot, wrong_authority, NOW_UNIX)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootStatusVerificationReason::AuthorityPolicy)
    );
    let rollback_policy = ZkRootStatusTrustPolicy {
        minimum_sequence: SEQUENCE + 1,
        ..trust
    };
    assert_eq!(
        verify_root_status_snapshot(snapshot, rollback_policy, NOW_UNIX)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootStatusVerificationReason::SequenceRollback)
    );
    let altered = ZkRootStatusSnapshot::try_from_parts(
        [0x43; 32],
        snapshot.issued_unix(),
        snapshot.expires_unix(),
        snapshot.sequence(),
        signer,
        *snapshot.signature(),
    )?;
    assert_eq!(
        verify_root_status_snapshot(altered, trust, NOW_UNIX)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootStatusVerificationReason::SignatureInvalid)
    );
    for time in [NOW_UNIX - 3, NOW_UNIX + 60] {
        assert_eq!(
            verify_root_status_snapshot(snapshot, trust, time)
                .err()
                .map(|error| error.reason()),
            Some(ZkRootStatusVerificationReason::Stale)
        );
    }
    Ok(())
}

#[test]
fn authority_snapshot_constructor_normalizes_high_s_signer_output() -> Result<(), TestError> {
    let status_root = [0x42; 32];
    let issued_unix = NOW_UNIX - 2;
    let expires_unix = NOW_UNIX + 60;
    let sequence = SEQUENCE;
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _owned_secret) = crypto_p256::generate_p256_keypair_from_secret_key(&secret)?;
    let uncompressed = crypto_p256::decompress_public_key(&compressed)?;
    let point =
        <[u8; 65]>::try_from(uncompressed.as_slice()).map_err(|_| TestError::PublicKeyLength)?;
    let signer = ZkStatusAuthorityPublicKey {
        x: point[1..33]
            .try_into()
            .map_err(|_| TestError::PublicKeyLength)?,
        y: point[33..65]
            .try_into()
            .map_err(|_| TestError::PublicKeyLength)?,
    };
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
    );
    let typed_digest = crypto_p256::P256Sha256Digest::new(digest);
    let signature_der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_ref(), &typed_digest)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&signature_der)?;
    let low_s = normalize_common_credential_root_p256_signature_low_s(signature)?;
    let high_s = high_s_twin(signature)?;

    assert_eq!(
        ZkRootStatusSnapshot::try_from_parts(
            status_root,
            issued_unix,
            expires_unix,
            sequence,
            signer,
            high_s,
        )
        .err()
        .map(ZkRootStatusSnapshotError::reason),
        Some(ZkRootStatusSnapshotReason::InvalidField)
    );

    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
        signer,
        high_s,
    )?;
    assert_eq!(snapshot.signature(), &low_s);
    assert_eq!(snapshot.signing_digest(), digest);
    assert!(verify_root_status_snapshot(
        snapshot,
        ZkRootStatusTrustPolicy {
            authority: signer,
            minimum_sequence: sequence,
            maximum_age_seconds: 30,
        },
        NOW_UNIX,
    )
    .is_ok());
    Ok(())
}
