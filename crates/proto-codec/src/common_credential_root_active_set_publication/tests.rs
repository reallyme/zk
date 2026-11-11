// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(feature = "native", feature = "wasm"))]

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    common_root::{
        common_credential_root_attestation_signing_digest, common_credential_root_root_commitment,
        ZkCommonCredentialRootActiveSet, ZkCommonCredentialRootAttestationTrustPolicy,
        ZkRootAssuranceAttestation, ZkRootStatusSnapshot, ZkRootStatusTrustPolicy,
        ZkRootStatusVerificationReason,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    admit_root_active_set_publication, build_root_active_set_from_authority,
    encode_root_active_set_publication, encode_root_active_set_publication_from_authority,
    ZkRootActiveSetAuthorityInput, ZkRootActiveSetAuthorityPublication,
    ZkRootActiveSetPublicationReason,
};

#[path = "staged_tests.rs"]
mod staged_tests;

const NOW: u64 = 1_800_000_000;
const SNAPSHOT_SEQUENCE: u64 = 7;
const MAXIMUM_AGE_SECONDS: u64 = 120;

fn status_trust(signer: ZkIssuerPublicKey, minimum_sequence: u64) -> ZkRootStatusTrustPolicy {
    ZkRootStatusTrustPolicy {
        authority: reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
        ),
        minimum_sequence,
        maximum_age_seconds: MAXIMUM_AGE_SECONDS,
    }
}

#[derive(Debug, Error)]
#[error("active-set publication test fixture failed")]
struct TestError;

fn signer(seed: u8) -> Result<(Zeroizing<[u8; 32]>, ZkIssuerPublicKey), TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = seed;
    let (compressed, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
    let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
    let public = ZkIssuerPublicKey {
        x: point[1..33].try_into().map_err(|_| TestError)?,
        y: point[33..65].try_into().map_err(|_| TestError)?,
    };
    Ok((secret, public))
}

fn signed_snapshot(root: [u8; 32]) -> Result<(ZkRootStatusSnapshot, ZkIssuerPublicKey), TestError> {
    let (secret, signer) = signer(37)?;
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
        reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
        ),
        signature,
    )
    .map_err(|_| TestError)?;
    Ok((snapshot, signer))
}

fn signed_attestation(
    root: &[u8; 32],
    secret: &[u8; 32],
    public: ZkIssuerPublicKey,
) -> Result<ZkRootAssuranceAttestation, TestError> {
    signed_attestation_with_interval(root, secret, public, NOW - 60, NOW + 60)
}

fn signed_attestation_with_interval(
    root: &[u8; 32],
    secret: &[u8; 32],
    public: ZkIssuerPublicKey,
    issued_unix: u64,
    expires_unix: u64,
) -> Result<ZkRootAssuranceAttestation, TestError> {
    let commitment = common_credential_root_root_commitment(root).map_err(|_| TestError)?;
    let digest = common_credential_root_attestation_signing_digest(
        &commitment,
        [0x55; 32],
        issued_unix,
        expires_unix,
        7,
    )
    .map_err(|_| TestError)?;
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret, &digest).map_err(|_| TestError)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| TestError)?;
    ZkRootAssuranceAttestation::try_from_authority_signed_parts(
        *commitment,
        [0x55; 32],
        issued_unix,
        expires_unix,
        7,
        reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(public),
        ),
        signature,
    )
    .map_err(|_| TestError)
}

#[test]
fn signed_bulk_publication_supports_local_opening_and_rejects_rollback() -> Result<(), TestError> {
    let ids = [[1_u8; 32], [2_u8; 32], [3_u8; 32]];
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&ids).map_err(|_| TestError)?;
    let (snapshot, signer) = signed_snapshot(set.root())?;
    let encoded = encode_root_active_set_publication(&set, &snapshot).map_err(|_| TestError)?;
    let decoded = admit_root_active_set_publication(&encoded)
        .map_err(|_| TestError)?
        .authenticate(status_trust(signer, SNAPSHOT_SEQUENCE), NOW)
        .map_err(|_| TestError)?;
    let trusted = decoded.verified_snapshot();
    let opening = decoded
        .active_set()
        .open_against(trusted, NOW, &ids[1])
        .map_err(|_| TestError)?;
    assert_eq!(opening.index(), 1);
    assert_eq!(opening.siblings().len(), 2);
    assert_eq!(
        admit_root_active_set_publication(&encoded)
            .map_err(|_| TestError)?
            .authenticate(status_trust(signer, SNAPSHOT_SEQUENCE + 1), NOW)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::Unauthenticated(
            ZkRootStatusVerificationReason::SequenceRollback
        ))
    );
    assert!(decoded
        .active_set()
        .open_against(trusted, NOW, &[4_u8; 32])
        .is_err());
    Ok(())
}

#[test]
fn authority_publication_rejects_attestations_inactive_at_snapshot_time() -> Result<(), TestError> {
    let (attestation_secret, attestation_signer) = signer(91)?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(attestation_signer),
        ),
        assurance_policy_id: [0x55; 32],
    };
    let expired = signed_attestation_with_interval(
        &[0x10; 32],
        &attestation_secret,
        attestation_signer,
        NOW - 120,
        NOW - 1,
    )?;
    let not_yet_valid = signed_attestation_with_interval(
        &[0x20; 32],
        &attestation_secret,
        attestation_signer,
        NOW + 1,
        NOW + 60,
    )?;
    let empty = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    let (snapshot, _) = signed_snapshot(empty.root())?;
    for attestation in [&expired, &not_yet_valid] {
        assert_eq!(
            encode_root_active_set_publication_from_authority(
                ZkRootActiveSetAuthorityPublication {
                    active_attestations: &[attestation],
                    revoked_attestation_ids: &[],
                    attestation_trust: trust,
                    snapshot: &snapshot,
                },
            )
            .err()
            .map(|error| error.reason()),
            Some(ZkRootActiveSetPublicationReason::InvalidAuthorityInput)
        );
    }
    Ok(())
}

#[test]
fn canonical_publication_rejects_malformed_and_mismatched_content() -> Result<(), TestError> {
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[[1_u8; 32], [2_u8; 32]])
        .map_err(|_| TestError)?;
    let (snapshot, signer) = signed_snapshot(set.root())?;
    let encoded = encode_root_active_set_publication(&set, &snapshot).map_err(|_| TestError)?;
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootActiveSetPublication>(&encoded)
        .map_err(|_| TestError)?;
    wire.sorted_attestation_ids[0] = 3;
    assert_eq!(
        admit_root_active_set_publication(&wire.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );
    wire.sorted_attestation_ids[0] = 1;
    wire.sorted_attestation_ids[32] = 4;
    // The signature does not cover the list, so a well-formed substituted
    // list is only caught by the root comparison that follows authentication.
    assert_eq!(
        admit_root_active_set_publication(&wire.encode_to_vec())
            .map_err(|_| TestError)?
            .authenticate(status_trust(signer, SNAPSHOT_SEQUENCE), NOW)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::RootMismatch)
    );
    wire.sorted_attestation_ids.pop();
    assert_eq!(
        admit_root_active_set_publication(&wire.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::InvalidEncoding)
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert!(admit_root_active_set_publication(&trailing).is_err());
    Ok(())
}

#[test]
fn decoding_never_turns_an_invalid_signature_into_trusted_status() -> Result<(), TestError> {
    let empty = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    let (snapshot, signer) = signed_snapshot(empty.root())?;
    let encoded = encode_root_active_set_publication(&empty, &snapshot).map_err(|_| TestError)?;
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootActiveSetPublication>(&encoded)
        .map_err(|_| TestError)?;
    let inner = wire.snapshot.as_option_mut().ok_or(TestError)?;
    inner.signature[0] ^= 1;
    let admitted =
        admit_root_active_set_publication(&wire.encode_to_vec()).map_err(|_| TestError)?;
    assert_eq!(admitted.identifier_count(), 0);
    assert_eq!(
        admitted
            .authenticate(status_trust(signer, SNAPSHOT_SEQUENCE), NOW)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::Unauthenticated(
            ZkRootStatusVerificationReason::SignatureInvalid
        ))
    );
    Ok(())
}

#[test]
fn authority_publication_derives_ids_without_roots_and_removes_revoked_ids() -> Result<(), TestError>
{
    let (attestation_secret, attestation_signer) = signer(91)?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(attestation_signer),
        ),
        assurance_policy_id: [0x55; 32],
    };
    let first = signed_attestation(&[0x10; 32], &attestation_secret, attestation_signer)?;
    let second = signed_attestation(&[0x20; 32], &attestation_secret, attestation_signer)?;
    let first_id = first
        .attestation_id_for_status_publication(trust, NOW)
        .map_err(|_| TestError)?;
    let second_id = second
        .attestation_id_for_status_publication(trust, NOW)
        .map_err(|_| TestError)?;
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[*first_id])
        .map_err(|_| TestError)?;
    let (snapshot, status_signer) = signed_snapshot(set.root())?;
    let prepared = build_root_active_set_from_authority(ZkRootActiveSetAuthorityInput {
        active_attestations: &[&first, &second],
        revoked_attestation_ids: &[*second_id],
        attestation_trust: trust,
        issued_unix: snapshot.issued_unix(),
    })
    .map_err(|_| TestError)?;
    assert_eq!(prepared.root(), snapshot.status_root());
    assert_eq!(prepared.sorted_ids(), &[*first_id]);

    let encoded =
        encode_root_active_set_publication_from_authority(ZkRootActiveSetAuthorityPublication {
            active_attestations: &[&first, &second],
            revoked_attestation_ids: &[*second_id],
            attestation_trust: trust,
            snapshot: &snapshot,
        })
        .map_err(|_| TestError)?;
    let decoded = admit_root_active_set_publication(&encoded)
        .map_err(|_| TestError)?
        .authenticate(status_trust(status_signer, SNAPSHOT_SEQUENCE), NOW)
        .map_err(|_| TestError)?;
    let verified = decoded.verified_snapshot();

    assert_eq!(decoded.active_set().len(), 1);
    assert!(decoded
        .active_set()
        .open_against(verified, NOW, &first_id)
        .is_ok());
    assert!(decoded
        .active_set()
        .open_against(verified, NOW, &second_id)
        .is_err());
    assert_eq!(
        encode_root_active_set_publication_from_authority(ZkRootActiveSetAuthorityPublication {
            active_attestations: &[&first, &second],
            revoked_attestation_ids: &[],
            attestation_trust: trust,
            snapshot: &snapshot,
        })
        .err()
        .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::RootMismatch)
    );
    Ok(())
}

#[test]
fn authority_publication_rejects_duplicate_or_wrong_policy_attestations() -> Result<(), TestError> {
    let (attestation_secret, attestation_signer) = signer(91)?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(attestation_signer),
        ),
        assurance_policy_id: [0x55; 32],
    };
    let first = signed_attestation(&[0x10; 32], &attestation_secret, attestation_signer)?;
    let first_duplicate = signed_attestation(&[0x10; 32], &attestation_secret, attestation_signer)?;
    let first_id = first
        .attestation_id_for_status_publication(trust, NOW)
        .map_err(|_| TestError)?;
    let set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[*first_id])
        .map_err(|_| TestError)?;
    let (snapshot, _) = signed_snapshot(set.root())?;
    assert_eq!(
        encode_root_active_set_publication_from_authority(ZkRootActiveSetAuthorityPublication {
            active_attestations: &[&first, &first_duplicate],
            revoked_attestation_ids: &[],
            attestation_trust: trust,
            snapshot: &snapshot,
        })
        .err()
        .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::InvalidAuthorityInput)
    );
    let empty = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[]).map_err(|_| TestError)?;
    let (empty_snapshot, _) = signed_snapshot(empty.root())?;
    assert_eq!(
        encode_root_active_set_publication_from_authority(ZkRootActiveSetAuthorityPublication {
            active_attestations: &[&first, &first_duplicate],
            revoked_attestation_ids: &[*first_id],
            attestation_trust: trust,
            snapshot: &empty_snapshot,
        })
        .err()
        .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::InvalidAuthorityInput)
    );
    let wrong_policy_attestation =
        signed_attestation(&[0x10; 32], &attestation_secret, attestation_signer)?;
    assert_eq!(
        encode_root_active_set_publication_from_authority(ZkRootActiveSetAuthorityPublication {
            active_attestations: &[&wrong_policy_attestation],
            revoked_attestation_ids: &[],
            attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy {
                signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
                    reallyme_zk_api::keys::ZkP256PublicKey::from(attestation_signer)
                ),
                assurance_policy_id: [0x56; 32],
            },
            snapshot: &snapshot,
        })
        .err()
        .map(|error| error.reason()),
        Some(ZkRootActiveSetPublicationReason::InvalidAuthorityInput)
    );
    Ok(())
}
