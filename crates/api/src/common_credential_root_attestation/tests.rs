// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

use thiserror::Error;
use zeroize::Zeroizing;

use super::{ZkRootAssuranceAttestation, ZkRootAssuranceAttestationReason};
use crate::{
    common_root::{
        common_credential_root_attestation_signing_digest, common_credential_root_root_commitment,
        derive_common_credential_root_attestation_id_from_commitment,
        normalize_common_credential_root_p256_signature_low_s, verify_root_status_snapshot,
        ZkCommonCredentialRootActiveSet, ZkCommonCredentialRootAttestationTrustPolicy,
        ZkRootStatusSnapshot, ZkRootStatusTrustPolicy,
    },
    keys::ZkAttestationPublicKey,
};

const NOW: u64 = 1_800_000_000;
const ROOT: [u8; 32] = [0x34; 32];
const POLICY: [u8; 32] = [0x55; 32];
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Debug, Error)]
#[error("root-assurance test fixture failed")]
struct TestError;

fn signed_attestation() -> Result<(ZkRootAssuranceAttestation, ZkAttestationPublicKey), TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
    let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
    let signer = ZkAttestationPublicKey {
        x: point[1..33].try_into().map_err(|_| TestError)?,
        y: point[33..65].try_into().map_err(|_| TestError)?,
    };
    let commitment = common_credential_root_root_commitment(&ROOT).map_err(|_| TestError)?;
    let digest = common_credential_root_attestation_signing_digest(
        &commitment,
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
    )
    .map_err(|_| TestError)?;
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
        .map_err(|_| TestError)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| TestError)?;
    let attestation = ZkRootAssuranceAttestation::try_from_authority_signed_parts(
        *commitment,
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
        signer,
        signature,
    )
    .map_err(|_| TestError)?;
    Ok((attestation, signer))
}

fn signed_status_root(
    root: [u8; 32],
) -> Result<crate::common_root::ZkVerifiedRootStatusSnapshot, TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 73;
    let (compressed, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
    let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
    let signer = ZkAttestationPublicKey {
        x: point[1..33].try_into().map_err(|_| TestError)?,
        y: point[33..65].try_into().map_err(|_| TestError)?,
    };
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(root, NOW - 1, NOW + 60, 11);
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
        .map_err(|_| TestError)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| TestError)?;
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        root,
        NOW - 1,
        NOW + 60,
        11,
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
            minimum_sequence: 11,
            maximum_age_seconds: 120,
        },
        NOW,
    )
    .map_err(|_| TestError)
}

fn high_s_twin(signature: [u8; 64]) -> Result<[u8; 64], TestError> {
    let canonical =
        normalize_common_credential_root_p256_signature_low_s(signature).map_err(|_| TestError)?;
    let mut high_s = canonical;
    let mut borrow = 0_u16;
    for index in (0..32).rev() {
        let minuend = u16::from(P256_ORDER[index]);
        let subtrahend = u16::from(canonical[32 + index])
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
        high_s[32 + index] = u8::try_from(value).map_err(|_| TestError)?;
        borrow = next_borrow;
    }
    if borrow != 0 {
        return Err(TestError);
    }
    Ok(high_s)
}

#[test]
fn signed_record_opens_only_for_the_exact_root_and_pinned_policy() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    let policy = ZkCommonCredentialRootAttestationTrustPolicy {
        signer,
        assurance_policy_id: POLICY,
    };
    assert!(attestation.verify_for_root(&ROOT, policy, NOW).is_ok());
    assert_eq!(
        attestation
            .verify_for_root(&[0x35; 32], policy, NOW)
            .err()
            .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::RootMismatch)
    );
    assert_eq!(
        attestation
            .verify_for_root(
                &ROOT,
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer,
                    assurance_policy_id: [0x56; 32],
                },
                NOW,
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::TrustRejected)
    );
    assert!(attestation
        .verify_for_root(&ROOT, policy, NOW + 60)
        .is_err());
    Ok(())
}

#[test]
fn authority_publication_id_matches_holder_id_and_active_set_without_root() -> Result<(), TestError>
{
    let (attestation, signer) = signed_attestation()?;
    let policy = ZkCommonCredentialRootAttestationTrustPolicy {
        signer,
        assurance_policy_id: POLICY,
    };
    let holder_id = attestation
        .verify_for_root(&ROOT, policy, NOW)
        .map_err(|_| TestError)?;
    let authority_id = attestation
        .attestation_id_for_status_publication(policy, NOW)
        .map_err(|_| TestError)?;
    assert_eq!(holder_id.as_ref(), authority_id.as_ref());
    assert_eq!(
        derive_common_credential_root_attestation_id_from_commitment(
            attestation.commitment_material()
        )
        .map_err(|_| TestError)?,
        *authority_id,
    );

    let active_set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[*authority_id])
        .map_err(|_| TestError)?;
    let snapshot = signed_status_root(active_set.root())?;
    let opening = active_set
        .open_against(snapshot, NOW, &holder_id)
        .map_err(|_| TestError)?;
    assert_eq!(opening.index(), 0);
    assert!(opening.siblings().is_empty());
    Ok(())
}

#[test]
fn decoded_attestation_rejects_high_s_artifact_signature() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    let high_s_signature = high_s_twin(*attestation.signature())?;
    assert_eq!(
        ZkRootAssuranceAttestation::try_from_signed_parts(
            *attestation.root_commitment(),
            POLICY,
            NOW - 60,
            NOW + 60,
            7,
            signer,
            high_s_signature,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::InvalidField)
    );
    Ok(())
}

#[test]
fn authority_constructor_canonicalizes_high_s_signer_output_before_id() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    let high_s_signature = high_s_twin(*attestation.signature())?;
    let high_s_record = ZkRootAssuranceAttestation::try_from_authority_signed_parts(
        *attestation.root_commitment(),
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
        signer,
        high_s_signature,
    )
    .map_err(|_| TestError)?;

    assert_eq!(high_s_record.signature(), attestation.signature());
    assert_ne!(high_s_record.signature(), &high_s_signature);
    assert_eq!(
        high_s_record
            .attestation_id_for_status_publication(
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer,
                    assurance_policy_id: POLICY,
                },
                NOW
            )
            .map_err(|_| TestError)?
            .as_ref(),
        attestation
            .attestation_id_for_status_publication(
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer,
                    assurance_policy_id: POLICY,
                },
                NOW
            )
            .map_err(|_| TestError)?
            .as_ref(),
    );
    Ok(())
}

#[test]
fn authority_publication_requires_pinned_signer_and_policy() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    assert_eq!(
        attestation
            .attestation_id_for_status_publication(
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer: ZkAttestationPublicKey {
                        x: [0x21; 32],
                        y: [0x22; 32],
                    },
                    assurance_policy_id: POLICY,
                },
                NOW
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::TrustRejected)
    );
    assert_eq!(
        attestation
            .attestation_id_for_status_publication(
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer,
                    assurance_policy_id: [0x56; 32],
                },
                NOW
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::TrustRejected)
    );
    Ok(())
}

#[test]
fn authority_publication_requires_attestation_valid_at_publication_time() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    let policy = ZkCommonCredentialRootAttestationTrustPolicy {
        signer,
        assurance_policy_id: POLICY,
    };
    for publication_time_unix in [NOW - 61, NOW + 60] {
        assert_eq!(
            attestation
                .attestation_id_for_status_publication(policy, publication_time_unix)
                .err()
                .map(|error| error.reason()),
            Some(ZkRootAssuranceAttestationReason::TrustRejected)
        );
    }
    assert!(attestation
        .attestation_id_for_status_publication(policy, NOW)
        .is_ok());
    Ok(())
}

#[test]
fn authority_publication_rejects_wrong_commitment_signature_pair() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    let wrong_commitment =
        common_credential_root_root_commitment(&[0x35; 32]).map_err(|_| TestError)?;
    let changed = ZkRootAssuranceAttestation::try_from_signed_parts(
        *wrong_commitment,
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
        signer,
        *attestation.signature(),
    )
    .map_err(|_| TestError)?;

    assert_eq!(
        changed
            .attestation_id_for_status_publication(
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer,
                    assurance_policy_id: POLICY,
                },
                NOW
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::TrustRejected)
    );
    assert_eq!(
        changed
            .verify_for_root(
                &ROOT,
                ZkCommonCredentialRootAttestationTrustPolicy {
                    signer,
                    assurance_policy_id: POLICY,
                },
                NOW,
            )
            .err()
            .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::RootMismatch)
    );
    Ok(())
}

#[test]
fn signed_record_rejects_invalid_shape_and_wrong_signature() -> Result<(), TestError> {
    let (attestation, signer) = signed_attestation()?;
    assert_eq!(
        ZkRootAssuranceAttestation::try_from_signed_parts(
            [0_u8; 32],
            POLICY,
            NOW - 60,
            NOW + 60,
            7,
            signer,
            *attestation.signature(),
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkRootAssuranceAttestationReason::InvalidField)
    );
    let mut changed_signature = *attestation.signature();
    changed_signature[0] ^= 1;
    let changed = ZkRootAssuranceAttestation::try_from_signed_parts(
        *attestation.root_commitment(),
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
        signer,
        changed_signature,
    )
    .map_err(|_| TestError)?;
    assert!(changed
        .verify_for_root(
            &ROOT,
            ZkCommonCredentialRootAttestationTrustPolicy {
                signer,
                assurance_policy_id: POLICY,
            },
            NOW,
        )
        .is_err());
    Ok(())
}
