// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_sha2_256::digest as sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{ZkCommonCredentialRootHolderAssurance, ZkCommonCredentialRootHolderAssuranceReason};
use crate::{
    common_root::{
        common_credential_root_attestation_signing_digest, common_credential_root_root_commitment,
        derive_common_credential_root_attestation_id, verify_root_status_snapshot,
        ZkCommonCredentialRootAttestationMaterial, ZkCommonCredentialRootAttestationTrustPolicy,
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
#[error("holder-assurance test fixture failed")]
struct TestError;

fn material<'a>(
    signer: ZkAttestationPublicKey,
    root: &'a [u8; 32],
    signature: &'a [u8; 64],
) -> ZkCommonCredentialRootAttestationMaterial<'a> {
    ZkCommonCredentialRootAttestationMaterial {
        reallyme_public_key: signer,
        assurance_policy_id: POLICY,
        request_time_unix: NOW,
        root,
        attestation_issued_unix: NOW - 60,
        attestation_expires_unix: NOW + 60,
        attestation_epoch: 7,
        attestation_signature: signature,
    }
}

fn signed_fixture() -> Result<
    (
        [u8; 64],
        ZkAttestationPublicKey,
        crate::common_root::ZkVerifiedRootStatusSnapshot,
    ),
    TestError,
> {
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
    let id = derive_common_credential_root_attestation_id(material(signer, &ROOT, &signature))
        .map_err(|_| TestError)?;
    let mut leaf = [0_u8; 38];
    leaf[..6].copy_from_slice(b"RMSTL2");
    leaf[6..].copy_from_slice(&id);
    let status_root = sha256(&leaf).into_bytes();
    let status_digest =
        ZkRootStatusSnapshot::signing_digest_for_fields(status_root, NOW - 1, NOW + 60, 7);
    let status_digest = crypto_p256::P256Sha256Digest::new(status_digest);
    let status_der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &status_digest)
            .map_err(|_| TestError)?;
    let status_signature =
        crypto_p256::p256_ecdsa_der_to_jose_signature(&status_der).map_err(|_| TestError)?;
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        status_root,
        NOW - 1,
        NOW + 60,
        7,
        crate::keys::ZkStatusAuthorityPublicKey::from(crate::keys::ZkP256PublicKey::from(signer)),
        status_signature,
    )
    .map_err(|_| TestError)?;
    let verified = verify_root_status_snapshot(
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
    .map_err(|_| TestError)?;
    Ok((signature, signer, verified))
}

fn high_s_twin(mut signature: [u8; 64]) -> Result<[u8; 64], TestError> {
    let mut borrow = 0_u16;
    for index in (32..64).rev() {
        let minuend = u16::from(P256_ORDER[index - 32]);
        let subtrahend = u16::from(signature[index]) + borrow;
        if minuend >= subtrahend {
            signature[index] = u8::try_from(minuend - subtrahend).map_err(|_| TestError)?;
            borrow = 0;
        } else {
            signature[index] = u8::try_from(256 + minuend - subtrahend).map_err(|_| TestError)?;
            borrow = 1;
        }
    }
    Ok(signature)
}

#[test]
fn admits_only_matching_signed_attestation_and_current_active_path() -> Result<(), TestError> {
    let (signature, signer, snapshot) = signed_fixture()?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer,
        assurance_policy_id: POLICY,
    };
    let admitted = ZkCommonCredentialRootHolderAssurance::admit(
        material(signer, &ROOT, &signature),
        trust,
        snapshot,
        NOW,
        0,
        &[],
    )
    .map_err(|_| TestError)?;
    assert_eq!(admitted.root(), &ROOT);
    assert_eq!(admitted.signature(), &signature);
    assert_eq!(admitted.status_index(), 0);
    assert!(admitted.siblings().is_empty());
    assert_eq!(admitted.epoch(), 7);
    assert_eq!(admitted.signer(), signer);
    assert_eq!(admitted.assurance_policy_id(), POLICY);
    assert!(admitted.validate_at(NOW).is_ok());
    assert!(admitted.require_lineage_roots(&ROOT, &ROOT).is_ok());
    assert_eq!(
        admitted
            .require_lineage_roots(&ROOT, &[0x35; 32])
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootHolderAssuranceReason::LineageRootMismatch)
    );
    assert_eq!(
        admitted
            .validate_at(NOW + 60)
            .err()
            .map(|error| error.reason()),
        Some(ZkCommonCredentialRootHolderAssuranceReason::Stale)
    );

    let wrong_root = [0x35; 32];
    assert_eq!(
        ZkCommonCredentialRootHolderAssurance::admit(
            material(signer, &wrong_root, &signature),
            trust,
            snapshot,
            NOW,
            0,
            &[],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootHolderAssuranceReason::InvalidAttestation)
    );
    assert_eq!(
        ZkCommonCredentialRootHolderAssurance::admit(
            material(signer, &ROOT, &signature),
            trust,
            snapshot,
            NOW,
            1,
            &[],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootHolderAssuranceReason::InvalidStatusOpening)
    );
    let mut altered_signature = signature;
    altered_signature[0] ^= 1;
    assert_eq!(
        ZkCommonCredentialRootHolderAssurance::admit(
            material(signer, &ROOT, &altered_signature),
            trust,
            snapshot,
            NOW,
            0,
            &[],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootHolderAssuranceReason::InvalidAttestation)
    );
    assert_eq!(
        ZkCommonCredentialRootHolderAssurance::admit(
            material(signer, &ROOT, &signature),
            trust,
            snapshot,
            NOW + 60,
            0,
            &[],
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkCommonCredentialRootHolderAssuranceReason::InvalidStatusOpening)
    );
    Ok(())
}

#[test]
fn admission_canonicalizes_high_s_attestation_before_deriving_active_status_id(
) -> Result<(), TestError> {
    let (signature, signer, snapshot) = signed_fixture()?;
    let high_s_signature = high_s_twin(signature)?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer,
        assurance_policy_id: POLICY,
    };

    let admitted = ZkCommonCredentialRootHolderAssurance::admit(
        material(signer, &ROOT, &high_s_signature),
        trust,
        snapshot,
        NOW,
        0,
        &[],
    )
    .map_err(|_| TestError)?;

    assert_eq!(admitted.signature(), &signature);
    assert_ne!(admitted.signature(), &high_s_signature);
    assert_eq!(
        admitted.attestation_id(),
        &derive_common_credential_root_attestation_id(material(signer, &ROOT, &signature))
            .map_err(|_| TestError)?
    );
    Ok(())
}
