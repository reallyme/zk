// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    common_root::{
        common_credential_root_attestation_signing_digest, common_credential_root_root_commitment,
        normalize_common_credential_root_p256_signature_low_s,
        ZkCommonCredentialRootAttestationTrustPolicy, ZkRootAssuranceAttestation,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{decode_root_assurance_attestation, encode_root_assurance_attestation};

const NOW: u64 = 1_800_000_000;
const ROOT: [u8; 32] = [0x34; 32];
const POLICY: [u8; 32] = [0x55; 32];
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Debug, Error)]
#[error("root assurance codec fixture failed")]
struct TestError;

fn signed_record() -> Result<(ZkRootAssuranceAttestation, ZkIssuerPublicKey), TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
    let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
    let signer = ZkIssuerPublicKey {
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
    let record = ZkRootAssuranceAttestation::try_from_authority_signed_parts(
        *commitment,
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
        reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
        ),
        signature,
    )
    .map_err(|_| TestError)?;
    Ok((record, signer))
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
fn canonical_private_record_retains_exact_signed_fields() -> Result<(), TestError> {
    let (record, signer) = signed_record()?;
    let encoded = encode_root_assurance_attestation(&record).map_err(|_| TestError)?;
    let decoded = decode_root_assurance_attestation(&encoded).map_err(|_| TestError)?;
    assert_eq!(decoded.issued_unix(), NOW - 60);
    assert_eq!(decoded.epoch(), 7);
    assert!(decoded
        .verify_for_root(
            &ROOT,
            ZkCommonCredentialRootAttestationTrustPolicy {
                signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
                    reallyme_zk_api::keys::ZkP256PublicKey::from(signer)
                ),
                assurance_policy_id: POLICY,
            },
            NOW,
        )
        .is_ok());
    Ok(())
}

#[test]
fn malformed_and_signature_substituted_records_fail_closed() -> Result<(), TestError> {
    let (record, signer) = signed_record()?;
    let encoded = encode_root_assurance_attestation(&record).map_err(|_| TestError)?;
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootAssuranceAttestation>(&encoded)
        .map_err(|_| TestError)?;
    wire.root_commitment.pop();
    assert!(decode_root_assurance_attestation(&wire.encode_to_vec()).is_err());
    wire.root_commitment = record.root_commitment().to_vec();
    wire.signature[0] ^= 1;
    let altered =
        decode_root_assurance_attestation(&wire.encode_to_vec()).map_err(|_| TestError)?;
    assert!(altered
        .verify_for_root(
            &ROOT,
            ZkCommonCredentialRootAttestationTrustPolicy {
                signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
                    reallyme_zk_api::keys::ZkP256PublicKey::from(signer)
                ),
                assurance_policy_id: POLICY,
            },
            NOW,
        )
        .is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_root_assurance_attestation(&trailing).is_err());
    Ok(())
}

#[test]
fn decoded_record_rejects_high_s_artifact_signature() -> Result<(), TestError> {
    let (record, _) = signed_record()?;
    let encoded = encode_root_assurance_attestation(&record).map_err(|_| TestError)?;
    let mut wire = DecodeOptions::new()
        .decode_from_slice::<pb::ZkRootAssuranceAttestation>(&encoded)
        .map_err(|_| TestError)?;
    wire.signature = high_s_twin(*record.signature())?.to_vec();
    assert!(decode_root_assurance_attestation(&wire.encode_to_vec()).is_err());
    Ok(())
}
