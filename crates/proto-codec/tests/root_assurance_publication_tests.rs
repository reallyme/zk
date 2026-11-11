// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-codec authority issuance, bulk status, and holder-path verification.

#![cfg(any(feature = "native", feature = "wasm"))]

use reallyme_zk_api::{
    common_root::{
        common_credential_root_attestation_signing_digest, common_credential_root_root_commitment,
        ZkCommonCredentialRootActiveSet, ZkCommonCredentialRootAttestationTrustPolicy,
        ZkCommonCredentialRootHolderAssurance, ZkRootAssuranceAttestation, ZkRootStatusSnapshot,
        ZkRootStatusTrustPolicy,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto_codec::common_credential_root_active_set_path_assignment::{
    decode_root_active_set_path_assignment, encode_root_active_set_path_assignment,
    ZkRootActiveSetPathAssignmentRef,
};
use reallyme_zk_proto_codec::common_credential_root_active_set_publication::{
    admit_root_active_set_publication, encode_root_active_set_publication_from_authority,
    ZkRootActiveSetAuthorityPublication,
};
use reallyme_zk_proto_codec::common_credential_root_attestation::{
    decode_root_assurance_attestation, encode_root_assurance_attestation,
};
use thiserror::Error;
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_000;
const ROOT: [u8; 32] = [0x34; 32];
const POLICY: [u8; 32] = [0x55; 32];

#[derive(Debug, Error)]
#[error("root-assurance publication integration fixture failed")]
struct TestError;

fn signer() -> Result<(Zeroizing<[u8; 32]>, ZkIssuerPublicKey), TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).map_err(|_| TestError)?;
    let point = crypto_p256::decompress_public_key(&compressed).map_err(|_| TestError)?;
    let public = ZkIssuerPublicKey {
        x: point[1..33].try_into().map_err(|_| TestError)?,
        y: point[33..65].try_into().map_err(|_| TestError)?,
    };
    Ok((secret, public))
}

fn jose_signature(secret: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64], TestError> {
    let digest = crypto_p256::P256Sha256Digest::new(*digest);
    let der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret, &digest).map_err(|_| TestError)?;
    crypto_p256::p256_ecdsa_der_to_jose_signature(&der).map_err(|_| TestError)
}

#[test]
fn issued_attestation_and_bulk_status_admit_one_live_holder_path() -> Result<(), TestError> {
    let (secret, public) = signer()?;
    let commitment = common_credential_root_root_commitment(&ROOT).map_err(|_| TestError)?;
    let attestation_digest = common_credential_root_attestation_signing_digest(
        &commitment,
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
    )
    .map_err(|_| TestError)?;
    let attestation = ZkRootAssuranceAttestation::try_from_authority_signed_parts(
        *commitment,
        POLICY,
        NOW - 60,
        NOW + 60,
        7,
        reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(public),
        ),
        jose_signature(&secret, &attestation_digest)?,
    )
    .map_err(|_| TestError)?;
    let private_bytes = encode_root_assurance_attestation(&attestation).map_err(|_| TestError)?;
    let stored_attestation =
        decode_root_assurance_attestation(&private_bytes).map_err(|_| TestError)?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(public),
        ),
        assurance_policy_id: POLICY,
    };
    let id = stored_attestation
        .verify_for_root(&ROOT, trust, NOW)
        .map_err(|_| TestError)?;

    let active_set =
        ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&[*id]).map_err(|_| TestError)?;
    let status_digest =
        ZkRootStatusSnapshot::signing_digest_for_fields(active_set.root(), NOW - 1, NOW + 60, 7);
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        active_set.root(),
        NOW - 1,
        NOW + 60,
        7,
        reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(public),
        ),
        jose_signature(&secret, &status_digest)?,
    )
    .map_err(|_| TestError)?;
    let published =
        encode_root_active_set_publication_from_authority(ZkRootActiveSetAuthorityPublication {
            active_attestations: &[&stored_attestation],
            revoked_attestation_ids: &[],
            attestation_trust: trust,
            snapshot: &snapshot,
        })
        .map_err(|_| TestError)?;
    let downloaded = admit_root_active_set_publication(&published)
        .map_err(|_| TestError)?
        .authenticate(
            ZkRootStatusTrustPolicy {
                authority: reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
                    reallyme_zk_api::keys::ZkP256PublicKey::from(public),
                ),
                minimum_sequence: 7,
                maximum_age_seconds: 120,
            },
            NOW,
        )
        .map_err(|_| TestError)?;
    let verified = downloaded.verified_snapshot();
    let opening = downloaded
        .active_set()
        .open_against(verified, NOW, &id)
        .map_err(|_| TestError)?;
    let assignment = encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
        feed_id: [0x5a; 32],
        active_status_root: verified.root(),
        sequence: verified.sequence(),
        attestation_id: &id,
        status_index: opening.index(),
        status_path: opening.siblings(),
    })
    .map_err(|_| TestError)?;
    let decoded_assignment =
        decode_root_active_set_path_assignment(&assignment).map_err(|_| TestError)?;
    assert_eq!(decoded_assignment.feed_id(), [0x5a; 32]);
    assert_eq!(decoded_assignment.active_status_root(), verified.root());
    assert_eq!(decoded_assignment.sequence(), verified.sequence());
    assert_eq!(decoded_assignment.attestation_id(), id.as_ref());
    let holder = ZkCommonCredentialRootHolderAssurance::admit(
        stored_attestation.material(&ROOT, NOW),
        trust,
        verified,
        NOW,
        opening.index(),
        opening.siblings(),
    )
    .map_err(|_| TestError)?;
    assert!(holder.require_lineage_roots(&ROOT, &ROOT).is_ok());
    assert!(downloaded
        .active_set()
        .open_against(verified, NOW, &[0x35; 32])
        .is_err());
    Ok(())
}
