// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        build_common_credential_root_poseidon2_claims_commitment,
        build_common_credential_root_sha256_claims_commitment,
        derive_common_credential_root_v1_lineage, ZkCommonCredentialRootClaim,
        ZkCommonCredentialRootPrivateLineageMaterial, ZkCommonCredentialRootSubjectPublicKey,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    ZkCommonCredentialRootPreparedClaims, ZkWalletStoredCredential,
};

use super::{
    decode_prepared_claims, decode_prepared_claims_for_lane, encode_prepared_claims,
    ZkCommonCredentialRootClaimsReason,
};
use crate::wallet_stored_credential::{
    decode_wallet_stored_credential, decode_wallet_stored_credential_for_lane,
    encode_wallet_stored_credential, ZkWalletStoredCredentialReason,
};

fn prepared() -> reallyme_zk_api::common_root::ZkCommonCredentialRootClaimsCommitment {
    let lineage = derive_common_credential_root_v1_lineage(
        &[1_u8; 32],
        ZkIssuerPublicKey {
            x: [2_u8; 32],
            y: [3_u8; 32],
        },
        "did:me:issuer-relationship",
        ZkCommonCredentialRootSubjectPublicKey {
            x: [4_u8; 32],
            y: [5_u8; 32],
        },
        &[6_u8; 32],
    )
    .expect("bounded relationship derives");
    let salt = [7_u8; 16];
    let claims = [ZkCommonCredentialRootClaim {
        name: "degree",
        value: b"verified",
        salt: &salt,
    }];
    build_common_credential_root_sha256_claims_commitment(&lineage, &salt, &claims)
        .expect("bounded claims build")
}

fn prepared_poseidon2() -> reallyme_zk_api::common_root::ZkCommonCredentialRootClaimsCommitment {
    let lineage = derive_common_credential_root_v1_lineage(
        &[1_u8; 32],
        issuer_key(),
        "did:me:issuer-relationship",
        subject_key(),
        &[6_u8; 32],
    )
    .expect("bounded relationship derives");
    let salt = [7_u8; 16];
    let claims = [ZkCommonCredentialRootClaim {
        name: "degree",
        value: b"verified",
        salt: &salt,
    }];
    build_common_credential_root_poseidon2_claims_commitment(&lineage, &salt, &claims)
        .expect("bounded Poseidon2 claims build")
}

#[test]
fn encrypted_poseidon2_claims_require_the_authenticated_lane() {
    let claims = prepared_poseidon2();
    let binding = [9_u8; 32];
    let encoded = encode_prepared_claims(&claims, binding).expect("bounded message encodes");
    let restored = decode_prepared_claims_for_lane(
        &encoded,
        ZkCredentialHashAlgorithm::Poseidon2,
        claims.root(),
        binding,
    )
    .expect("exact issuer-authenticated lane restores");
    assert_eq!(
        restored.credential_hash_algorithm(),
        ZkCredentialHashAlgorithm::Poseidon2
    );
    assert_eq!(restored.root(), claims.root());
    assert_eq!(restored.openings().len(), claims.openings().len());

    let wrong_lane = decode_prepared_claims_for_lane(
        &encoded,
        ZkCredentialHashAlgorithm::Sha256,
        claims.root(),
        binding,
    )
    .err()
    .expect("other issuer lane rejects");
    assert_eq!(
        wrong_lane.reason(),
        ZkCommonCredentialRootClaimsReason::BindingMismatch
    );

    let mut decoded = DecodeOptions::new()
        .decode_from_slice::<ZkCommonCredentialRootPreparedClaims>(&encoded)
        .expect("canonical fixture decodes");
    decoded.credential_hash_algorithm = buffa::EnumValue::from(
        reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED,
    );
    let omitted_lane = decoded.encode_to_vec();
    let missing = decode_prepared_claims_for_lane(
        &omitted_lane,
        ZkCredentialHashAlgorithm::Poseidon2,
        claims.root(),
        binding,
    )
    .err()
    .expect("missing lane rejects");
    assert_eq!(
        missing.reason(),
        ZkCommonCredentialRootClaimsReason::InvalidEncoding
    );
}

#[test]
fn encrypted_poseidon2_wallet_record_requires_the_signed_issuer_lane() {
    let claims = prepared_poseidon2();
    let binding = [9_u8; 32];
    let credential = b"issuer-authenticated Poseidon2 credential envelope protobuf";
    let encoded = encode_wallet_stored_credential(
        credential,
        &claims,
        &private_lineage(&claims),
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .expect("bounded private record encodes");
    let restored = decode_wallet_stored_credential_for_lane(
        &encoded,
        credential,
        issuer_key(),
        subject_key(),
        ZkCredentialHashAlgorithm::Poseidon2,
        claims.root(),
        binding,
    )
    .expect("issuer-authenticated Poseidon2 lane restores");
    assert_eq!(
        restored.prepared_claims().credential_hash_algorithm(),
        ZkCredentialHashAlgorithm::Poseidon2
    );
    let wrong_lane = decode_wallet_stored_credential_for_lane(
        &encoded,
        credential,
        issuer_key(),
        subject_key(),
        ZkCredentialHashAlgorithm::Sha256,
        claims.root(),
        binding,
    )
    .err()
    .expect("issuer lane mismatch fails closed");
    assert_eq!(
        wrong_lane.reason(),
        ZkWalletStoredCredentialReason::PrivateClaimMismatch
    );
}

#[test]
fn prepared_claims_require_the_fixed_claim_tree_depth_in_both_lanes() {
    let binding = [9_u8; 32];
    for (claims, lane) in [
        (prepared(), ZkCredentialHashAlgorithm::Sha256),
        (prepared_poseidon2(), ZkCredentialHashAlgorithm::Poseidon2),
    ] {
        let encoded = encode_prepared_claims(&claims, binding).expect("bounded message encodes");
        let canonical = DecodeOptions::new()
            .decode_from_slice::<ZkCommonCredentialRootPreparedClaims>(&encoded)
            .expect("canonical fixture decodes");
        for opening in &canonical.openings {
            assert_eq!(opening.siblings.len(), 6);
        }
        decode_prepared_claims_for_lane(&encoded, lane, claims.root(), binding)
            .expect("full-depth openings restore");

        for wrong_depth in [0_usize, 1, 5, 7] {
            let mut message = canonical.clone();
            let opening = message
                .openings
                .first_mut()
                .expect("fixture has a lineage opening");
            let filler = opening
                .siblings
                .first()
                .cloned()
                .expect("full-depth opening has siblings");
            opening.siblings.resize(wrong_depth, filler);
            let rejected = decode_prepared_claims_for_lane(
                &message.encode_to_vec(),
                lane,
                claims.root(),
                binding,
            )
            .err()
            .expect("wrong-depth opening rejects");
            assert_eq!(
                rejected.reason(),
                ZkCommonCredentialRootClaimsReason::InvalidEncoding
            );
        }
    }
}

fn issuer_key() -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [2_u8; 32],
        y: [3_u8; 32],
    }
}

fn subject_key() -> ZkCommonCredentialRootSubjectPublicKey {
    ZkCommonCredentialRootSubjectPublicKey {
        x: [4_u8; 32],
        y: [5_u8; 32],
    }
}

fn private_lineage(
    claims: &reallyme_zk_api::common_root::ZkCommonCredentialRootClaimsCommitment,
) -> ZkCommonCredentialRootPrivateLineageMaterial {
    ZkCommonCredentialRootPrivateLineageMaterial::new(
        [1_u8; 32],
        "did:me:issuer-relationship".to_owned(),
        [6_u8; 32],
        issuer_key(),
        subject_key(),
        claims,
    )
    .expect("fixture lineage matches prepared claims")
}

#[test]
fn encrypted_record_payload_round_trips_with_exact_issuer_binding() {
    let claims = prepared();
    let binding = [9_u8; 32];
    let encoded = encode_prepared_claims(&claims, binding).expect("bounded message encodes");
    let restored =
        decode_prepared_claims(&encoded, claims.root(), binding).expect("matching record decodes");
    assert_eq!(restored.root(), claims.root());
    assert_eq!(restored.openings().len(), claims.openings().len());
    for (before, after) in claims.openings().iter().zip(restored.openings()) {
        assert_eq!(before.name_hash(), after.name_hash());
        assert_eq!(before.value(), after.value());
        assert_eq!(before.salt(), after.salt());
        assert_eq!(before.leaf_index(), after.leaf_index());
        assert_eq!(before.siblings(), after.siblings());
    }
}

#[test]
fn rejects_other_credential_and_modified_private_opening() {
    let claims = prepared();
    let binding = [9_u8; 32];
    let encoded = encode_prepared_claims(&claims, binding).expect("bounded message encodes");
    let binding_error = decode_prepared_claims(&encoded, claims.root(), [8_u8; 32])
        .map(|_| ())
        .expect_err("other issuance binding rejected");
    assert_eq!(
        binding_error.reason(),
        ZkCommonCredentialRootClaimsReason::BindingMismatch
    );
    let root_error = decode_prepared_claims(&encoded, [8_u8; 32], binding)
        .map(|_| ())
        .expect_err("other issuer root rejected");
    assert_eq!(
        root_error.reason(),
        ZkCommonCredentialRootClaimsReason::BindingMismatch
    );

    let mut message = DecodeOptions::new()
        .decode_from_slice::<ZkCommonCredentialRootPreparedClaims>(&encoded)
        .expect("self-encoded protobuf decodes");
    message.openings[1].claim_value[0] ^= 1;
    let tampered = message.encode_to_vec();
    let opening_error = decode_prepared_claims(&tampered, claims.root(), binding)
        .map(|_| ())
        .expect_err("modified private claim fails path verification");
    assert_eq!(
        opening_error.reason(),
        ZkCommonCredentialRootClaimsReason::OpeningMismatch
    );
}

#[test]
fn rejects_malformed_and_oversized_protected_messages() {
    let claims = prepared();
    let binding = [9_u8; 32];
    assert!(decode_prepared_claims(&[], claims.root(), binding).is_err());
    assert!(decode_prepared_claims(&vec![0_u8; 32 * 1024 + 1], claims.root(), binding).is_err());
    assert!(decode_prepared_claims(&[0xff], claims.root(), binding).is_err());
    let encoded = encode_prepared_claims(&claims, binding).expect("bounded message encodes");
    let mut duplicated_root = encoded.to_vec();
    duplicated_root.extend_from_slice(&[0x12, 0x20]);
    duplicated_root.extend_from_slice(&claims.root());
    assert!(decode_prepared_claims(&duplicated_root, claims.root(), binding).is_err());
}

#[test]
fn wallet_record_payload_round_trips_only_for_the_authenticated_credential() {
    let claims = prepared();
    let binding = [9_u8; 32];
    let credential = b"canonical authenticated OpenID4VCI CredentialEnvelope protobuf";
    let lineage = private_lineage(&claims);
    let encoded = encode_wallet_stored_credential(
        credential,
        &claims,
        &lineage,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .expect("validated material encodes");
    let restored = decode_wallet_stored_credential(
        &encoded,
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .expect("exact credential and private claims decode");
    assert_eq!(restored.credential_envelope_pb(), credential);
    assert_eq!(restored.prepared_claims().root(), claims.root());
    assert_eq!(restored.prepared_claims().openings().len(), 2);
    assert_eq!(restored.private_lineage().root(), &[1_u8; 32]);
    assert_eq!(restored.private_lineage().nonce(), &[6_u8; 32]);

    let error = decode_wallet_stored_credential(
        &encoded,
        b"different credential",
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .err()
    .expect("another credential must be rejected");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::InvalidEncoding
    );
    let error = decode_wallet_stored_credential(
        &encoded,
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        [8_u8; 32],
    )
    .err()
    .expect("another issuance binding must be rejected");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::PrivateClaimMismatch
    );
    let error = encode_wallet_stored_credential(
        credential,
        &claims,
        &lineage,
        issuer_key(),
        subject_key(),
        [8_u8; 32],
        binding,
    )
    .expect_err("another issuer root must be rejected");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::PrivateClaimMismatch
    );
}

#[test]
fn wallet_record_rejects_substituted_or_missing_lineage() {
    let claims = prepared();
    let lineage = private_lineage(&claims);
    let credential = b"credential";
    let binding = [9_u8; 32];
    let encoded = encode_wallet_stored_credential(
        credential,
        &claims,
        &lineage,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .expect("matching private material encodes");

    let wrong_issuer = ZkIssuerPublicKey {
        x: [12; 32],
        y: [13; 32],
    };
    let error = decode_wallet_stored_credential(
        &encoded,
        credential,
        wrong_issuer,
        subject_key(),
        claims.root(),
        binding,
    )
    .err()
    .expect("trusted issuer substitution must fail");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::PrivateLineageMismatch
    );

    let wrong_subject = ZkCommonCredentialRootSubjectPublicKey {
        x: [14; 32],
        y: [15; 32],
    };
    let error = decode_wallet_stored_credential(
        &encoded,
        credential,
        issuer_key(),
        wrong_subject,
        claims.root(),
        binding,
    )
    .err()
    .expect("holder substitution must fail");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::PrivateLineageMismatch
    );

    let mut wire = DecodeOptions::new()
        .decode_from_slice::<ZkWalletStoredCredential>(&encoded)
        .expect("self encoded record decodes");
    wire.private_lineage
        .as_option_mut()
        .expect("lineage present")
        .nonce[0] ^= 1;
    let tampered = wire.encode_to_vec();
    let error = decode_wallet_stored_credential(
        &tampered,
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .err()
    .expect("changed nonce must fail");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::PrivateLineageMismatch
    );

    wire.private_lineage = buffa::MessageField::none();
    let missing = wire.encode_to_vec();
    let error = decode_wallet_stored_credential(
        &missing,
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .err()
    .expect("missing lineage must fail");
    assert_eq!(
        error.reason(),
        ZkWalletStoredCredentialReason::InvalidEncoding
    );
}

#[test]
fn wallet_record_payload_rejects_unknown_and_oversized_wire_data() {
    let claims = prepared();
    let binding = [9_u8; 32];
    let credential = b"credential";
    let lineage = private_lineage(&claims);
    let encoded = encode_wallet_stored_credential(
        credential,
        &claims,
        &lineage,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .expect("validated material encodes");
    let mut unknown = encoded.to_vec();
    unknown.extend_from_slice(&[0x20, 0x01]);
    assert!(decode_wallet_stored_credential(
        &unknown,
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding
    )
    .is_err());
    let mut duplicated_version = encoded.to_vec();
    duplicated_version.extend_from_slice(&[0x08, 0x01]);
    assert!(decode_wallet_stored_credential(
        &duplicated_version,
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .is_err());
    assert!(decode_wallet_stored_credential(
        &[],
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding
    )
    .is_err());
    assert!(decode_wallet_stored_credential(
        &vec![0_u8; 1024 * 1024 + 32 * 1024 + 1025],
        credential,
        issuer_key(),
        subject_key(),
        claims.root(),
        binding,
    )
    .is_err());
}
