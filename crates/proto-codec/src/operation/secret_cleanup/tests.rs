// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    zk_stage_witness_input::Input, ZkClaimProofBundleWitness, ZkCredentialSubjectClaimInput,
    ZkInputBytes16, ZkInputBytes32, ZkInputBytes64, ZkInputClaimDisclosure, ZkInputIssuerContext,
    ZkInputMerkleClaimProof, ZkInputMerklePath, ZkInputP256PublicKey, ZkInputSubjectClaimLink,
    ZkStageWitnessInput, ZkWitness,
};

use super::{
    zeroize_stage_witness_input_proto, zeroize_witness_bundle_proto, zeroize_witness_proto,
};

#[test]
fn witness_cleanup_clears_encoded_buffer_before_drop() {
    let mut witness = ZkWitness::default();
    witness.encoded = vec![0x71, 0x82, 0x93];

    zeroize_witness_proto(&mut witness);

    // A no-op cleanup must fail this test. Vec::zeroize clears its length after
    // overwriting the initialized bytes, so those bytes cannot be read safely.
    assert!(witness.encoded.is_empty());
}

#[test]
fn bundle_cleanup_clears_every_stage_witness_before_drop() {
    let mut first = ZkWitness::default();
    first.encoded = vec![0x71, 0x82];
    let mut second = ZkWitness::default();
    second.encoded = vec![0x93, 0xa4, 0xb5];
    let mut bundle = ZkClaimProofBundleWitness {
        stage_witnesses: vec![first, second],
        ..Default::default()
    };

    zeroize_witness_bundle_proto(&mut bundle);

    assert!(bundle.stage_witnesses[0].encoded.is_empty());
    assert!(bundle.stage_witnesses[1].encoded.is_empty());
}

#[test]
fn witness_stage_input_cleanup_overwrites_bytes_and_scalars() -> Result<(), ZkError> {
    let mut input = ZkStageWitnessInput {
        input: Some(Input::CredentialSubjectClaim(Box::new(
            ZkCredentialSubjectClaimInput {
                issuer_context: MessageField::some(ZkInputIssuerContext {
                    issuer_public_key: p256_public_key(1, 2),
                    challenge: bytes32(3),
                    audience_hash: bytes32(4),
                    expiry_unix: 5,
                    transaction_data_hash: bytes32(6),
                    __buffa_unknown_fields: Default::default(),
                }),
                session_binding: bytes32(7),
                disclosure: MessageField::some(ZkInputClaimDisclosure {
                    credential_binding: bytes32(8),
                    value_length: 9,
                    value: bytes64(10),
                    claim_name_hash: bytes32(11),
                    __buffa_unknown_fields: Default::default(),
                }),
                proof: MessageField::some(ZkInputMerkleClaimProof {
                    envelope_hash: bytes32(12),
                    merkle_root: bytes32(13),
                    claim_salt: bytes16(14),
                    leaf_index: 15,
                    path: MessageField::some(ZkInputMerklePath {
                        path_length: 16,
                        siblings: vec![ZkInputBytes32 {
                            value: vec![17; 32],
                            __buffa_unknown_fields: Default::default(),
                        }],
                        __buffa_unknown_fields: Default::default(),
                    }),
                    __buffa_unknown_fields: Default::default(),
                }),
                link: MessageField::some(ZkInputSubjectClaimLink {
                    issuer_subject_binding_signature: bytes64(18),
                    subject_public_key: p256_public_key(19, 20),
                    __buffa_unknown_fields: Default::default(),
                }),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    zeroize_stage_witness_input_proto(&mut input);

    let Some(Input::CredentialSubjectClaim(claim)) = input.input.as_ref() else {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    };
    let issuer = claim
        .issuer_context
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let issuer_key = issuer
        .issuer_public_key
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let issuer_x = issuer_key
        .x
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert!(issuer_x.value.iter().all(|byte| *byte == 0));
    assert_eq!(issuer.expiry_unix, 0);
    let disclosure = claim
        .disclosure
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert_eq!(disclosure.value_length, 0);
    let disclosure_value = disclosure
        .value
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert!(disclosure_value.value.iter().all(|byte| *byte == 0));
    let proof = claim
        .proof
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert_eq!(proof.leaf_index, 0);
    let path = proof
        .path
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert_eq!(path.path_length, 0);
    let sibling = path
        .siblings
        .first()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert!(sibling.value.iter().all(|byte| *byte == 0));
    let link = claim
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let signature = link
        .issuer_subject_binding_signature
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert!(signature.value.iter().all(|byte| *byte == 0));
    Ok(())
}

fn bytes16(marker: u8) -> MessageField<ZkInputBytes16, buffa::Inline<ZkInputBytes16>> {
    MessageField::some(ZkInputBytes16 {
        value: vec![marker; 16],
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes32(marker: u8) -> MessageField<ZkInputBytes32, buffa::Inline<ZkInputBytes32>> {
    MessageField::some(ZkInputBytes32 {
        value: vec![marker; 32],
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes64(marker: u8) -> MessageField<ZkInputBytes64, buffa::Inline<ZkInputBytes64>> {
    MessageField::some(ZkInputBytes64 {
        value: vec![marker; 64],
        __buffa_unknown_fields: Default::default(),
    })
}

fn p256_public_key(
    x: u8,
    y: u8,
) -> MessageField<ZkInputP256PublicKey, buffa::Inline<ZkInputP256PublicKey>> {
    MessageField::some(ZkInputP256PublicKey {
        x: bytes32(x),
        y: bytes32(y),
        __buffa_unknown_fields: Default::default(),
    })
}
