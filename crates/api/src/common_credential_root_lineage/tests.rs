// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{derive_common_credential_root_v1_lineage, ZkCommonCredentialRootLineageReason};
use crate::{common_root::ZkCommonCredentialRootSubjectPublicKey, keys::ZkIssuerPublicKey};

fn fixed_hex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = core::str::from_utf8(chunk).expect("reviewed ASCII hex vector");
        bytes[index] = u8::from_str_radix(text, 16).expect("reviewed hex vector");
    }
    bytes
}

#[test]
fn reproduces_both_reviewed_lineage_derivation_vectors() {
    for (name, issuer_x, issuer_y, subject_x, subject_y, nonce, context, tag) in [
        (
            "university",
            "3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1",
            "9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740",
            "177c837ae0ac495a61805df2d85ee2fc792e284b65ead58a98e15d9d46072c01",
            "63bb58cd4ebea558a24091adb40f4e7226ee14c3a1fb4df39c43bbe2efc7bfd8",
            "2776dc2166e402344828c4faa23aa74afd987f116f2227c78786676bea041b9b",
            "de5211482a8933aa5d1443da199f38b5a257a5861424576a55064fa7eb4f08ee",
            "6c6499bb078cb178c766284de7c8633f66fb294ec6f8db5072d86428d09f8eea",
        ),
        (
            "employer",
            "47776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73e",
            "aa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc",
            "cb6d2861102c0c25ce39b7c17108c507782c452257884895c1fc7b74ab03ed83",
            "58d7614b24d9ef515c35e7100d6d6ce4a496716e30fa3e03e39150752bcecdaa",
            "7948224835d0737b64e4f8de85eebee49580babe0f5aae5121dd5a4081f682e0",
            "3d5ac0462fd91a1cc29a854452d3c607950fc4542bb0447f1ea770684afd9ef4",
            "d29f6b69c033980058120d090c3fae00c3c7ab8269ba66f385db544f1ea9d398",
        ),
    ] {
        let root = core::array::from_fn(|index| u8::try_from(index + 1).expect("32 bytes"));
        let result = derive_common_credential_root_v1_lineage(
            &root,
            ZkIssuerPublicKey {
                x: fixed_hex::<32>(issuer_x),
                y: fixed_hex::<32>(issuer_y),
            },
            &format!("did:me:fixture:{name}"),
            ZkCommonCredentialRootSubjectPublicKey {
                x: fixed_hex::<32>(subject_x),
                y: fixed_hex::<32>(subject_y),
            },
            &fixed_hex::<32>(nonce),
        )
        .expect("reviewed derivation vector must match");
        assert_eq!(result.context_hash(), fixed_hex::<32>(context));
        assert_eq!(*result.tag(), fixed_hex::<32>(tag));
    }
}

#[test]
fn rejects_invalid_relationship_and_degenerate_secret_material() {
    let root = [1_u8; 32];
    let nonce = [2_u8; 32];
    let key = ZkIssuerPublicKey {
        x: [3_u8; 32],
        y: [4_u8; 32],
    };
    let subject = ZkCommonCredentialRootSubjectPublicKey {
        x: [5_u8; 32],
        y: [6_u8; 32],
    };
    for did in ["", "did:me:", "did:example:other"] {
        let error = derive_common_credential_root_v1_lineage(&root, key, did, subject, &nonce)
            .err()
            .expect("invalid relationship must fail");
        assert_eq!(
            error.reason(),
            ZkCommonCredentialRootLineageReason::InvalidRelationship
        );
    }
    for (candidate_root, candidate_nonce) in [([0_u8; 32], nonce), (root, [0_u8; 32])] {
        let error = derive_common_credential_root_v1_lineage(
            &candidate_root,
            key,
            "did:me:relationship",
            subject,
            &candidate_nonce,
        )
        .err()
        .expect("zero material must fail");
        assert_eq!(
            error.reason(),
            ZkCommonCredentialRootLineageReason::InvalidMaterial
        );
    }
}
