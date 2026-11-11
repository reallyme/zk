// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::super::{ZkCommonCredentialRootClaim, ZkCommonCredentialRootClaimCommitmentReason};

fn root_from_leaves(
    credential_hash_algorithm: crate::circuits::ZkCredentialHashAlgorithm,
    mut level: Vec<[u8; 32]>,
) -> [u8; 32] {
    let empty = super::super::transcript::empty_subtree_digests(credential_hash_algorithm)
        .expect("bounded empty subtrees");
    for empty_subtree in empty {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&empty_subtree);
                super::super::transcript::parent_digest(credential_hash_algorithm, &pair[0], right)
                    .expect("bounded parent digest")
            })
            .collect();
    }
    level[0]
}

#[test]
fn issuer_rejects_subtree_hidden_in_the_lineage_slot() {
    let salt = [0x61; 16];
    let claims = [
        ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"verified",
            salt: &salt,
        },
        ZkCommonCredentialRootClaim {
            name: "country",
            value: b"MT",
            salt: &salt,
        },
    ];
    for credential_hash_algorithm in [
        crate::circuits::ZkCredentialHashAlgorithm::Sha256,
        crate::circuits::ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        let wallet = super::super::build_from_parts_for_lane(
            credential_hash_algorithm,
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 16],
            &claims,
        )
        .expect("bounded wallet commitment");
        let genuine_lineage_leaf = super::super::transcript::opening_leaf_digest(
            credential_hash_algorithm,
            &wallet.openings()[0],
        )
        .expect("bounded lineage leaf");
        // A claim the issuer never approved, hidden beside the genuine
        // lineage leaf under one interior node.
        let fabricated_leaf = super::super::transcript::claim_leaf_digest(
            credential_hash_algorithm,
            "age_over_18",
            b"true",
            &[0x62; 16],
        )
        .expect("bounded fabricated leaf");
        let hidden_subtree = super::super::transcript::parent_digest(
            credential_hash_algorithm,
            &genuine_lineage_leaf,
            &fabricated_leaf,
        )
        .expect("bounded interior node");
        let mut leaves = vec![hidden_subtree];
        for claim in &claims {
            leaves.push(
                super::super::transcript::claim_leaf_digest(
                    credential_hash_algorithm,
                    claim.name,
                    claim.value,
                    claim.salt,
                )
                .expect("bounded approved leaf"),
            );
        }
        let extended_root = root_from_leaves(credential_hash_algorithm, leaves);
        let verify = match credential_hash_algorithm {
            crate::circuits::ZkCredentialHashAlgorithm::Sha256 => {
                super::super::verify_common_credential_root_sha256_issuer_claims_root
            }
            _ => super::super::verify_common_credential_root_poseidon2_issuer_claims_root,
        };
        for lineage_slot_value in [hidden_subtree, genuine_lineage_leaf] {
            let error = verify(extended_root, lineage_slot_value, &claims)
                .expect_err("issuer must not sign a root with a wallet-built lineage slot");
            assert_eq!(
                error.reason(),
                ZkCommonCredentialRootClaimCommitmentReason::IssuerRootMismatch
            );
        }
        // A finished leaf is no longer accepted in place of the claim digest.
        let error = verify(wallet.root(), genuine_lineage_leaf, &claims)
            .expect_err("finished lineage leaf is not a claim digest");
        assert_eq!(
            error.reason(),
            ZkCommonCredentialRootClaimCommitmentReason::IssuerRootMismatch
        );
        verify(
            wallet.root(),
            wallet
                .opaque_lineage_claim_digest()
                .expect("bounded lineage claim digest"),
            &claims,
        )
        .expect("genuine lineage claim digest reconstructs the wallet root");
    }
}
