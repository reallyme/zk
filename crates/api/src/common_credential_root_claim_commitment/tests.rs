// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

mod issuer_root_tests;

use super::{
    build_from_parts as build_common_credential_root_sha256_claims_commitment,
    ZkCommonCredentialRootClaim, ZkCommonCredentialRootClaimCommitmentReason,
};

#[test]
fn issuer_recomputes_approved_claims_without_learning_lineage_value() {
    let salt = [0x31; 16];
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
    let wallet = build_common_credential_root_sha256_claims_commitment(
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 16],
        &claims,
    )
    .expect("bounded wallet commitment");
    let opaque_leaf = wallet
        .opaque_lineage_claim_digest()
        .expect("bounded lineage claim digest");
    let approved = super::verify_common_credential_root_sha256_issuer_claims_root(
        wallet.root(),
        opaque_leaf,
        &claims,
    )
    .expect("exact approved claims and lineage claim digest reconstruct root");
    assert_eq!(approved.root(), wallet.root());
    assert_eq!(
        approved.credential_hash_algorithm(),
        crate::circuits::ZkCredentialHashAlgorithm::Sha256
    );

    let wrong_value = [
        ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"unverified",
            salt: &salt,
        },
        ZkCommonCredentialRootClaim {
            name: "country",
            value: b"MT",
            salt: &salt,
        },
    ];
    let wrong_salt = [0x32; 16];
    let wrong_salt_claims = [
        ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"verified",
            salt: &wrong_salt,
        },
        ZkCommonCredentialRootClaim {
            name: "country",
            value: b"MT",
            salt: &salt,
        },
    ];
    let wrong_name = [
        ZkCommonCredentialRootClaim {
            name: "qualification",
            value: b"verified",
            salt: &salt,
        },
        ZkCommonCredentialRootClaim {
            name: "country",
            value: b"MT",
            salt: &salt,
        },
    ];
    for (leaf, check_claims) in [
        (opaque_leaf, &wrong_value[..]),
        (opaque_leaf, &wrong_salt_claims[..]),
        (opaque_leaf, &wrong_name[..]),
        ([0x51; 32], &claims[..]),
    ] {
        let error = super::verify_common_credential_root_sha256_issuer_claims_root(
            wallet.root(),
            leaf,
            check_claims,
        )
        .expect_err("substituted claim material must fail");
        assert_eq!(
            error.reason(),
            ZkCommonCredentialRootClaimCommitmentReason::IssuerRootMismatch
        );
    }
}

#[test]
fn issuer_rejects_invalid_claim_tree_inputs() {
    let salt = [1; 16];
    let valid = [ZkCommonCredentialRootClaim {
        name: "degree",
        value: b"verified",
        salt: &salt,
    }];
    let root = [2; 32];
    let leaf = [3; 32];
    for (claims, expected) in [
        (
            &[][..],
            ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimCount,
        ),
        (
            &[ZkCommonCredentialRootClaim {
                name: "reallyme.lineage.v1",
                value: b"bad",
                salt: &salt,
            }][..],
            ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName,
        ),
        (
            &[ZkCommonCredentialRootClaim {
                name: "degree",
                value: b"",
                salt: &salt,
            }][..],
            ZkCommonCredentialRootClaimCommitmentReason::InvalidValueLength,
        ),
        (
            &[ZkCommonCredentialRootClaim {
                name: "degree",
                value: b"verified",
                salt: &[0; 16],
            }][..],
            ZkCommonCredentialRootClaimCommitmentReason::InvalidSalt,
        ),
    ] {
        let error =
            super::verify_common_credential_root_sha256_issuer_claims_root(root, leaf, claims)
                .expect_err("invalid issuer claim material must fail");
        assert_eq!(error.reason(), expected);
    }
    let error =
        super::verify_common_credential_root_sha256_issuer_claims_root(root, [0; 32], &valid)
            .expect_err("all-zero lineage claim digest must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidLineageLeaf
    );
    let duplicate = [
        ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"first",
            salt: &salt,
        },
        ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"second",
            salt: &salt,
        },
    ];
    let error =
        super::verify_common_credential_root_sha256_issuer_claims_root(root, leaf, &duplicate)
            .expect_err("duplicate issuer claim names must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName
    );
    let excess = (0..64)
        .map(|_| ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"verified",
            salt: &salt,
        })
        .collect::<Vec<_>>();
    let error = super::verify_common_credential_root_sha256_issuer_claims_root(root, leaf, &excess)
        .expect_err("more than 64 total leaves must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimCount
    );
}

#[test]
fn issuer_accepts_maximum_admitted_claim_tree() {
    let salt = [0x47; 16];
    let names = (0..63)
        .map(|index| format!("claim-{index}"))
        .collect::<Vec<_>>();
    let claims = names
        .iter()
        .map(|name| ZkCommonCredentialRootClaim {
            name,
            value: b"approved",
            salt: &salt,
        })
        .collect::<Vec<_>>();
    let wallet = build_common_credential_root_sha256_claims_commitment(
        &[0x11; 32],
        &[0x22; 32],
        &salt,
        &claims,
    )
    .expect("64 leaves are admitted");
    let leaf = wallet
        .opaque_lineage_claim_digest()
        .expect("bounded lineage claim digest");
    super::verify_common_credential_root_sha256_issuer_claims_root(wallet.root(), leaf, &claims)
        .expect("maximum approved tree matches wallet root");
}

fn fixed_hex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = core::str::from_utf8(chunk).expect("reviewed ASCII hex test vector");
        bytes[index] = u8::from_str_radix(text, 16).expect("reviewed hex test vector");
    }
    bytes
}

#[test]
fn reproduces_both_reviewed_sha256_circuit_commitment_vectors() {
    for (name, context, tag, lineage_salt, selected_salt, expected_root) in [
        (
            "university",
            "de5211482a8933aa5d1443da199f38b5a257a5861424576a55064fa7eb4f08ee",
            "1439ca94f1ff41117cb5fb652227c0df6008930ebffcc4da3e8752f03a12982f",
            "250c86286da00d672127a320a5db777b",
            "38d74c98e1504cb1a17104d2653e83ed",
            "cd5444cf0a3b3280492d458664d6529abd0a2e7262b1d8e4e13cfc13cc31612b",
        ),
        (
            "employer",
            "3d5ac0462fd91a1cc29a854452d3c607950fc4542bb0447f1ea770684afd9ef4",
            "874f138a289b6d0dcbe3d9eb8d8190029bf6c22726dd00c5ffd0d506de019369",
            "e4251884f85abf1aecba4c305b21b8f8",
            "942b77287c65f8e61078a591eca5b10a",
            "9a77d478f67deec9655c0ca5433604e9c5e4498d97fb16b6cecd72fe095c98a9",
        ),
    ] {
        let claim_name = format!("fixture selected claim name:{name}");
        let claim_value = format!("verified:{name}");
        let claim_salt = fixed_hex::<16>(selected_salt);
        let claims = [ZkCommonCredentialRootClaim {
            name: &claim_name,
            value: claim_value.as_bytes(),
            salt: &claim_salt,
        }];
        let commitment = build_common_credential_root_sha256_claims_commitment(
            &fixed_hex::<32>(context),
            &fixed_hex::<32>(tag),
            &fixed_hex::<16>(lineage_salt),
            &claims,
        )
        .expect("reviewed circuit vector must build");
        assert_eq!(commitment.root(), fixed_hex::<32>(expected_root));
        assert_eq!(commitment.openings().len(), 2);
        assert_eq!(commitment.openings()[0].leaf_index(), 0);
        assert_eq!(commitment.openings()[1].leaf_index(), 1);
        assert_eq!(
            commitment.openings()[0].siblings().len(),
            super::CLAIM_TREE_DEPTH
        );
        assert_eq!(
            commitment.openings()[1].siblings().len(),
            super::CLAIM_TREE_DEPTH
        );
    }
}

#[test]
fn reproduces_both_reviewed_poseidon2_circuit_commitment_vectors() {
    for (name, context, tag, lineage_salt, selected_salt, expected_root) in [
        (
            "university",
            "de5211482a8933aa5d1443da199f38b5a257a5861424576a55064fa7eb4f08ee",
            "1439ca94f1ff41117cb5fb652227c0df6008930ebffcc4da3e8752f03a12982f",
            "250c86286da00d672127a320a5db777b",
            "38d74c98e1504cb1a17104d2653e83ed",
            "04e149a7f9ac8b79c33bee3abf6f07f74099769a4386ef260cf7c68b50d2b3a0",
        ),
        (
            "employer",
            "3d5ac0462fd91a1cc29a854452d3c607950fc4542bb0447f1ea770684afd9ef4",
            "874f138a289b6d0dcbe3d9eb8d8190029bf6c22726dd00c5ffd0d506de019369",
            "e4251884f85abf1aecba4c305b21b8f8",
            "942b77287c65f8e61078a591eca5b10a",
            "2e2cc05c4dd869ddc550d7f4d554443b3f72c6679c9fbd022ab761a5b7ad7932",
        ),
    ] {
        let claim_name = format!("fixture selected claim name:{name}");
        let claim_value = format!("verified:{name}");
        let claim_salt = fixed_hex::<16>(selected_salt);
        let claims = [ZkCommonCredentialRootClaim {
            name: &claim_name,
            value: claim_value.as_bytes(),
            salt: &claim_salt,
        }];
        let commitment = super::build_from_parts_for_lane(
            crate::circuits::ZkCredentialHashAlgorithm::Poseidon2,
            &fixed_hex::<32>(context),
            &fixed_hex::<32>(tag),
            &fixed_hex::<16>(lineage_salt),
            &claims,
        )
        .expect("reviewed circuit vector must build");
        assert_eq!(commitment.root(), fixed_hex::<32>(expected_root));
        assert_eq!(
            commitment.credential_hash_algorithm(),
            crate::circuits::ZkCredentialHashAlgorithm::Poseidon2
        );
        let leaf = commitment
            .opaque_lineage_claim_digest()
            .expect("bounded lineage claim digest");
        let approved = super::verify_common_credential_root_poseidon2_issuer_claims_root(
            commitment.root(),
            leaf,
            &claims,
        )
        .expect("issuer accepts exactly the selected approved claim");
        assert_eq!(approved.root(), commitment.root());
        assert_eq!(
            approved.credential_hash_algorithm(),
            crate::circuits::ZkCredentialHashAlgorithm::Poseidon2
        );
        let wrong_lane = super::ZkCommonCredentialRootClaimsCommitment::restore_verified(
            commitment.root(),
            commitment
                .openings()
                .iter()
                .map(|opening| {
                    super::ZkCommonCredentialRootClaimOpening::restore(
                        opening.name_hash(),
                        opening.value().to_vec(),
                        *opening.salt(),
                        opening.leaf_index(),
                        opening.siblings().to_vec(),
                    )
                })
                .collect(),
        );
        assert!(
            wrong_lane.is_err(),
            "a Poseidon2 opening cannot be read as SHA-256"
        );
    }
}

#[test]
fn rejects_reserved_duplicate_and_empty_claim_names() {
    let salt = [1_u8; 16];
    let context = [2_u8; 32];
    let tag = [3_u8; 32];
    for name in ["", "reallyme.lineage.v1"] {
        let claims = [ZkCommonCredentialRootClaim {
            name,
            value: b"valid",
            salt: &salt,
        }];
        let error =
            build_common_credential_root_sha256_claims_commitment(&context, &tag, &salt, &claims)
                .err()
                .expect("invalid name must fail");
        assert_eq!(
            error.reason(),
            ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName
        );
    }
    let claims = [
        ZkCommonCredentialRootClaim {
            name: "same",
            value: b"first",
            salt: &salt,
        },
        ZkCommonCredentialRootClaim {
            name: "same",
            value: b"second",
            salt: &salt,
        },
    ];
    let error =
        build_common_credential_root_sha256_claims_commitment(&context, &tag, &salt, &claims)
            .err()
            .expect("duplicate name must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName
    );
}

#[test]
fn oversized_claim_names_fail_before_issuance_hashing() {
    let salt = [0x5a_u8; 16];
    let oversized_name = "n".repeat(super::MAX_CLAIM_NAME_BYTES + 1);
    let claims = [ZkCommonCredentialRootClaim {
        name: &oversized_name,
        value: b"verified",
        salt: &salt,
    }];
    let error = build_common_credential_root_sha256_claims_commitment(
        &[0x11; 32],
        &[0x22; 32],
        &salt,
        &claims,
    )
    .err()
    .expect("oversized wallet claim name rejects");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName
    );
    let error = super::verify_common_credential_root_poseidon2_issuer_claims_root(
        [0x33; 32], [0x44; 32], &claims,
    )
    .expect_err("oversized issuer claim name rejects");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimName
    );
}

#[test]
fn rejects_invalid_salts_values_and_leaf_count() {
    let context = [2_u8; 32];
    let tag = [3_u8; 32];
    let salt = [1_u8; 16];
    let zero_salt = [0_u8; 16];
    let no_claims =
        build_common_credential_root_sha256_claims_commitment(&context, &tag, &salt, &[])
            .err()
            .expect("lineage-only tree must fail");
    assert_eq!(
        no_claims.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidClaimCount
    );
    let large = [7_u8; 65];
    for (value, claim_salt, expected) in [
        (
            &b""[..],
            &salt,
            ZkCommonCredentialRootClaimCommitmentReason::InvalidValueLength,
        ),
        (
            &large[..],
            &salt,
            ZkCommonCredentialRootClaimCommitmentReason::InvalidValueLength,
        ),
        (
            &b"valid"[..],
            &zero_salt,
            ZkCommonCredentialRootClaimCommitmentReason::InvalidSalt,
        ),
    ] {
        let claims = [ZkCommonCredentialRootClaim {
            name: "claim",
            value,
            salt: claim_salt,
        }];
        let error =
            build_common_credential_root_sha256_claims_commitment(&context, &tag, &salt, &claims)
                .err()
                .expect("invalid claim must fail");
        assert_eq!(error.reason(), expected);
    }
    let valid = [ZkCommonCredentialRootClaim {
        name: "claim",
        value: b"valid",
        salt: &salt,
    }];
    let error =
        build_common_credential_root_sha256_claims_commitment(&context, &tag, &zero_salt, &valid)
            .err()
            .expect("zero lineage salt must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidSalt
    );
}

#[test]
fn every_tree_has_the_fixed_depth_and_pads_with_empty_subtrees() {
    let salt = [1_u8; 16];
    let context = [2_u8; 32];
    let tag = [3_u8; 32];
    let names = (0..63)
        .map(|index| format!("claim-{index}"))
        .collect::<Vec<_>>();
    for claim_count in [1_usize, 2, 3, 31, 32, 63] {
        let claims = names
            .iter()
            .take(claim_count)
            .map(|name| ZkCommonCredentialRootClaim {
                name,
                value: b"one",
                salt: &salt,
            })
            .collect::<Vec<_>>();
        for credential_hash_algorithm in [
            crate::circuits::ZkCredentialHashAlgorithm::Sha256,
            crate::circuits::ZkCredentialHashAlgorithm::Poseidon2,
        ] {
            let commitment = super::build_from_parts_for_lane(
                credential_hash_algorithm,
                &context,
                &tag,
                &salt,
                &claims,
            )
            .expect("bounded tree builds");
            let empty = super::transcript::empty_subtree_digests(credential_hash_algorithm)
                .expect("bounded empty subtrees");
            assert_eq!(empty[0], [0_u8; 32]);
            let leaf_count = claim_count + 1;
            for opening in commitment.openings() {
                assert_eq!(opening.siblings().len(), super::CLAIM_TREE_DEPTH);
                // Recompute the root from this opening alone and require the
                // canonical empty subtree wherever no issued leaf exists.
                let mut digest =
                    super::transcript::opening_leaf_digest(credential_hash_algorithm, opening)
                        .expect("bounded opening");
                let mut index = usize::try_from(opening.leaf_index()).expect("bounded index");
                let mut width = leaf_count;
                for (level, sibling) in opening.siblings().iter().enumerate() {
                    if (index ^ 1) >= width {
                        assert_eq!(*sibling, empty[level]);
                    }
                    digest = if index % 2 == 0 {
                        super::transcript::parent_digest(
                            credential_hash_algorithm,
                            &digest,
                            sibling,
                        )
                    } else {
                        super::transcript::parent_digest(
                            credential_hash_algorithm,
                            sibling,
                            &digest,
                        )
                    }
                    .expect("bounded parent digest");
                    index /= 2;
                    width = width.div_ceil(2);
                }
                assert_eq!(digest, commitment.root());
            }
        }
    }
}

#[test]
fn restored_opening_rejects_non_empty_padding_and_short_paths() {
    let salt = [1_u8; 16];
    let claims = [ZkCommonCredentialRootClaim {
        name: "degree",
        value: b"verified",
        salt: &salt,
    }];
    let commitment = build_common_credential_root_sha256_claims_commitment(
        &[2_u8; 32],
        &[3_u8; 32],
        &salt,
        &claims,
    )
    .expect("two-leaf tree builds");
    let restore = |edit: &dyn Fn(usize, &mut Vec<[u8; 32]>)| {
        let openings = commitment
            .openings()
            .iter()
            .enumerate()
            .map(|(position, opening)| {
                let mut siblings = opening.siblings().to_vec();
                edit(position, &mut siblings);
                super::ZkCommonCredentialRootClaimOpening::restore(
                    opening.name_hash(),
                    opening.value().to_vec(),
                    *opening.salt(),
                    opening.leaf_index(),
                    siblings,
                )
            })
            .collect();
        super::ZkCommonCredentialRootClaimsCommitment::restore_verified(commitment.root(), openings)
            .map(|_| ())
            .map_err(|error| error.reason())
    };
    assert_eq!(restore(&|_, _| {}), Ok(()));
    // A padding level that is not the canonical empty subtree is rejected.
    assert_eq!(
        restore(&|position, siblings| {
            if position == 0 {
                siblings[3] = [0x55; 32];
            }
        }),
        Err(ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening)
    );
    // A path shorter or longer than the fixed depth is rejected.
    assert_eq!(
        restore(&|position, siblings| {
            if position == 1 {
                siblings.truncate(1);
            }
        }),
        Err(ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening)
    );
    assert_eq!(
        restore(&|position, siblings| {
            if position == 1 {
                siblings.push([0_u8; 32]);
            }
        }),
        Err(ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening)
    );
}

#[test]
fn wallet_accepts_only_the_issuer_root_for_its_private_openings() {
    let salt = [1_u8; 16];
    let claims = [ZkCommonCredentialRootClaim {
        name: "degree",
        value: b"verified",
        salt: &salt,
    }];
    let commitment = build_common_credential_root_sha256_claims_commitment(
        &[2_u8; 32],
        &[3_u8; 32],
        &salt,
        &claims,
    )
    .expect("bounded reviewed claim must build");
    commitment
        .verify_issuer_root(&commitment.root())
        .expect("same root must match");
    let mut substituted_root = commitment.root();
    substituted_root[0] ^= 1;
    let error = commitment
        .verify_issuer_root(&substituted_root)
        .expect_err("different issuer root must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::IssuerRootMismatch
    );
}

#[test]
fn restored_openings_require_exact_path_and_position() {
    let salt = [1_u8; 16];
    let claims = [
        ZkCommonCredentialRootClaim {
            name: "degree",
            value: b"verified",
            salt: &salt,
        },
        ZkCommonCredentialRootClaim {
            name: "occupation",
            value: b"engineer",
            salt: &salt,
        },
    ];
    let commitment = build_common_credential_root_sha256_claims_commitment(
        &[2_u8; 32],
        &[3_u8; 32],
        &salt,
        &claims,
    )
    .expect("three-leaf tree builds");
    let restored = commitment
        .openings()
        .iter()
        .map(|opening| {
            super::ZkCommonCredentialRootClaimOpening::restore(
                opening.name_hash(),
                opening.value().to_vec(),
                *opening.salt(),
                opening.leaf_index(),
                opening.siblings().to_vec(),
            )
        })
        .collect();
    let accepted = super::ZkCommonCredentialRootClaimsCommitment::restore_verified(
        commitment.root(),
        restored,
    )
    .expect("canonical paths restore");
    assert_eq!(accepted.root(), commitment.root());

    let mut wrong_siblings = commitment.openings()[2].siblings().to_vec();
    wrong_siblings[0][0] ^= 1;
    let altered = commitment
        .openings()
        .iter()
        .enumerate()
        .map(|(position, opening)| {
            super::ZkCommonCredentialRootClaimOpening::restore(
                opening.name_hash(),
                opening.value().to_vec(),
                *opening.salt(),
                opening.leaf_index(),
                if position == 2 {
                    wrong_siblings.clone()
                } else {
                    opening.siblings().to_vec()
                },
            )
        })
        .collect();
    let error =
        super::ZkCommonCredentialRootClaimsCommitment::restore_verified(commitment.root(), altered)
            .map(|_| ())
            .expect_err("altered odd-leaf sibling must fail");
    assert_eq!(
        error.reason(),
        ZkCommonCredentialRootClaimCommitmentReason::InvalidOpening
    );
}
