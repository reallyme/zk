// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_noir_witness_core::{CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32};

use super::{merkle_path, pb};

fn fixture(
    count: usize,
) -> MessageField<pb::ZkInputMerklePath, buffa::Inline<pb::ZkInputMerklePath>> {
    MessageField::some(pb::ZkInputMerklePath {
        path_length: CLAIM_TREE_DEPTH_U32,
        siblings: (0..count)
            .map(|_| pb::ZkInputBytes32 {
                value: vec![1; 32],
                __buffa_unknown_fields: Default::default(),
            })
            .collect(),
        __buffa_unknown_fields: Default::default(),
    })
}

#[test]
fn full_claim_path_is_preserved() -> Result<(), ZkError> {
    let path = merkle_path(&fixture(CLAIM_TREE_DEPTH))?;
    assert_eq!(path.length().value(), CLAIM_TREE_DEPTH_U32);
    assert!(path
        .siblings()
        .iter()
        .all(|sibling| sibling.as_bytes() == &[1; 32]));
    Ok(())
}

#[test]
fn missing_siblings_are_not_silently_padded() {
    for count in [0, CLAIM_TREE_DEPTH - 1] {
        let reason = merkle_path(&fixture(count))
            .err()
            .map(|error| error.reason());
        assert_eq!(reason, Some(ZkErrorReason::InvalidProofEncoding));
    }
}

#[test]
fn excess_siblings_are_rejected_before_copying() {
    let reason = merkle_path(&fixture(CLAIM_TREE_DEPTH + 1))
        .err()
        .map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::ClaimPayloadTooLarge));
}

#[test]
fn malformed_sibling_is_rejected() {
    let mut input = fixture(CLAIM_TREE_DEPTH);
    input.get_or_insert_default().siblings[0].value.pop();
    let reason = merkle_path(&input).err().map(|error| error.reason());
    assert_eq!(reason, Some(ZkErrorReason::InvalidProofEncoding));
}
