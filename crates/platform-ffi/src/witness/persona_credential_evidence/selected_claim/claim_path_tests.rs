// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::errors::ZkErrorReason;
use reallyme_zk_noir_witness_core::{CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::require_full_depth_claim_path;
use crate::witness::input::merkle_path;

fn selected_claim_reason(path_length: u32, sibling_count: usize) -> Option<ZkErrorReason> {
    require_full_depth_claim_path(path_length, sibling_count)
        .err()
        .map(|error| error.reason())
}

fn typed_path_reason(path_length: u32, sibling_count: usize) -> Option<ZkErrorReason> {
    let path = MessageField::some(pb::ZkInputMerklePath {
        path_length,
        siblings: vec![
            pb::ZkInputBytes32 {
                value: vec![1; 32],
                __buffa_unknown_fields: Default::default(),
            };
            sibling_count
        ],
        __buffa_unknown_fields: Default::default(),
    });
    merkle_path(&path).err().map(|error| error.reason())
}

#[test]
fn fixed_claim_tree_depth_is_six() {
    assert_eq!(CLAIM_TREE_DEPTH, 6);
    assert_eq!(usize::try_from(CLAIM_TREE_DEPTH_U32), Ok(CLAIM_TREE_DEPTH));
}

#[test]
fn selected_claim_opening_accepts_only_the_fixed_claim_tree_depth() {
    assert_eq!(selected_claim_reason(6, 6), None);
    for (path_length, sibling_count) in [(0_u32, 0_usize), (1, 1), (5, 5)] {
        assert_eq!(
            selected_claim_reason(path_length, sibling_count),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    for (path_length, sibling_count) in [(6_u32, 5_usize), (5, 6), (6, 0), (0, 6)] {
        assert_eq!(
            selected_claim_reason(path_length, sibling_count),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    for (path_length, sibling_count) in [(7_u32, 7_usize), (7, 6), (6, 7), (u32::MAX, 6)] {
        assert_eq!(
            selected_claim_reason(path_length, sibling_count),
            Some(ZkErrorReason::ClaimPayloadTooLarge)
        );
    }
}

#[test]
fn typed_claim_path_accepts_only_the_fixed_claim_tree_depth() {
    assert_eq!(typed_path_reason(6, 6), None);
    for (short_depth, short_count) in [(0_u32, 0_usize), (1, 1), (5, 5)] {
        assert_eq!(
            typed_path_reason(short_depth, short_count),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
        assert_eq!(
            typed_path_reason(short_depth, CLAIM_TREE_DEPTH),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    for oversized_depth in [CLAIM_TREE_DEPTH_U32 + 1, u32::MAX] {
        assert_eq!(
            typed_path_reason(oversized_depth, CLAIM_TREE_DEPTH),
            Some(ZkErrorReason::ClaimPayloadTooLarge)
        );
    }
    for short in [0_usize, 1, 5] {
        assert_eq!(
            typed_path_reason(CLAIM_TREE_DEPTH_U32, short),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
    assert_eq!(
        typed_path_reason(CLAIM_TREE_DEPTH_U32, 7),
        Some(ZkErrorReason::ClaimPayloadTooLarge)
    );
}
