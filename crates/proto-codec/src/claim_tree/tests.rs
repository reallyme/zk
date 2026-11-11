// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::errors::ZkErrorReason;

use super::{is_claim_tree_depth, validate_claim_path_shape, CLAIM_TREE_DEPTH};

fn reason(path_length: u32, sibling_count: usize) -> Option<ZkErrorReason> {
    validate_claim_path_shape(path_length, sibling_count)
        .err()
        .map(|error| error.reason())
}

#[test]
fn only_the_fixed_depth_is_a_claim_tree_depth() {
    assert_eq!(CLAIM_TREE_DEPTH, 6);
    assert!(is_claim_tree_depth(6));
    for rejected in [0_usize, 1, 5, 7, usize::MAX] {
        assert!(!is_claim_tree_depth(rejected));
    }
}

#[test]
fn full_depth_path_is_accepted() {
    assert_eq!(reason(6, 6), None);
}

#[test]
fn short_paths_are_malformed() {
    for short in [0_u32, 1, 5] {
        let sibling_count = usize::try_from(short).unwrap_or(usize::MAX);
        assert_eq!(
            reason(short, sibling_count),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
}

#[test]
fn declared_length_and_sibling_count_must_both_be_the_fixed_depth() {
    assert_eq!(reason(6, 5), Some(ZkErrorReason::InvalidProofEncoding));
    assert_eq!(reason(5, 6), Some(ZkErrorReason::InvalidProofEncoding));
    assert_eq!(reason(0, 6), Some(ZkErrorReason::InvalidProofEncoding));
    assert_eq!(reason(6, 0), Some(ZkErrorReason::InvalidProofEncoding));
}

#[test]
fn over_depth_paths_keep_the_bounded_size_error() {
    assert_eq!(reason(7, 7), Some(ZkErrorReason::ClaimPayloadTooLarge));
    assert_eq!(reason(7, 6), Some(ZkErrorReason::ClaimPayloadTooLarge));
    assert_eq!(reason(6, 7), Some(ZkErrorReason::ClaimPayloadTooLarge));
    assert_eq!(
        reason(u32::MAX, 6),
        Some(ZkErrorReason::ClaimPayloadTooLarge)
    );
}
