// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::errors::ZkErrorReason;

use super::{claim_path_len, path_len};

#[test]
fn claim_and_lineage_openings_require_the_fixed_claim_tree_depth() {
    assert_eq!(claim_path_len(6).ok(), Some(6));
    for rejected in [0_usize, 1, 5, 7, usize::MAX] {
        assert_eq!(
            claim_path_len(rejected).err().map(|error| error.reason()),
            Some(ZkErrorReason::InvalidProofEncoding)
        );
    }
}

#[test]
fn status_paths_keep_their_own_variable_depth() {
    for accepted in [0_usize, 1, 5, 6, 7, 12, 20] {
        assert_eq!(path_len(accepted).ok(), u32::try_from(accepted).ok());
    }
}
