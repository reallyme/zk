// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ClaimBundleCount, ClaimValueLength, CommonCredentialRootStatusPathLength, MerklePathLength,
    SecretInputs, CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32,
};
use crate::WitnessErrorReason;

#[test]
fn fixed_capacity_lengths_accept_boundaries() -> Result<(), crate::WitnessError> {
    ClaimValueLength::new(0)?;
    ClaimValueLength::new(64)?;
    MerklePathLength::new(6)?;
    CommonCredentialRootStatusPathLength::new(0)?;
    CommonCredentialRootStatusPathLength::new(20)?;
    ClaimBundleCount::<4>::new(0)?;
    ClaimBundleCount::<4>::new(4)?;
    Ok(())
}

#[test]
fn fixed_capacity_lengths_reject_values_above_capacity() {
    assert_eq!(
        ClaimValueLength::new(65).err().map(|error| error.reason),
        Some(WitnessErrorReason::ClaimValueLengthOutOfRange)
    );
    assert_eq!(
        MerklePathLength::new(7).err().map(|error| error.reason),
        Some(WitnessErrorReason::MerklePathLengthOutOfRange)
    );
    assert_eq!(
        CommonCredentialRootStatusPathLength::new(21)
            .err()
            .map(|error| error.reason),
        Some(WitnessErrorReason::CommonCredentialRootStatusPathLengthOutOfRange)
    );
    assert_eq!(
        ClaimBundleCount::<4>::new(5)
            .err()
            .map(|error| error.reason),
        Some(WitnessErrorReason::ClaimBundleCountOutOfRange)
    );
}

#[test]
fn claim_path_length_accepts_only_the_fixed_claim_tree_depth() -> Result<(), crate::WitnessError> {
    assert_eq!(CLAIM_TREE_DEPTH, 6);
    assert_eq!(usize::try_from(CLAIM_TREE_DEPTH_U32), Ok(CLAIM_TREE_DEPTH));
    assert_eq!(
        MerklePathLength::new(CLAIM_TREE_DEPTH_U32)?.value(),
        CLAIM_TREE_DEPTH_U32
    );
    for rejected in [0_u32, 1, 5, 7, u32::MAX] {
        assert_eq!(
            MerklePathLength::new(rejected)
                .err()
                .map(|error| error.reason),
            Some(WitnessErrorReason::MerklePathLengthOutOfRange)
        );
    }
    Ok(())
}

#[test]
fn secret_inputs_debug_never_exposes_the_inner_value() {
    let secret = SecretInputs::new([17_u8, 23_u8, 42_u8]);
    let debug = format!("{secret:?}");

    assert_eq!(debug, "SecretInputs([REDACTED])");
}
