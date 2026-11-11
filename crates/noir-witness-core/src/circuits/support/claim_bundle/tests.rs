// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::validate_claim_bundle_slot_paths;
use crate::domain::{
    ClaimBundleCount, ClaimBundleEntry, ClaimBundleProof, ClaimNameHash, ClaimSalt, ClaimValue,
    ClaimValueLength, EnvelopeHash, MerkleLeafIndex, MerklePath, MerklePathLength, MerkleRoot,
    MerkleSiblingHash, CLAIM_TREE_DEPTH_U32, FIELD_ELEMENT_BYTES, MAX_CLAIM_VALUE_BYTES,
    SALT_BYTES,
};
use crate::{WitnessError, WitnessErrorReason};

const BUNDLE_SIZE: usize = 4;

fn full_depth_path() -> Result<MerklePath, WitnessError> {
    Ok(MerklePath::new(
        core::array::from_fn(|_| MerkleSiblingHash::new([7_u8; FIELD_ELEMENT_BYTES])),
        MerklePathLength::new(CLAIM_TREE_DEPTH_U32)?,
    ))
}

fn entry(merkle_path: Option<MerklePath>) -> Result<ClaimBundleEntry, WitnessError> {
    Ok(ClaimBundleEntry {
        claim_value: ClaimValue::new([0_u8; MAX_CLAIM_VALUE_BYTES], ClaimValueLength::new(0)?),
        claim_name_hash: ClaimNameHash::new([0_u8; FIELD_ELEMENT_BYTES]),
        claim_salt: ClaimSalt::new([0_u8; SALT_BYTES]),
        merkle_leaf_index: MerkleLeafIndex::new(0),
        merkle_path,
    })
}

fn proof(
    slots_with_path: [bool; BUNDLE_SIZE],
) -> Result<ClaimBundleProof<BUNDLE_SIZE>, WitnessError> {
    let [first, second, third, fourth] = slots_with_path;
    let slot = |has_path: bool| -> Result<ClaimBundleEntry, WitnessError> {
        entry(if has_path {
            Some(full_depth_path()?)
        } else {
            None
        })
    };
    Ok(ClaimBundleProof {
        envelope_hash: EnvelopeHash::new([1_u8; FIELD_ELEMENT_BYTES]),
        merkle_root: MerkleRoot::new([2_u8; FIELD_ELEMENT_BYTES]),
        entries: [slot(first)?, slot(second)?, slot(third)?, slot(fourth)?],
    })
}

fn validate(count: u32, slots_with_path: [bool; BUNDLE_SIZE]) -> Result<(), WitnessError> {
    validate_claim_bundle_slot_paths(
        &ClaimBundleCount::<BUNDLE_SIZE>::new(count)?,
        &proof(slots_with_path)?,
    )
}

#[test]
fn active_slots_carry_full_depth_paths_and_unused_slots_carry_none() -> Result<(), WitnessError> {
    validate(1, [true, false, false, false])?;
    validate(2, [true, true, false, false])?;
    validate(4, [true, true, true, true])?;
    Ok(())
}

#[test]
fn active_slot_without_a_path_is_rejected() {
    for (count, slots) in [
        (1, [false, false, false, false]),
        (2, [true, false, false, false]),
        (4, [true, true, true, false]),
    ] {
        assert_eq!(
            validate(count, slots).err().map(|error| error.reason),
            Some(WitnessErrorReason::MerklePathLengthOutOfRange)
        );
    }
}

#[test]
fn unused_slot_with_a_path_is_rejected() {
    for (count, slots) in [
        (0, [true, false, false, false]),
        (1, [true, true, false, false]),
        (2, [true, true, false, true]),
    ] {
        assert_eq!(
            validate(count, slots).err().map(|error| error.reason),
            Some(WitnessErrorReason::MerklePathLengthOutOfRange)
        );
    }
}
