// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::InputMap;

use crate::domain::{
    ClaimBundleCount, ClaimBundleProof, CLAIM_TREE_DEPTH, FIELD_ELEMENT_BYTES,
    MAX_CLAIM_VALUE_BYTES, SALT_BYTES,
};
use crate::{WitnessError, WitnessErrorReason};
use zeroize::Zeroizing;

use super::{
    insert_byte_array_matrix_input, insert_byte_array_tensor_input, insert_envelope_hash,
    insert_merkle_root, insert_u32_array_input,
};

pub(crate) struct ClaimBundleProofFieldNames {
    pub envelope_hash_name: &'static str,
    pub merkle_root_name: &'static str,
    pub value_lengths_name: &'static str,
    pub value_bytes_name: &'static str,
    pub name_hashes_name: &'static str,
    pub salts_name: &'static str,
    pub indices_name: &'static str,
    pub path_lengths_name: &'static str,
    pub paths_name: &'static str,
}

/// Path length the circuit requires for a bundle slot that carries no claim.
const UNUSED_BUNDLE_SLOT_PATH_LENGTH: u32 = 0;

/// Requires every active bundle slot to carry a full-depth claim path and
/// every unused slot to carry none, so a malformed bundle is rejected before
/// any witness execution.
pub(crate) fn validate_claim_bundle_slot_paths<const BUNDLE_SIZE: usize>(
    bundle_count: &ClaimBundleCount<BUNDLE_SIZE>,
    proof: &ClaimBundleProof<BUNDLE_SIZE>,
) -> Result<(), WitnessError> {
    let active_slots = usize::try_from(bundle_count.value())
        .map_err(|_| WitnessError::new(WitnessErrorReason::ClaimBundleCountOutOfRange))?;
    for (slot, entry) in proof.entries.iter().enumerate() {
        if entry.merkle_path.is_some() != (slot < active_slots) {
            return Err(WitnessError::new(
                WitnessErrorReason::MerklePathLengthOutOfRange,
            ));
        }
    }
    Ok(())
}

pub(crate) fn insert_claim_bundle_proof<const BUNDLE_SIZE: usize>(
    input_map: &mut InputMap,
    field_names: ClaimBundleProofFieldNames,
    proof: &ClaimBundleProof<BUNDLE_SIZE>,
) {
    insert_envelope_hash(
        input_map,
        field_names.envelope_hash_name,
        &proof.envelope_hash,
    );
    insert_merkle_root(input_map, field_names.merkle_root_name, &proof.merkle_root);

    let value_lengths: [u32; BUNDLE_SIZE] =
        std::array::from_fn(|index| proof.entries[index].claim_value.length().value());
    let mut value_bytes = Zeroizing::new([[0_u8; MAX_CLAIM_VALUE_BYTES]; BUNDLE_SIZE]);
    let mut name_hashes = Zeroizing::new([[0_u8; FIELD_ELEMENT_BYTES]; BUNDLE_SIZE]);
    let mut salts = Zeroizing::new([[0_u8; SALT_BYTES]; BUNDLE_SIZE]);
    let indices: [u32; BUNDLE_SIZE] =
        std::array::from_fn(|index| proof.entries[index].merkle_leaf_index.value());
    let path_lengths: [u32; BUNDLE_SIZE] = std::array::from_fn(|index| {
        proof.entries[index]
            .merkle_path
            .as_ref()
            .map_or(UNUSED_BUNDLE_SLOT_PATH_LENGTH, |path| path.length().value())
    });
    let mut paths: Zeroizing<[[[u8; FIELD_ELEMENT_BYTES]; CLAIM_TREE_DEPTH]; BUNDLE_SIZE]> =
        Zeroizing::new([[[0_u8; FIELD_ELEMENT_BYTES]; CLAIM_TREE_DEPTH]; BUNDLE_SIZE]);
    for (index, entry) in proof.entries.iter().enumerate() {
        value_bytes[index].copy_from_slice(entry.claim_value.as_bytes());
        name_hashes[index].copy_from_slice(entry.claim_name_hash.as_bytes());
        salts[index].copy_from_slice(entry.claim_salt.as_bytes());
        for (target, source) in paths[index].iter_mut().zip(
            entry
                .merkle_path
                .iter()
                .flat_map(|path| path.siblings().iter()),
        ) {
            target.copy_from_slice(source.as_bytes());
        }
    }

    insert_u32_array_input(input_map, field_names.value_lengths_name, value_lengths);
    insert_byte_array_matrix_input(input_map, field_names.value_bytes_name, &value_bytes);
    insert_byte_array_matrix_input(input_map, field_names.name_hashes_name, &name_hashes);
    insert_byte_array_matrix_input(input_map, field_names.salts_name, &salts);
    insert_u32_array_input(input_map, field_names.indices_name, indices);
    insert_u32_array_input(input_map, field_names.path_lengths_name, path_lengths);
    insert_byte_array_tensor_input(input_map, field_names.paths_name, &paths);
}

#[cfg(test)]
#[path = "claim_bundle/tests.rs"]
mod tests;
