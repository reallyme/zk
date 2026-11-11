// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed credential claim-tree shape shared by every claim-path admission
//! layer in this crate.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

/// Fixed height of every credential claim tree. The claim circuits accept
/// only paths of exactly this length. Issuer status-list and root active-set
/// trees have their own depths and are not governed by this constant.
pub(crate) const CLAIM_TREE_DEPTH: usize = 6;

/// Returns whether a claim path holds exactly the fixed number of siblings.
pub(crate) const fn is_claim_tree_depth(sibling_count: usize) -> bool {
    sibling_count == CLAIM_TREE_DEPTH
}

/// Requires a typed claim path to declare and carry exactly the fixed depth.
///
/// A path that exceeds the fixed depth keeps the bounded-size error; any
/// other shape is a malformed encoding. Both are rejected before proving.
pub(crate) fn validate_claim_path_shape(
    path_length: u32,
    sibling_count: usize,
) -> Result<(), ZkError> {
    let declared_length =
        usize::try_from(path_length).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if declared_length > CLAIM_TREE_DEPTH || sibling_count > CLAIM_TREE_DEPTH {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    if !is_claim_tree_depth(declared_length) || !is_claim_tree_depth(sibling_count) {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
