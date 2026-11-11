// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local Wallet inventory selector for a prepared claim and one-time copy.
//!
//! This digest is never a proof or a verifier-visible identifier. It lets an
//! encrypted Wallet store reject a mismatched claim before its durable burn.

use crypto_sha2_256::digest as sha2_256_digest;
use zeroize::Zeroizing;

use crate::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
};

const DOMAIN: &[u8] = b"reallyme/prepared-claim-selector/v1\0";
const MAX_COPY_ID_BYTES: usize = 256;
const MAX_CLAIM_VALUE_BYTES: usize = 64;
const HASH_BYTES: usize = 32;

/// Derive a copy-scoped selector from the exact disclosed claim.
///
/// The copy ID is an authenticated local inventory identifier. The hash lane
/// is included because identical claim bytes can appear in different proof
/// systems. The output must stay inside protected Wallet inventory metadata.
pub fn persona_credential_evidence_claim_selector_digest(
    copy_id: &str,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    claim_name_hash: &[u8; HASH_BYTES],
    claim_value: &[u8],
) -> Result<[u8; HASH_BYTES], ZkError> {
    if copy_id.is_empty() || copy_id.len() > MAX_COPY_ID_BYTES {
        return Err(ZkError::new(ZkErrorReason::InvalidPublicInputName));
    }
    if claim_value.is_empty() || claim_value.len() > MAX_CLAIM_VALUE_BYTES {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    let lane = match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => 1_u8,
        ZkCredentialHashAlgorithm::Poseidon2 => 2_u8,
    };
    let capacity = DOMAIN
        .len()
        .checked_add(2)
        .and_then(|length| length.checked_add(copy_id.len()))
        .and_then(|length| length.checked_add(1 + HASH_BYTES + 1))
        .and_then(|length| length.checked_add(claim_value.len()))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut preimage = Zeroizing::new(Vec::new());
    preimage
        .try_reserve_exact(capacity)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    preimage.extend_from_slice(DOMAIN);
    let copy_length =
        u16::try_from(copy_id.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    preimage.extend_from_slice(&copy_length.to_be_bytes());
    preimage.extend_from_slice(copy_id.as_bytes());
    preimage.push(lane);
    preimage.extend_from_slice(claim_name_hash);
    let value_length =
        u8::try_from(claim_value.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    preimage.push(value_length);
    preimage.extend_from_slice(claim_value);
    Ok(sha2_256_digest(preimage.as_slice()).into_bytes())
}

#[cfg(test)]
#[path = "persona_credential_evidence_claim_selector/tests.rs"]
mod tests;
