// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-private claim openings encoded only inside an encrypted record.

use buffa::{DecodeOptions, EnumValue, Message};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{ZkCommonCredentialRootClaimOpening, ZkCommonCredentialRootClaimsCommitment},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FORMAT_VERSION: u32 = 1;
const DIGEST_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const MAX_OPENINGS: usize = 64;
const MAX_ENCODED_BYTES: usize = 32 * 1024;
const PROTO_RECURSION_LIMIT: u32 = 16;

// Buffa owns separate Vec allocations for every decoded value and salt. Wipe
// those allocations on every return path, including malformed-record errors.
struct SensitivePreparedClaimsMessage(pb::ZkCommonCredentialRootPreparedClaims);

impl Drop for SensitivePreparedClaimsMessage {
    fn drop(&mut self) {
        self.0.claim_root.zeroize();
        self.0.issuance_binding.zeroize();
        for opening in &mut self.0.openings {
            opening.claim_name_hash.zeroize();
            opening.claim_value.zeroize();
            opening.claim_salt.zeroize();
            for sibling in &mut opening.siblings {
                sibling.value.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for SensitivePreparedClaimsMessage {}

/// Stable failure reasons for private wallet material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootClaimsReason {
    /// The protected protobuf was malformed or outside the bounded persona_mode.
    #[error("invalid protected claim material")]
    InvalidEncoding,
    /// This private material belongs to a different signed credential.
    #[error("credential binding mismatch")]
    BindingMismatch,
    /// An opening did not reconstruct the authenticated issuer root.
    #[error("claim opening mismatch")]
    OpeningMismatch,
}

/// Redacted error from protected claim-material conversion.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("protected claims conversion failed: {reason}")]
pub struct ZkCommonCredentialRootClaimsError {
    reason: ZkCommonCredentialRootClaimsReason,
}

impl ZkCommonCredentialRootClaimsError {
    /// Return a stable, non-sensitive reason code.
    #[must_use]
    pub const fn reason(self) -> ZkCommonCredentialRootClaimsReason {
        self.reason
    }
}

const fn invalid(reason: ZkCommonCredentialRootClaimsReason) -> ZkCommonCredentialRootClaimsError {
    ZkCommonCredentialRootClaimsError { reason }
}

/// Encode a holder-prepared claim tree for encryption by the Wallet. The
/// issuance binding is verified again on decryption, after issuer receipt
/// validation has authenticated it.
pub fn encode_prepared_claims(
    claims: &ZkCommonCredentialRootClaimsCommitment,
    issuance_binding: [u8; DIGEST_BYTES],
) -> Result<Zeroizing<Vec<u8>>, ZkCommonCredentialRootClaimsError> {
    if issuance_binding.iter().all(|byte| *byte == 0)
        || claims.openings().len() < 2
        || claims.openings().len() > MAX_OPENINGS
    {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
    }
    let openings = claims
        .openings()
        .iter()
        .map(|opening| {
            let siblings = opening
                .siblings()
                .iter()
                .map(|sibling| {
                    let mut message = pb::ZkInputBytes32::default();
                    message.value = sibling.to_vec();
                    message
                })
                .collect();
            let mut message = pb::ZkCommonCredentialRootPrivateClaimOpening::default();
            message.claim_name_hash = opening.name_hash().to_vec();
            message.claim_value = opening.value().to_vec();
            message.claim_salt = opening.salt().to_vec();
            message.leaf_index = opening.leaf_index();
            message.siblings = siblings;
            message
        })
        .collect();
    let mut message =
        SensitivePreparedClaimsMessage(pb::ZkCommonCredentialRootPreparedClaims::default());
    message.0.format_version = FORMAT_VERSION;
    message.0.claim_root = claims.root().to_vec();
    message.0.issuance_binding = issuance_binding.to_vec();
    message.0.openings = openings;
    message.0.credential_hash_algorithm =
        EnumValue::from(match claims.credential_hash_algorithm() {
            ZkCredentialHashAlgorithm::Sha256 => {
                pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256
            }
            ZkCredentialHashAlgorithm::Poseidon2 => {
                pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
            }
            _ => return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding)),
        });
    let bytes = Zeroizing::new(message.0.encode_to_vec());
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
    }
    Ok(bytes)
}

/// Decode only after wallet storage has authenticated and decrypted the
/// record. Both expected values come from the validated issuer receipt.
pub fn decode_prepared_claims(
    bytes: &[u8],
    issuer_root: [u8; DIGEST_BYTES],
    issuance_binding: [u8; DIGEST_BYTES],
) -> Result<ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootClaimsError> {
    decode_prepared_claims_for_lane(
        bytes,
        ZkCredentialHashAlgorithm::Sha256,
        issuer_root,
        issuance_binding,
    )
}

/// Restore private openings only under the hash lane authenticated by the
/// issuer receipt. The encrypted record cannot choose its own interpretation.
pub fn decode_prepared_claims_for_lane(
    bytes: &[u8],
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    issuer_root: [u8; DIGEST_BYTES],
    issuance_binding: [u8; DIGEST_BYTES],
) -> Result<ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootClaimsError> {
    if bytes.is_empty() || bytes.len() > MAX_ENCODED_BYTES {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
    }
    let mut message = SensitivePreparedClaimsMessage(
        DecodeOptions::new()
            .with_recursion_limit(PROTO_RECURSION_LIMIT)
            .with_element_memory_limit(MAX_ENCODED_BYTES)
            .with_max_message_size(MAX_ENCODED_BYTES)
            .with_unknown_field_limit(0)
            .decode_from_slice::<pb::ZkCommonCredentialRootPreparedClaims>(bytes)
            .map_err(|_| invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding))?,
    );
    if Zeroizing::new(message.0.encode_to_vec()).as_slice() != bytes {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
    }
    if message.0.format_version != FORMAT_VERSION
        || message.0.openings.len() < 2
        || message.0.openings.len() > MAX_OPENINGS
    {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
    }
    if message.0.claim_root.as_slice() != issuer_root
        || message.0.issuance_binding.as_slice() != issuance_binding
    {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::BindingMismatch));
    }
    let stored_credential_hash_algorithm = match message.0.credential_hash_algorithm.as_known() {
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256) => {
            ZkCredentialHashAlgorithm::Sha256
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2) => {
            ZkCredentialHashAlgorithm::Poseidon2
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED) | None => {
            return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
        }
    };
    if stored_credential_hash_algorithm != expected_credential_hash_algorithm {
        return Err(invalid(ZkCommonCredentialRootClaimsReason::BindingMismatch));
    }
    let mut openings = Vec::new();
    openings
        .try_reserve_exact(message.0.openings.len())
        .map_err(|_| invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding))?;
    for opening in &mut message.0.openings {
        if !crate::claim_tree::is_claim_tree_depth(opening.siblings.len()) {
            return Err(invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding));
        }
        let name_hash = fixed::<DIGEST_BYTES>(&opening.claim_name_hash)?;
        let salt = fixed::<SALT_BYTES>(&opening.claim_salt)?;
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(opening.siblings.len())
            .map_err(|_| invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding))?;
        for sibling in &opening.siblings {
            siblings.push(fixed::<DIGEST_BYTES>(&sibling.value)?);
        }
        openings.push(ZkCommonCredentialRootClaimOpening::restore(
            name_hash,
            core::mem::take(&mut opening.claim_value),
            salt,
            opening.leaf_index,
            siblings,
        ));
    }
    ZkCommonCredentialRootClaimsCommitment::restore_verified_for_lane(
        expected_credential_hash_algorithm,
        issuer_root,
        openings,
    )
    .map_err(|_| invalid(ZkCommonCredentialRootClaimsReason::OpeningMismatch))
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], ZkCommonCredentialRootClaimsError> {
    value
        .try_into()
        .map_err(|_| invalid(ZkCommonCredentialRootClaimsReason::InvalidEncoding))
}

#[cfg(test)]
#[path = "common_credential_root_private_claims/tests.rs"]
mod tests;
