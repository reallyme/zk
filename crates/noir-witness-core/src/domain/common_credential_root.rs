// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WitnessError, WitnessErrorReason};

use super::{
    ClaimSalt, CredentialBindingHash, EnvelopeHash, IssuerRootBindingSignature, MerkleLeafIndex,
    MerklePath, MerkleRoot, MerkleSiblingHash, P256PublicKey, RelationshipDidHash,
    RelationshipNonce, SubjectJoinHash, UnixTimestamp, MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH,
};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootStatusIndex(u32);

impl CommonCredentialRootStatusIndex {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootStatusPathLength(u32);

impl CommonCredentialRootStatusPathLength {
    pub fn new(value: u32) -> Result<Self, WitnessError> {
        if usize::try_from(value)
            .ok()
            .is_some_and(|value_as_usize| value_as_usize <= MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH)
        {
            Ok(Self(value))
        } else {
            Err(WitnessError::new(
                WitnessErrorReason::CommonCredentialRootStatusPathLengthOutOfRange,
            ))
        }
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootStatusPath {
    siblings: [MerkleSiblingHash; MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH],
    length: CommonCredentialRootStatusPathLength,
}

impl CommonCredentialRootStatusPath {
    pub fn new(
        siblings: [MerkleSiblingHash; MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH],
        length: CommonCredentialRootStatusPathLength,
    ) -> Self {
        Self { siblings, length }
    }

    pub const fn siblings(&self) -> &[MerkleSiblingHash; MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH] {
        &self.siblings
    }

    pub const fn length(&self) -> &CommonCredentialRootStatusPathLength {
        &self.length
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootLineagePublicSlot {
    pub issuer_public_key: P256PublicKey,
    pub expiry_unix: UnixTimestamp,
    pub credential_binding_hash: CredentialBindingHash,
    pub subject_join_hash: SubjectJoinHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootLineageCredentialWitness {
    pub envelope_hash: EnvelopeHash,
    pub merkle_root: MerkleRoot,
    pub issuer_root_binding_signature: IssuerRootBindingSignature,
    pub subject_public_key: P256PublicKey,
    pub relationship_did_hash: RelationshipDidHash,
    pub relationship_nonce: RelationshipNonce,
    pub claim_salt: ClaimSalt,
    pub merkle_leaf_index: MerkleLeafIndex,
    pub merkle_path: MerklePath,
}
