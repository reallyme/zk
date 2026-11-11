// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WitnessError, WitnessErrorReason};

mod artifact;
mod common_credential_root;
mod constants;
mod primitives;
mod secret;
pub use artifact::{
    CompiledProgramArtifactJson, SerializedWitnessStack, MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES,
};
pub use common_credential_root::{
    CommonCredentialRootLineageCredentialWitness, CommonCredentialRootLineagePublicSlot,
    CommonCredentialRootStatusIndex, CommonCredentialRootStatusPath,
    CommonCredentialRootStatusPathLength,
};
pub use constants::{
    CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32, FIELD_ELEMENT_BYTES, FIELD_ELEMENT_BYTES_U32,
    MAX_CLAIM_VALUE_BYTES, MAX_CLAIM_VALUE_BYTES_U32, MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH,
    MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH_U32, SALT_BYTES, SALT_BYTES_U32, SIGNATURE_BYTES,
    SIGNATURE_BYTES_U32,
};
pub use primitives::{
    ActiveStatusRoot, AssurancePolicyId, AttestationId, AttestationJoinHash, AudienceHash,
    ChallengeNonceHash, ClaimBundleHash, ClaimNameHash, ClaimSalt, CredentialBindingHash,
    EnvelopeBindingHash, EnvelopeHash, IssuerRootBindingSignature, IssuerSignature,
    IssuerSubjectBindingSignature, JoinSalt, MerkleRoot, P256Coordinate, P256PublicKey,
    PersonaFreshSignature, PersonaSignature, RelationshipDidHash, RelationshipNonce,
    RootCommitment, RootJoinHash, SessionBindingHash, SubjectJoinHash, SubjectLinkSignature,
    SubjectSignature, TransactionDataHash,
};
pub use secret::SecretInputs;

#[derive(PartialEq, Eq)]
pub struct UnixTimestamp(u64);

impl UnixTimestamp {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }
}

impl Zeroize for UnixTimestamp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for UnixTimestamp {}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AttestationEpoch(u32);

impl AttestationEpoch {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimValueLength(u32);

impl ClaimValueLength {
    pub fn new(value: u32) -> Result<Self, WitnessError> {
        if usize::try_from(value)
            .ok()
            .is_some_and(|value_as_usize| value_as_usize <= MAX_CLAIM_VALUE_BYTES)
        {
            Ok(Self(value))
        } else {
            Err(WitnessError::new(
                WitnessErrorReason::ClaimValueLengthOutOfRange,
            ))
        }
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

/// Length of a credential claim-tree path. Every claim tree has the fixed
/// depth [`CLAIM_TREE_DEPTH`], so this is the only accepted value.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MerklePathLength(u32);

impl MerklePathLength {
    pub fn new(value: u32) -> Result<Self, WitnessError> {
        if usize::try_from(value)
            .ok()
            .is_some_and(|value_as_usize| value_as_usize == CLAIM_TREE_DEPTH)
        {
            Ok(Self(value))
        } else {
            Err(WitnessError::new(
                WitnessErrorReason::MerklePathLengthOutOfRange,
            ))
        }
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MerkleLeafIndex(u32);

impl MerkleLeafIndex {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimBundleCount<const MAX: usize>(u32);

impl<const MAX: usize> ClaimBundleCount<MAX> {
    pub fn new(value: u32) -> Result<Self, WitnessError> {
        if usize::try_from(value)
            .ok()
            .is_some_and(|value_as_usize| value_as_usize <= MAX)
        {
            Ok(Self(value))
        } else {
            Err(WitnessError::new(
                WitnessErrorReason::ClaimBundleCountOutOfRange,
            ))
        }
    }

    pub const fn value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimValue {
    bytes: [u8; MAX_CLAIM_VALUE_BYTES],
    length: ClaimValueLength,
}

impl ClaimValue {
    pub fn new(bytes: [u8; MAX_CLAIM_VALUE_BYTES], length: ClaimValueLength) -> Self {
        Self { bytes, length }
    }

    pub const fn as_bytes(&self) -> &[u8; MAX_CLAIM_VALUE_BYTES] {
        &self.bytes
    }

    pub const fn length(&self) -> &ClaimValueLength {
        &self.length
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MerkleSiblingHash([u8; FIELD_ELEMENT_BYTES]);

impl MerkleSiblingHash {
    pub const fn new(bytes: [u8; FIELD_ELEMENT_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; FIELD_ELEMENT_BYTES] {
        &self.0
    }
}

/// Full-depth credential claim-tree path. The length is always
/// [`CLAIM_TREE_DEPTH`] because [`MerklePathLength`] admits no other value.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MerklePath {
    siblings: [MerkleSiblingHash; CLAIM_TREE_DEPTH],
    length: MerklePathLength,
}

impl MerklePath {
    pub fn new(siblings: [MerkleSiblingHash; CLAIM_TREE_DEPTH], length: MerklePathLength) -> Self {
        Self { siblings, length }
    }

    pub const fn siblings(&self) -> &[MerkleSiblingHash; CLAIM_TREE_DEPTH] {
        &self.siblings
    }

    pub const fn length(&self) -> &MerklePathLength {
        &self.length
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct IssuerBoundContext {
    pub issuer_public_key: P256PublicKey,
    pub challenge_nonce_hash: ChallengeNonceHash,
    pub audience_hash: AudienceHash,
    pub transaction_data_hash: TransactionDataHash,
    pub expiry_unix: UnixTimestamp,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionContext {
    pub challenge_nonce_hash: ChallengeNonceHash,
    pub audience_hash: AudienceHash,
    pub transaction_data_hash: TransactionDataHash,
    pub expiry_unix: UnixTimestamp,
    pub session_binding_hash: SessionBindingHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimDisclosure {
    pub credential_binding_hash: CredentialBindingHash,
    pub claim_value: ClaimValue,
    pub claim_name_hash: ClaimNameHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MerkleClaimProof {
    pub envelope_hash: EnvelopeHash,
    pub merkle_root: MerkleRoot,
    pub claim_salt: ClaimSalt,
    pub merkle_leaf_index: MerkleLeafIndex,
    pub merkle_path: MerklePath,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimBundleEntry {
    pub claim_value: ClaimValue,
    pub claim_name_hash: ClaimNameHash,
    pub claim_salt: ClaimSalt,
    pub merkle_leaf_index: MerkleLeafIndex,
    /// Full-depth claim path for an active bundle slot. An unused slot carries
    /// no path; the circuit requires its path length and siblings to be zero.
    pub merkle_path: Option<MerklePath>,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimBundleProof<const BUNDLE_SIZE: usize> {
    pub envelope_hash: EnvelopeHash,
    pub merkle_root: MerkleRoot,
    pub entries: [ClaimBundleEntry; BUNDLE_SIZE],
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EnvelopeSignatureProof {
    pub envelope_hash: EnvelopeHash,
    pub issuer_signature: IssuerSignature,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialRootProof {
    pub envelope_hash: EnvelopeHash,
    pub merkle_root: MerkleRoot,
    pub issuer_root_binding_signature: IssuerRootBindingSignature,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SubjectClaimLink {
    pub issuer_subject_binding_signature: IssuerSubjectBindingSignature,
    pub subject_public_key: P256PublicKey,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaClaimLink {
    pub issuer_subject_binding_signature: IssuerSubjectBindingSignature,
    pub subject_public_key: P256PublicKey,
    pub persona_public_key: P256PublicKey,
    pub subject_link_signature: SubjectLinkSignature,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PublicPersonaClaimLink {
    pub issuer_subject_binding_signature: IssuerSubjectBindingSignature,
    pub subject_public_key: P256PublicKey,
    pub subject_link_signature: SubjectLinkSignature,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SubjectSessionAuthorization {
    pub subject_public_key: P256PublicKey,
    pub subject_signature: SubjectSignature,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaSessionAuthorization {
    pub persona_public_key: P256PublicKey,
    pub persona_signature: PersonaSignature,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PublicPersonaSessionAuthorization {
    pub persona_fresh_signature: PersonaFreshSignature,
}

#[cfg(test)]
mod tests;
