// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]
// This crate is a publish=false workspace implementation crate. Its public
// structs mirror the audited circuit input names so FFI/package adapters can
// assemble witnesses without stringly typed maps; the canonical API semantics
// remain documented in crates/api and crates/proto rather than duplicated here.
#![allow(missing_docs)]
#![cfg_attr(not(test), warn(unused_crate_dependencies, unused_extern_crates))]

//! Typed ReallyMe Noir witness generation against the pinned modern Noir stack.

use acvm as _;
use serde as _;

mod abi_encoding;
pub mod circuits;
pub mod domain;
mod error;
mod execution;
mod input_cleanup;
mod witness_serialization;

pub use domain::{
    ActiveStatusRoot, AssurancePolicyId, AttestationEpoch, AttestationId, AttestationJoinHash,
    AudienceHash, ChallengeNonceHash, ClaimBundleCount, ClaimBundleEntry, ClaimBundleHash,
    ClaimBundleProof, ClaimDisclosure, ClaimNameHash, ClaimSalt, ClaimValue, ClaimValueLength,
    CommonCredentialRootLineageCredentialWitness, CommonCredentialRootLineagePublicSlot,
    CommonCredentialRootStatusIndex, CommonCredentialRootStatusPath,
    CommonCredentialRootStatusPathLength, CompiledProgramArtifactJson, CredentialBindingHash,
    CredentialRootProof, EnvelopeBindingHash, EnvelopeHash, EnvelopeSignatureProof,
    IssuerBoundContext, IssuerRootBindingSignature, IssuerSignature, IssuerSubjectBindingSignature,
    JoinSalt, MerkleClaimProof, MerkleLeafIndex, MerklePath, MerklePathLength, MerkleRoot,
    MerkleSiblingHash, P256Coordinate, P256PublicKey, PersonaClaimLink, PersonaFreshSignature,
    PersonaSessionAuthorization, PersonaSignature, PublicPersonaClaimLink,
    PublicPersonaSessionAuthorization, RelationshipDidHash, RelationshipNonce, RootCommitment,
    RootJoinHash, SecretInputs, SerializedWitnessStack, SessionBindingHash, SessionContext,
    SubjectClaimLink, SubjectJoinHash, SubjectLinkSignature, SubjectSessionAuthorization,
    SubjectSignature, TransactionDataHash, UnixTimestamp, CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32,
    FIELD_ELEMENT_BYTES, FIELD_ELEMENT_BYTES_U32, MAX_CLAIM_VALUE_BYTES, MAX_CLAIM_VALUE_BYTES_U32,
    MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH, MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH_U32,
    MAX_COMPILED_PROGRAM_ARTIFACT_JSON_BYTES, SALT_BYTES, SALT_BYTES_U32, SIGNATURE_BYTES,
    SIGNATURE_BYTES_U32,
};
pub use error::{WitnessError, WitnessErrorReason};
pub use execution::generate_witness_from_artifact_json_and_toml;
