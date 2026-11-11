// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict post-manifest verification-vector conversion and mutation execution.

use buffa::Message;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::Digest32;
use zeroize::Zeroizing;

use crate::{
    operation::{ZkProviderOperation, MAX_ZK_PROTO_OPERATION_BYTES},
    release::ReleaseArtifactPin,
};

/// Exact verification-vector format accepted by this codec.
pub const VERIFICATION_VECTOR_FORMAT_VERSION: u32 = 1;
/// Maximum canonical verification-vector-set bytes.
pub const MAX_ZK_VERIFICATION_VECTOR_SET_BYTES: usize =
    MAX_ZK_PROTO_OPERATION_BYTES + (4 * 1024 * 1024);

const VERIFICATION_VECTOR_RECURSION_LIMIT: u32 = 32;
const VERIFICATION_VECTOR_UNKNOWN_FIELD_LIMIT: usize = 0;
const VERIFICATION_VECTOR_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_VERIFICATION_VECTOR_SET_BYTES;
const ARTIFACTS_PER_VECTOR_SET: usize = 4;

/// Computes the exact request commitment for one canonical vector mutation.
///
/// The input must itself be a canonical provider operation. The returned
/// digest names the post-mutation bytes actually presented to preflight or the
/// provider, so expected outcomes cannot be cross-paired between vectors.
pub fn verification_request_sha256(
    base_operation_bytes: &[u8],
    mutation: VerificationVectorMutation,
) -> Result<Digest32, ZkError> {
    let _validated = crate::operation::decode_operation_request(base_operation_bytes)?;
    let mut request = decode_base_operation(base_operation_bytes)?;
    apply_mutation(&mut request, mutation)?;
    let effective = Zeroizing::new(request.encode_to_vec());
    Ok(Digest32::sha256(&effective))
}

/// Validated real-proof input for one canonical post-manifest bundle vector set.
///
/// This value borrows proof material and therefore implements neither `Debug`
/// nor `Clone`; concrete proof bytes should not enter incidental diagnostics.
pub struct ClaimProofBundleVerificationVectorInput<'a> {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    claim_proof_bundle: &'a ZkClaimProofBundle,
    artifact_manifests: [ReleaseArtifactPin; ARTIFACTS_PER_VECTOR_SET],
}

impl<'a> ClaimProofBundleVerificationVectorInput<'a> {
    /// Requires canonical stage order and exact proof-to-manifest identity.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        claim_proof_bundle: &'a ZkClaimProofBundle,
        artifact_manifests: [ReleaseArtifactPin; ARTIFACTS_PER_VECTOR_SET],
    ) -> Result<Self, ZkError> {
        Self::try_new_for_suite(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            claim_proof_bundle,
            artifact_manifests,
        )
    }

    /// Requires exact suite identity in the bundle and every stage proof.
    pub fn try_new_for_suite(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        claim_proof_bundle: &'a ZkClaimProofBundle,
        artifact_manifests: [ReleaseArtifactPin; ARTIFACTS_PER_VECTOR_SET],
    ) -> Result<Self, ZkError> {
        if claim_proof_bundle.bundle_kind() != bundle_kind
            || claim_proof_bundle.proof_suite() != proof_suite
            || claim_proof_bundle.stage_proofs().len() != ARTIFACTS_PER_VECTOR_SET
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        for ((expected_stage, stage_proof), manifest) in ZkClaimProofBundleStage::ALL
            .iter()
            .zip(claim_proof_bundle.stage_proofs())
            .zip(&artifact_manifests)
        {
            let expected_ref = bundle_kind.source_ref(credential_hash_algorithm, *expected_stage);
            if stage_proof.bundle_kind() != bundle_kind
                || stage_proof.stage() != *expected_stage
                || stage_proof.proof().circuit_ref() != expected_ref
                || stage_proof.proof().proof_suite() != proof_suite
                || stage_proof.proof().artifact_identity() != manifest.manifest_sha256().into()
                || manifest.bundle_kind() != bundle_kind
                || manifest.stage() != *expected_stage
                || manifest.circuit_ref() != expected_ref
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
        }
        Ok(Self {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            claim_proof_bundle,
            artifact_manifests,
        })
    }
}

mod encoding;
pub use encoding::encode_claim_proof_bundle_verification_vector_set;

/// Closed deterministic mutation supported by verification conformance lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationVectorMutation {
    /// Execute the valid base verification operation unchanged.
    None,
    /// Remove proof bytes.
    EmptyProof,
    /// Grow one proof beyond the API bound.
    ProofTooLarge,
    /// Flip one proof byte while preserving structural validity.
    TamperedProof,
    /// Replace compact public inputs with an invalid encoding.
    MalformedPublicInputs,
    /// Mismatch the verifier nonce.
    WrongNonce,
    /// Mismatch the verifier audience.
    WrongAudience,
    /// Change expected transaction data while retaining original public inputs.
    WrongTransactionData,
    /// Replace the verifier trust list with a different nonzero issuer key.
    UntrustedIssuer,
    /// Advance verifier time to the presentation expiry boundary.
    PresentationExpired,
    /// Set unsupported v1 credential-status policy evidence.
    CredentialStatusPresent,
    /// Mutate the bundle-level session binding while retaining stage public inputs.
    WrongBundleSessionBinding,
    /// Replace one sealed artifact-manifest identity.
    StaleArtifactManifest,
    /// Select an unsupported source-circuit version.
    UnsupportedCircuitRevision,
    /// Duplicate one production bundle stage.
    DuplicateStage,
    /// Remove one production bundle stage.
    MissingStage,
    /// Relabel one proof as the wrong production stage.
    WrongStage,
    /// Move one bundle proof to the other hash lane.
    MixedHashLane,
}

impl VerificationVectorMutation {
    /// Exact ordered mutation catalog required by bundle conformance evidence.
    pub const BUNDLE_CONFORMANCE: &'static [Self] = &[
        Self::None,
        Self::EmptyProof,
        Self::ProofTooLarge,
        Self::TamperedProof,
        Self::MalformedPublicInputs,
        Self::WrongNonce,
        Self::WrongAudience,
        Self::WrongTransactionData,
        Self::UntrustedIssuer,
        Self::PresentationExpired,
        Self::CredentialStatusPresent,
        Self::WrongBundleSessionBinding,
        Self::StaleArtifactManifest,
        Self::UnsupportedCircuitRevision,
        Self::DuplicateStage,
        Self::MissingStage,
        Self::WrongStage,
        Self::MixedHashLane,
    ];
}

/// Expected validated provider response for one verification vector.
pub enum ExpectedVerificationOutcome {
    /// Successful exact stage verification.
    Stage(crate::result::ZkStageVerificationReport),
    /// Successful complete production-bundle verification.
    Bundle(Box<crate::result::ZkClaimProofBundleVerificationReport>),
    /// Exact typed failure expected from preflight or provider execution.
    Error(ZkError),
}

/// One validated post-manifest verification vector.
///
/// This owner intentionally implements neither `Debug` nor `Clone`; its
/// encoded operation retains concrete proof bytes in zeroizing storage.
pub struct VerificationVector {
    number: u32,
    mutation: VerificationVectorMutation,
    encoded_base_operation: Zeroizing<Vec<u8>>,
    expected_outcome: ExpectedVerificationOutcome,
}

impl VerificationVector {
    /// Stable one-based number within the set.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }
    /// Typed deterministic mutation.
    #[must_use]
    pub const fn mutation(&self) -> VerificationVectorMutation {
        self.mutation
    }
    /// Expected provider response after mutation.
    #[must_use]
    pub const fn expected_outcome(&self) -> &ExpectedVerificationOutcome {
        &self.expected_outcome
    }

    /// Applies the mutation and re-enters the canonical operation boundary.
    ///
    /// Structurally valid proof mutations return an operation for the injected
    /// provider; preflight-invalid mutations return their typed boundary error.
    pub fn execute(&self) -> Result<ZkProviderOperation, ZkError> {
        if self.mutation == VerificationVectorMutation::None {
            return crate::operation::decode_operation_request(&self.encoded_base_operation);
        }
        let mut request = decode_base_operation(&self.encoded_base_operation)?;
        apply_mutation(&mut request, self.mutation)?;
        let mutated = Zeroizing::new(request.encode_to_vec());
        crate::operation::decode_operation_request(&mutated)
    }
}

/// Validated post-manifest vectors for one bundle_kind and hash lane.
pub struct VerificationVectorSet {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    artifact_manifests: Vec<ReleaseArtifactPin>,
    vectors: Vec<VerificationVector>,
}

impl VerificationVectorSet {
    /// Production bundle_kind shared by the set.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }
    /// Hash lane shared by the set.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }
    /// Exact production proof suite.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }
    /// Four sealed stage manifests in production order.
    #[must_use]
    pub fn artifact_manifests(&self) -> &[ReleaseArtifactPin] {
        &self.artifact_manifests
    }
    /// Canonically numbered verification vectors.
    #[must_use]
    pub fn vectors(&self) -> &[VerificationVector] {
        &self.vectors
    }
    /// Consumes the set into its proof-bearing vector owners.
    #[must_use]
    pub fn into_vectors(self) -> Vec<VerificationVector> {
        self.vectors
    }
}

mod decoding;
mod mutation;
pub use decoding::decode_verification_vector_set;
use mutation::{apply_mutation, decode_base_operation};
