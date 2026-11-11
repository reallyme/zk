// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict binary decoding and deterministic execution for proving vectors.

use buffa::Message;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkClaimProofBundleWitness},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofMetadata, ZkProofSuite, ZkPublicInputs, ZkSessionBinding},
};
use zeroize::Zeroizing;

use crate::operation::ZkProviderOperation;

/// Canonical pre-manifest proving-vector format version.
pub const PROVING_VECTOR_FORMAT_VERSION: u32 = 1;

/// Maximum binary size accepted for one proving-vector set.
pub const MAX_ZK_PROVING_VECTOR_SET_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of proving cases in one canonical vector set.
pub const MAX_PROVING_VECTORS: usize = 64;

const VECTOR_RECURSION_LIMIT: u32 = 32;
const VECTOR_UNKNOWN_FIELD_LIMIT: usize = 0;
const VECTOR_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_PROVING_VECTOR_SET_BYTES;
const PRODUCTION_STAGE_COUNT: usize = 4;

/// Public proof-shape material paired with one exact release witness stage.
///
/// This type borrows canonical public inputs and contains no proof or witness
/// bytes. The verification-key digest binds the future proof metadata to the
/// artifact that was used by the verified release cycle.
#[derive(Clone, Copy)]
pub struct StageProvingVectorInput<'a> {
    stage: ZkClaimProofBundleStage,
    verification_key_sha256: [u8; 32],
    public_inputs: &'a ZkPublicInputs,
}

impl<'a> StageProvingVectorInput<'a> {
    /// Validates the exact public-input ABI and active session binding.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        stage: ZkClaimProofBundleStage,
        verification_key_sha256: [u8; 32],
        public_inputs: &'a ZkPublicInputs,
        session_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        session_binding.decode_and_validate(
            bundle_kind.source_ref(credential_hash_algorithm, stage),
            public_inputs,
        )?;
        Ok(Self {
            stage,
            verification_key_sha256,
            public_inputs,
        })
    }
}

/// Validated real-material input for a canonical bundle proving-vector set.
///
/// Witness stacks remain in their zeroizing API owner. Encoding copies them
/// only into hardened generated messages and the returned zeroizing protobuf
/// buffer; no raw witness file or unmanaged intermediate is retained.
pub struct BundleProvingVectorInput<'a> {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    witness_bundle: &'a ZkClaimProofBundleWitness,
    session_binding: ZkSessionBinding,
    stages: [StageProvingVectorInput<'a>; PRODUCTION_STAGE_COUNT],
}

impl<'a> BundleProvingVectorInput<'a> {
    /// Validates complete canonical stage order and exact witness coordinates.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        witness_bundle: &'a ZkClaimProofBundleWitness,
        session_binding: ZkSessionBinding,
        stages: [StageProvingVectorInput<'a>; PRODUCTION_STAGE_COUNT],
    ) -> Result<Self, ZkError> {
        Self::try_new_for_suite(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            witness_bundle,
            session_binding,
            stages,
        )
    }

    /// Validates a complete vector input for one exact proof suite.
    pub fn try_new_for_suite(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        witness_bundle: &'a ZkClaimProofBundleWitness,
        session_binding: ZkSessionBinding,
        stages: [StageProvingVectorInput<'a>; PRODUCTION_STAGE_COUNT],
    ) -> Result<Self, ZkError> {
        if witness_bundle.bundle_kind() != bundle_kind
            || witness_bundle.credential_hash_algorithm() != credential_hash_algorithm
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        for (expected, stage) in ZkClaimProofBundleStage::ALL.iter().zip(&stages) {
            if stage.stage != *expected {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            session_binding.decode_and_validate(
                bundle_kind.source_ref(credential_hash_algorithm, *expected),
                stage.public_inputs,
            )?;
            let _exact_witness = witness_bundle.stage_witness(*expected)?;
        }
        Ok(Self {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            witness_bundle,
            session_binding,
            stages,
        })
    }
}

mod encoding;
pub use encoding::encode_bundle_proving_vector_set;

/// Deterministic mutation applied to a valid base proving operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvingVectorMutation {
    /// Execute the base operation without mutation.
    None,
    /// Remove the required witness bytes.
    EmptyWitness,
    /// Replace the witness with one byte beyond the API limit.
    WitnessTooLarge,
    /// Replace stage public inputs with a non-empty wrong-length encoding.
    MalformedPublicInputs,
    /// Change the expected nonce while retaining the original public inputs.
    WrongNonce,
    /// Change the expected audience while retaining the original public inputs.
    WrongAudience,
    /// Change expected transaction data while retaining original public inputs.
    WrongTransactionData,
    /// Select a circuit version not registered by the v1 API.
    UnsupportedCircuitRevision,
    /// Remove one required witness stack from a production bundle.
    MissingStageWitness,
    /// Swap two witness stacks while retaining their exact circuit references.
    ReorderedStageWitness,
    /// Relabel one stack with another stage's exact circuit reference.
    CrossCircuitWitness,
}

/// Deterministic shape expected from one successful stage proof.
#[derive(Debug, PartialEq, Eq)]
pub struct ExpectedStageProofShape {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    metadata: ZkProofMetadata,
    public_inputs: ZkPublicInputs,
    session_binding: ZkSessionBinding,
}

impl ExpectedStageProofShape {
    /// Expected production bundle_kind.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Expected production stage.
    #[must_use]
    pub const fn stage(&self) -> ZkClaimProofBundleStage {
        self.stage
    }

    /// Expected proof metadata excluding manifest identity and proof bytes.
    #[must_use]
    pub const fn metadata(&self) -> &ZkProofMetadata {
        &self.metadata
    }

    /// Expected canonical public inputs.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkPublicInputs {
        &self.public_inputs
    }

    /// Expected presentation-session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }
}

/// Deterministic shape expected from one successful production bundle.
#[derive(Debug, PartialEq, Eq)]
pub struct ExpectedBundleProofShape {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    session_binding: ZkSessionBinding,
    stages: [ExpectedStageProofShape; PRODUCTION_STAGE_COUNT],
}

impl ExpectedBundleProofShape {
    /// Expected production bundle_kind.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Expected hash lane.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Expected exact proof suite.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Expected presentation-session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }

    /// Expected stages in canonical production order.
    #[must_use]
    pub const fn stages(&self) -> &[ExpectedStageProofShape; PRODUCTION_STAGE_COUNT] {
        &self.stages
    }
}

/// Expected deterministic result of one proving vector.
#[derive(Debug, PartialEq, Eq)]
pub enum ExpectedProvingOutcome {
    /// Successful diagnostic stage proof shape.
    Stage(ExpectedStageProofShape),
    /// Successful production bundle proof shape.
    Bundle(Box<ExpectedBundleProofShape>),
    /// Exact structured failure expected after mutation.
    Error(ZkError),
}

/// One validated proving vector.
///
/// This type intentionally implements neither `Debug` nor `Clone`: its encoded
/// operation transitively owns synthetic witness bytes in zeroizing storage.
pub struct ProvingVector {
    number: u32,
    mutation: ProvingVectorMutation,
    encoded_base_operation: Zeroizing<Vec<u8>>,
    expected_outcome: ExpectedProvingOutcome,
}

impl ProvingVector {
    /// Stable one-based number within the vector set.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Typed mutation executed by the conformance harness.
    #[must_use]
    pub const fn mutation(&self) -> ProvingVectorMutation {
        self.mutation
    }

    /// Expected deterministic proof shape or exact structured error.
    #[must_use]
    pub const fn expected_outcome(&self) -> &ExpectedProvingOutcome {
        &self.expected_outcome
    }

    /// Executes the typed mutation and decodes through the canonical operation
    /// boundary.
    ///
    /// Success returns the validated proving operation. Negative mutations
    /// return the same typed error a provider boundary must expose.
    pub fn execute(self) -> Result<ZkProviderOperation, ZkError> {
        if self.mutation == ProvingVectorMutation::None {
            return crate::operation::decode_operation_request(&self.encoded_base_operation);
        }

        let mut request = decode_base_operation(&self.encoded_base_operation)?;
        apply_mutation(&mut request, self.mutation)?;
        let mutated = Zeroizing::new(request.encode_to_vec());
        crate::operation::decode_operation_request(&mutated)
    }
}

/// Validated canonical pre-manifest proving-vector set.
///
/// This type intentionally implements neither `Debug` nor `Clone` because its
/// vectors retain zeroizing encoded proving operations.
pub struct ProvingVectorSet {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    vectors: Vec<ProvingVector>,
}

impl ProvingVectorSet {
    /// Production bundle_kind shared by every vector.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Hash lane shared by every vector.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Exact production proof suite shared by every vector.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Canonically ordered proving vectors.
    #[must_use]
    pub fn vectors(&self) -> &[ProvingVector] {
        &self.vectors
    }

    /// Consumes the set and returns its zeroizing vector owners.
    #[must_use]
    pub fn into_vectors(self) -> Vec<ProvingVector> {
        self.vectors
    }
}

mod decoding;
mod mutation;
pub use decoding::decode_proving_vector_set;
use mutation::{apply_mutation, decode_base_operation};
