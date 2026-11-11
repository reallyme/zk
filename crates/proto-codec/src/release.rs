// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical release-index ownership and matrix validation.

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    exact_source_artifact_identity, ArtifactToolchain, ArtifactVersion, Digest32,
};

/// Exact release-index format accepted by this codec.
pub const RELEASE_INDEX_FORMAT_VERSION: u32 = 1;
/// Maximum canonical binary release-index size.
pub const MAX_ZK_RELEASE_INDEX_BYTES: usize = 1024 * 1024;
/// Complete production manifest count: two hashes by two request-bound profiles by four stages.
pub const RELEASE_ARTIFACT_MANIFEST_COUNT: usize = 16;
/// Complete post-manifest vector-set count: two hashes by two request-bound profiles.
pub const RELEASE_VERIFICATION_VECTOR_SET_COUNT: usize = 4;
/// Two hash lanes by seven exact common-credential-root v1 source programs.
pub const RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT: usize = 14;
/// Two hash lanes by six exact persona-credential-evidence source programs.
pub const RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT: usize = 12;
/// Maximum cases admitted to one verification-vector set.
pub const MAX_RELEASE_VERIFICATION_VECTORS: u32 = 256;

const RELEASE_RECURSION_LIMIT: u32 = 16;
const RELEASE_UNKNOWN_FIELD_LIMIT: usize = 0;
const RELEASE_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_RELEASE_INDEX_BYTES;
const COMMON_CREDENTIAL_ROOT_STAGES: [ZkCircuitStage; 7] = [
    ZkCircuitStage::RootAttestation,
    ZkCircuitStage::RootStatus,
    ZkCircuitStage::Lineage,
    ZkCircuitStage::IssuerCredentialStatus,
    ZkCircuitStage::PrivatePersonaClaim,
    ZkCircuitStage::PublicPersonaClaim,
    ZkCircuitStage::PublicSession,
];
const PERSONA_CREDENTIAL_EVIDENCE_STAGES: [ZkCircuitStage; 6] = [
    ZkCircuitStage::EvidenceIssuerEnvelope,
    ZkCircuitStage::EvidenceClaimRoot,
    ZkCircuitStage::EvidenceSignedValidity,
    ZkCircuitStage::EvidencePublicClaim,
    ZkCircuitStage::EvidencePrivateClaim,
    ZkCircuitStage::EvidenceCurrentState,
];

/// Signed source and binary digests for one persona-credential-evidence program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleasePersonaCredentialEvidenceArtifactPin {
    circuit_ref: ZkCircuitRef,
    source_lock_sha256: Digest32,
    source_closure_sha256: Digest32,
    bytecode_sha256: Digest32,
    verification_key_sha256: Digest32,
    artifact_identity_sha256: reallyme_zk_api::artifacts::ZkArtifactSetIdentity,
}

impl ReleasePersonaCredentialEvidenceArtifactPin {
    /// Admit only an exact persona-credential-evidence source with a recomputed identity.
    pub fn try_new(
        circuit_ref: ZkCircuitRef,
        source_lock_sha256: Digest32,
        source_closure_sha256: Digest32,
        bytecode_sha256: Digest32,
        verification_key_sha256: Digest32,
        artifact_identity_sha256: reallyme_zk_api::artifacts::ZkArtifactSetIdentity,
    ) -> Result<Self, ZkError> {
        if circuit_ref.family != ZkCircuitFamily::PersonaCredentialEvidenceV1
            || circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION
            || !PERSONA_CREDENTIAL_EVIDENCE_STAGES.contains(&circuit_ref.stage)
            || source_lock_sha256.is_zero()
            || source_closure_sha256.is_zero()
            || bytecode_sha256.is_zero()
            || verification_key_sha256.is_zero()
            || artifact_identity_sha256.is_zero()
            || exact_source_artifact_identity(
                circuit_ref,
                source_closure_sha256,
                bytecode_sha256,
                verification_key_sha256,
            )? != artifact_identity_sha256
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            circuit_ref,
            source_lock_sha256,
            source_closure_sha256,
            bytecode_sha256,
            verification_key_sha256,
            artifact_identity_sha256,
        })
    }

    /// Exact reviewed circuit reference.
    #[must_use]
    pub const fn circuit_ref(self) -> ZkCircuitRef {
        self.circuit_ref
    }
    /// Hash of the reviewed source lock.
    #[must_use]
    pub const fn source_lock_sha256(self) -> Digest32 {
        self.source_lock_sha256
    }
    /// Hash of this program's complete source closure.
    #[must_use]
    pub const fn source_closure_sha256(self) -> Digest32 {
        self.source_closure_sha256
    }
    /// Hash of the compiled ACIR program.
    #[must_use]
    pub const fn bytecode_sha256(self) -> Digest32 {
        self.bytecode_sha256
    }
    /// Hash of the exact verification key.
    #[must_use]
    pub const fn verification_key_sha256(self) -> Digest32 {
        self.verification_key_sha256
    }
    /// Proof-facing exact artifact identity.
    #[must_use]
    pub const fn artifact_identity_sha256(
        self,
    ) -> reallyme_zk_api::artifacts::ZkArtifactSetIdentity {
        self.artifact_identity_sha256
    }
}

/// Signed identity and independent content digests for one exact program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseCommonCredentialRootArtifactPin {
    circuit_ref: ZkCircuitRef,
    source_lock_sha256: Digest32,
    source_closure_sha256: Digest32,
    bytecode_sha256: Digest32,
    verification_key_sha256: Digest32,
    artifact_identity_sha256: reallyme_zk_api::artifacts::ZkArtifactSetIdentity,
}

impl ReleaseCommonCredentialRootArtifactPin {
    /// Requires a source ref in the common-credential-root v1 matrix and matching identity.
    pub fn try_new(
        circuit_ref: ZkCircuitRef,
        source_lock_sha256: Digest32,
        source_closure_sha256: Digest32,
        bytecode_sha256: Digest32,
        verification_key_sha256: Digest32,
        artifact_identity_sha256: reallyme_zk_api::artifacts::ZkArtifactSetIdentity,
    ) -> Result<Self, ZkError> {
        if circuit_ref.family != ZkCircuitFamily::CommonCredentialRootV1
            || circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION
            || !COMMON_CREDENTIAL_ROOT_STAGES.contains(&circuit_ref.stage)
            || source_lock_sha256.is_zero()
            || source_closure_sha256.is_zero()
            || bytecode_sha256.is_zero()
            || verification_key_sha256.is_zero()
            || artifact_identity_sha256
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || exact_source_artifact_identity(
                circuit_ref,
                source_closure_sha256,
                bytecode_sha256,
                verification_key_sha256,
            )? != artifact_identity_sha256
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            circuit_ref,
            source_lock_sha256,
            source_closure_sha256,
            bytecode_sha256,
            verification_key_sha256,
            artifact_identity_sha256,
        })
    }

    /// Exact source circuit admitted by this pin.
    #[must_use]
    pub const fn circuit_ref(self) -> ZkCircuitRef {
        self.circuit_ref
    }
    /// Digest of the shared source closure lock.
    #[must_use]
    pub const fn source_lock_sha256(self) -> Digest32 {
        self.source_lock_sha256
    }
    /// Digest of this circuit's complete source closure.
    #[must_use]
    pub const fn source_closure_sha256(self) -> Digest32 {
        self.source_closure_sha256
    }
    /// Digest of the compiled ACIR program.
    #[must_use]
    pub const fn bytecode_sha256(self) -> Digest32 {
        self.bytecode_sha256
    }
    /// Digest of the corresponding verification key.
    #[must_use]
    pub const fn verification_key_sha256(self) -> Digest32 {
        self.verification_key_sha256
    }
    /// Proof-facing identity recomputed from all source and binary digests.
    #[must_use]
    pub const fn artifact_identity_sha256(
        self,
    ) -> reallyme_zk_api::artifacts::ZkArtifactSetIdentity {
        self.artifact_identity_sha256
    }
}

/// One validated sealed artifact-manifest identity in the release matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseArtifactPin {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    manifest_sha256: ZkArtifactManifestDigest,
}

impl ReleaseArtifactPin {
    /// Validates exact bundle_kind/stage/source-circuit identity.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        manifest_sha256: ZkArtifactManifestDigest,
    ) -> Result<Self, ZkError> {
        if circuit_ref != bundle_kind.source_ref(circuit_ref.credential_hash_algorithm, stage) {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            bundle_kind,
            stage,
            circuit_ref,
            manifest_sha256,
        })
    }

    /// Production bundle_kind coordinate.
    #[must_use]
    pub const fn bundle_kind(self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }
    /// Production stage coordinate.
    #[must_use]
    pub const fn stage(self) -> ZkClaimProofBundleStage {
        self.stage
    }
    /// Exact source circuit coordinate.
    #[must_use]
    pub const fn circuit_ref(self) -> ZkCircuitRef {
        self.circuit_ref
    }
    /// SHA-256 of the canonical artifact-manifest protobuf bytes.
    #[must_use]
    pub const fn manifest_sha256(self) -> ZkArtifactManifestDigest {
        self.manifest_sha256
    }
}

/// One validated post-manifest verification-vector-set identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseVerificationVectorPin {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    vector_set_sha256: Digest32,
    vector_count: u32,
}

impl ReleaseVerificationVectorPin {
    /// Validates a non-empty bounded vector-set pin for the production suite.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        vector_set_sha256: Digest32,
        vector_count: u32,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        if vector_count == 0 || vector_count > MAX_RELEASE_VERIFICATION_VECTORS {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            vector_set_sha256,
            vector_count,
        })
    }

    /// Production bundle_kind coordinate.
    #[must_use]
    pub const fn bundle_kind(self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }
    /// Hash-lane coordinate.
    #[must_use]
    pub const fn credential_hash_algorithm(self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }
    /// Exact approved proof suite.
    #[must_use]
    pub const fn proof_suite(self) -> ZkProofSuite {
        self.proof_suite
    }
    /// SHA-256 of canonical verification-vector-set protobuf bytes.
    #[must_use]
    pub const fn vector_set_sha256(self) -> Digest32 {
        self.vector_set_sha256
    }
    /// Number of canonical cases in the pinned vector set.
    #[must_use]
    pub const fn vector_count(self) -> u32 {
        self.vector_count
    }
}

/// Validated acyclic root for one production artifact and vector release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIndex {
    release_version: ArtifactVersion,
    toolchain: ArtifactToolchain,
    proof_suite: ZkProofSuite,
    capability_registry_sha256: Digest32,
    artifact_manifests: Vec<ReleaseArtifactPin>,
    verification_vectors: Vec<ReleaseVerificationVectorPin>,
    common_credential_root_artifacts: Vec<ReleaseCommonCredentialRootArtifactPin>,
    persona_credential_evidence_artifacts: Vec<ReleasePersonaCredentialEvidenceArtifactPin>,
}

impl ReleaseIndex {
    /// Validates release identity and both complete canonical matrices.
    pub fn try_new(
        release_version: ArtifactVersion,
        toolchain: ArtifactToolchain,
        proof_suite: ZkProofSuite,
        capability_registry_sha256: Digest32,
        artifact_manifests: Vec<ReleaseArtifactPin>,
        verification_vectors: Vec<ReleaseVerificationVectorPin>,
    ) -> Result<Self, ZkError> {
        Self::try_new_with_common_credential_root(
            release_version,
            toolchain,
            proof_suite,
            capability_registry_sha256,
            artifact_manifests,
            verification_vectors,
            Vec::new(),
        )
    }

    /// Validates the production matrices and optional complete common-credential-root set.
    pub fn try_new_with_common_credential_root(
        release_version: ArtifactVersion,
        toolchain: ArtifactToolchain,
        proof_suite: ZkProofSuite,
        capability_registry_sha256: Digest32,
        artifact_manifests: Vec<ReleaseArtifactPin>,
        verification_vectors: Vec<ReleaseVerificationVectorPin>,
        common_credential_root_artifacts: Vec<ReleaseCommonCredentialRootArtifactPin>,
    ) -> Result<Self, ZkError> {
        Self::try_new_with_exact_sources(
            release_version,
            toolchain,
            proof_suite,
            capability_registry_sha256,
            artifact_manifests,
            verification_vectors,
            common_credential_root_artifacts,
            Vec::new(),
        )
    }

    /// Validates the production matrices and both exact-source circuit-family sets.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_with_exact_sources(
        release_version: ArtifactVersion,
        toolchain: ArtifactToolchain,
        proof_suite: ZkProofSuite,
        capability_registry_sha256: Digest32,
        artifact_manifests: Vec<ReleaseArtifactPin>,
        verification_vectors: Vec<ReleaseVerificationVectorPin>,
        common_credential_root_artifacts: Vec<ReleaseCommonCredentialRootArtifactPin>,
        persona_credential_evidence_artifacts: Vec<ReleasePersonaCredentialEvidenceArtifactPin>,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        validate_artifact_matrix(&artifact_manifests)?;
        validate_vector_matrix(&verification_vectors, proof_suite)?;
        validate_unique_release_digests(&artifact_manifests, &verification_vectors)?;
        validate_common_credential_root_matrix(&common_credential_root_artifacts)?;
        validate_persona_credential_evidence_matrix(&persona_credential_evidence_artifacts)?;
        if let (Some(common_credential_root), Some(persona_credential_evidence)) = (
            common_credential_root_artifacts.first(),
            persona_credential_evidence_artifacts.first(),
        ) {
            if common_credential_root.source_lock_sha256()
                != persona_credential_evidence.source_lock_sha256()
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
        }
        Ok(Self {
            release_version,
            toolchain,
            proof_suite,
            capability_registry_sha256,
            artifact_manifests,
            verification_vectors,
            common_credential_root_artifacts,
            persona_credential_evidence_artifacts,
        })
    }

    /// Validated release/version token.
    #[must_use]
    pub const fn release_version(&self) -> ArtifactVersion {
        self.release_version
    }
    /// Exact compiler and proving-system versions.
    #[must_use]
    pub const fn toolchain(&self) -> ArtifactToolchain {
        self.toolchain
    }
    /// Exact approved proof suite shared by the release.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }
    /// Semantic capability-registry identity shared by every manifest.
    #[must_use]
    pub const fn capability_registry_sha256(&self) -> Digest32 {
        self.capability_registry_sha256
    }
    /// Complete manifest pins in hash/bundle_kind/stage order.
    #[must_use]
    pub fn artifact_manifests(&self) -> &[ReleaseArtifactPin] {
        &self.artifact_manifests
    }
    /// Complete vector pins in hash/bundle_kind order.
    #[must_use]
    pub fn verification_vectors(&self) -> &[ReleaseVerificationVectorPin] {
        &self.verification_vectors
    }
    /// Empty until sealed; otherwise all twelve common-credential-root exact programs.
    #[must_use]
    pub fn common_credential_root_artifacts(&self) -> &[ReleaseCommonCredentialRootArtifactPin] {
        &self.common_credential_root_artifacts
    }
    /// Empty until sealed; otherwise all twelve persona-credential-evidence programs.
    #[must_use]
    pub fn persona_credential_evidence_artifacts(
        &self,
    ) -> &[ReleasePersonaCredentialEvidenceArtifactPin] {
        &self.persona_credential_evidence_artifacts
    }
}

mod codec;
pub(crate) use codec::{
    artifact_pin_from_proto, artifact_pin_to_proto, bundle_kind_to_proto, production_stage_to_proto,
};
pub use codec::{decode_release_index, encode_release_index};
use codec::{
    validate_artifact_matrix, validate_common_credential_root_matrix,
    validate_persona_credential_evidence_matrix, validate_unique_release_digests,
    validate_vector_matrix,
};
