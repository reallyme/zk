// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hash-pinned artifact manifests for ReallyMe ZK providers.
//!
//! This crate validates metadata that binds the stable production proof
//! profiles from `reallyme-zk-api` to exact source circuits, ACIR bytecode,
//! verification keys, capability registry hashes, and vector sets. Fetching and
//! caching are adapter responsibilities layered on top of this contract.

use crate::{ArtifactToolchain, Digest32, MAX_VECTOR_SET_DIGESTS};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::{circuit_ref_capabilities, ZkCircuitCapabilities, ZkSemanticGuarantee},
    circuits::ZkCircuitRef,
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkCompatibilitySuiteAcknowledgement,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};

/// Hashes that must move atomically with a circuit version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigests {
    /// Hash of the normalized Noir source tree for the exact source circuit.
    pub noir_source_sha256: Digest32,
    /// Hash of the ACIR bytecode bundled or fetched by providers.
    pub bytecode_sha256: Digest32,
    /// Hash of the verification key accepted by verifiers.
    pub verification_key_sha256: Digest32,
    /// Hash of the semantic capability registry used for this release.
    pub capability_registry_sha256: Digest32,
    /// Hashes of valid and invalid vector sets for this circuit version.
    pub vector_set_sha256: Vec<Digest32>,
}

/// Proof-suite and canonical-manifest identity that must travel together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactManifestPin {
    proof_suite: ZkProofSuite,
    manifest_sha256: ZkArtifactManifestDigest,
}

/// Validated artifact metadata before the canonical protobuf identity is
/// sealed.
///
/// Release tooling uses this type to assemble exact artifact hashes, then asks
/// the proto codec to encode and hash one canonical manifest. Runtime code uses
/// only `ProductionArtifactManifest` and never accepts an unsealed draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionArtifactManifestDraft {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    toolchain: ArtifactToolchain,
    capabilities: ZkCircuitCapabilities,
    digests: ArtifactDigests,
}

impl ProductionArtifactManifestDraft {
    /// Validates all manifest content that does not depend on its final digest.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        toolchain: ArtifactToolchain,
        capabilities: ZkCircuitCapabilities,
        digests: ArtifactDigests,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        Self::try_new_with_suite_policy(
            bundle_kind,
            stage,
            circuit_ref,
            proof_suite,
            toolchain,
            capabilities,
            digests,
        )
    }

    /// Validates a manifest draft for an explicitly acknowledged
    /// non-production compatibility suite.
    ///
    /// Compatibility artifacts are never selected by the production
    /// constructor because they may omit masking or use non-release transcript
    /// settings. Callers must keep compatibility manifests out of production
    /// release indexes and providers unless a test-only lane deliberately uses
    /// them.
    #[allow(
        clippy::too_many_arguments,
        reason = "public compatibility constructor mirrors the production manifest constructor; reshaping it requires an explicit semver release decision"
    )]
    pub fn try_new_compatibility(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        toolchain: ArtifactToolchain,
        capabilities: ZkCircuitCapabilities,
        digests: ArtifactDigests,
        _acknowledgement: ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if proof_suite == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(
            bundle_kind,
            stage,
            circuit_ref,
            proof_suite,
            toolchain,
            capabilities,
            digests,
        )
    }

    fn try_new_with_suite_policy(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        toolchain: ArtifactToolchain,
        capabilities: ZkCircuitCapabilities,
        digests: ArtifactDigests,
    ) -> Result<Self, ZkError> {
        validate_manifest_content(
            bundle_kind,
            stage,
            circuit_ref,
            proof_suite,
            capabilities,
            &digests,
        )?;
        Ok(Self {
            bundle_kind,
            stage,
            circuit_ref,
            proof_suite,
            toolchain,
            capabilities,
            digests,
        })
    }

    /// Production bundle_kind for this draft.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Production stage for this draft.
    #[must_use]
    pub const fn stage(&self) -> ZkClaimProofBundleStage {
        self.stage
    }

    /// Exact source circuit for this draft.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Exact production proof suite for this draft.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Exact toolchain for this draft.
    #[must_use]
    pub const fn toolchain(&self) -> ArtifactToolchain {
        self.toolchain
    }

    /// Exact registry capabilities for this draft.
    #[must_use]
    pub const fn capabilities(&self) -> ZkCircuitCapabilities {
        self.capabilities
    }

    /// Artifact and vector hashes for this draft.
    #[must_use]
    pub const fn digests(&self) -> &ArtifactDigests {
        &self.digests
    }
}

impl ArtifactManifestPin {
    /// Creates a production-compatible manifest pin.
    pub fn try_new(
        proof_suite: ZkProofSuite,
        manifest_sha256: ZkArtifactManifestDigest,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        Self::try_new_with_suite_policy(proof_suite, manifest_sha256)
    }

    /// Creates an explicitly acknowledged compatibility manifest pin.
    pub fn try_new_compatibility(
        proof_suite: ZkProofSuite,
        manifest_sha256: ZkArtifactManifestDigest,
        _acknowledgement: ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if proof_suite == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(proof_suite, manifest_sha256)
    }

    fn try_new_with_suite_policy(
        proof_suite: ZkProofSuite,
        manifest_sha256: ZkArtifactManifestDigest,
    ) -> Result<Self, ZkError> {
        if manifest_sha256.is_zero() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            proof_suite,
            manifest_sha256,
        })
    }

    /// Exact suite used to create and verify the pinned artifacts.
    #[must_use]
    pub const fn proof_suite(self) -> ZkProofSuite {
        self.proof_suite
    }

    /// SHA-256 identity of the canonical binary protobuf manifest.
    #[must_use]
    pub const fn manifest_sha256(self) -> ZkArtifactManifestDigest {
        self.manifest_sha256
    }
}

/// Production artifact manifest for one bridge bundle_kind/stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionArtifactManifest {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    manifest_pin: ArtifactManifestPin,
    toolchain: ArtifactToolchain,
    capabilities: ZkCircuitCapabilities,
    digests: ArtifactDigests,
}

impl ProductionArtifactManifest {
    /// Validates that a production bundle_kind/stage is bound to the expected
    /// source circuit and stores the hash-pinned artifact metadata.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        manifest_pin: ArtifactManifestPin,
        toolchain: ArtifactToolchain,
        capabilities: ZkCircuitCapabilities,
        digests: ArtifactDigests,
    ) -> Result<Self, ZkError> {
        manifest_pin.proof_suite().require_production()?;
        Self::try_new_with_suite_policy(
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin,
            toolchain,
            capabilities,
            digests,
        )
    }

    /// Validates an explicitly acknowledged compatibility artifact manifest.
    #[allow(
        clippy::too_many_arguments,
        reason = "public compatibility constructor mirrors the production bundle-manifest constructor; reshaping it requires an explicit semver release decision"
    )]
    pub fn try_new_compatibility(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        manifest_pin: ArtifactManifestPin,
        toolchain: ArtifactToolchain,
        capabilities: ZkCircuitCapabilities,
        digests: ArtifactDigests,
        _acknowledgement: ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if manifest_pin.proof_suite() == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin,
            toolchain,
            capabilities,
            digests,
        )
    }

    fn try_new_with_suite_policy(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        manifest_pin: ArtifactManifestPin,
        toolchain: ArtifactToolchain,
        capabilities: ZkCircuitCapabilities,
        digests: ArtifactDigests,
    ) -> Result<Self, ZkError> {
        validate_manifest_content(
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin.proof_suite(),
            capabilities,
            &digests,
        )?;

        Ok(Self {
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin,
            toolchain,
            capabilities,
            digests,
        })
    }

    /// Production bundle_kind for this artifact set.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Production stage for this artifact set.
    #[must_use]
    pub const fn stage(&self) -> ZkClaimProofBundleStage {
        self.stage
    }

    /// Exact source circuit for this artifact set.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Exact proof suite used to produce and verify the artifacts.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.manifest_pin.proof_suite()
    }

    /// SHA-256 identity of the canonical binary protobuf manifest.
    #[must_use]
    pub const fn manifest_sha256(&self) -> ZkArtifactManifestDigest {
        self.manifest_pin.manifest_sha256()
    }

    /// Exact compiler and backend versions used to produce the artifacts.
    #[must_use]
    pub const fn toolchain(&self) -> ArtifactToolchain {
        self.toolchain
    }

    /// Exact stage capabilities pinned with this manifest.
    #[must_use]
    pub const fn capabilities(&self) -> ZkCircuitCapabilities {
        self.capabilities
    }

    /// Semantic guarantees pinned with this manifest.
    #[must_use]
    pub fn semantic_guarantees(&self) -> &[ZkSemanticGuarantee] {
        self.capabilities.semantic_guarantees
    }

    /// Hash-pinned artifact digests.
    #[must_use]
    pub const fn digests(&self) -> &ArtifactDigests {
        &self.digests
    }
}

fn validate_manifest_content(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    _proof_suite: ZkProofSuite,
    capabilities: ZkCircuitCapabilities,
    digests: &ArtifactDigests,
) -> Result<(), ZkError> {
    validate_digests(digests)?;
    if bundle_kind.source_ref(circuit_ref.credential_hash_algorithm, stage) != circuit_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    if capabilities != circuit_ref_capabilities(circuit_ref)? {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    if digests.vector_set_sha256.is_empty()
        || digests.vector_set_sha256.len() > MAX_VECTOR_SET_DIGESTS
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}

fn validate_digests(digests: &ArtifactDigests) -> Result<(), ZkError> {
    if digests.noir_source_sha256.is_zero()
        || digests.bytecode_sha256.is_zero()
        || digests.verification_key_sha256.is_zero()
        || digests.capability_registry_sha256.is_zero()
        || digests.vector_set_sha256.iter().any(Digest32::is_zero)
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}
