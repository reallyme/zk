// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Barretenberg bundle provider adapter.
//!
//! This crate is intentionally outside the open-stack dependency boundary. It
//! adapts a linked Barretenberg implementation to the proof-system-agnostic
//! `reallyme-zk-api` traits without exposing ACIR, FFI handles, backend error
//! text, or CLI shell-out behavior to identity, OpenID4VP, or wallet crates.

use crate::linked::{BbStageProveRequest, BbStageVerifyRequest, LinkedBarretenbergBackend};
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest,
        ZkClaimProofBundleProver, ZkClaimProofBundleStage, ZkClaimProofBundleStageProof,
        ZkPresentationBoundClaimBundleVerifier, ZkPresentationBoundClaimBundleVerifyRequest,
    },
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::{
    ArtifactBytes, ArtifactKind, ProductionArtifactManifest, ProductionBundleManifest,
    VerifiedArtifactBytes,
};

mod artifacts;
mod common_credential_root;
#[cfg(feature = "native")]
mod credential_status;
mod validation;
pub use artifacts::BbStageVerificationArtifacts;
use validation::{validate_hash_lane, validate_resolved_manifest, validate_stage_ref};
pub(crate) use validation::{validate_presentation_expiry, validate_resolved_artifacts};

/// Hash-verified artifacts for one Barretenberg production stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BbStageArtifacts {
    manifest: ProductionArtifactManifest,
    bytecode: VerifiedArtifactBytes,
    verification_key: VerifiedArtifactBytes,
}

impl BbStageArtifacts {
    /// Validates resolved bytecode and verification-key bytes against the
    /// manifest digests before a linked backend can use them.
    pub fn try_new(
        manifest: ProductionArtifactManifest,
        bytecode: VerifiedArtifactBytes,
        verification_key: VerifiedArtifactBytes,
    ) -> Result<Self, ZkError> {
        if bytecode.digest() != manifest.digests().bytecode_sha256 {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        if bytecode.kind() != ArtifactKind::AcirBytecode {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        if verification_key.digest() != manifest.digests().verification_key_sha256 {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        if verification_key.kind() != ArtifactKind::VerificationKey {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(Self {
            manifest,
            bytecode,
            verification_key,
        })
    }

    /// Manifest pinned to these artifact bytes.
    #[must_use]
    pub const fn manifest(&self) -> &ProductionArtifactManifest {
        &self.manifest
    }

    /// Hash-verified ACIR bytecode bytes.
    #[must_use]
    pub const fn bytecode(&self) -> &VerifiedArtifactBytes {
        &self.bytecode
    }

    /// Hash-verified verification-key bytes.
    #[must_use]
    pub const fn verification_key(&self) -> &VerifiedArtifactBytes {
        &self.verification_key
    }
}

/// Resolves hash-pinned artifacts for a production stage.
pub trait BarretenbergArtifactResolver: Send + Sync {
    /// Returns bytecode, verification key, and manifest metadata for one stage.
    fn resolve_stage_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError>;

    /// Resolves only the material needed for verification.
    ///
    /// Custom resolvers remain source compatible through this conservative
    /// default. Resolvers backed by external storage should override it to
    /// avoid loading ACIR bytecode on verification-only paths.
    fn resolve_stage_verification_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<BbStageVerificationArtifacts, ZkError> {
        let artifacts = self.resolve_stage_artifacts(profile, stage, circuit_ref, proof_suite)?;
        BbStageVerificationArtifacts::try_new(artifacts.manifest, artifacts.verification_key)
    }
}

/// Resolves hash-pinned exact artifacts for a common-credential-root proof slot.
///
/// This is intentionally separate from `BarretenbergArtifactResolver` because
/// common-credential-root presentations are nine-slot exact-source presentations, not the
/// four-stage production bundle manifest. A deployment must opt in with a
/// resolver backed by a sealed release index or an equivalently authenticated
/// trust root before `BarretenbergBundleProvider` can satisfy
/// `ZkCommonCredentialRootVerifier`.
pub trait BarretenbergCommonCredentialRootArtifactResolver: Send + Sync {
    /// Returns bytecode, verification key, and reviewed artifact identity for
    /// one canonical common-credential-root slot.
    fn resolve_common_credential_root_artifacts(
        &self,
        profile: ZkCommonCredentialRootPersonaMode,
        slot: ZkCommonCredentialRootProofSlot,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<crate::BbExactCircuitArtifacts, ZkError>;
}

impl<T> BarretenbergCommonCredentialRootArtifactResolver for &T
where
    T: BarretenbergCommonCredentialRootArtifactResolver + ?Sized,
{
    fn resolve_common_credential_root_artifacts(
        &self,
        profile: ZkCommonCredentialRootPersonaMode,
        slot: ZkCommonCredentialRootProofSlot,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<crate::BbExactCircuitArtifacts, ZkError> {
        (**self).resolve_common_credential_root_artifacts(profile, slot, circuit_ref, proof_suite)
    }
}

/// Byte store used by the manifest-backed resolver.
///
/// Implementations may read bundled mobile assets, a content-addressed local
/// cache, or service-managed artifact storage. Implementations must reject a
/// declared content length with `ArtifactKind::validate_length` before
/// allocating or reading it and return only the corresponding bounded owner;
/// digest checking remains centralized in `ManifestBackedArtifactResolver`.
pub trait BarretenbergArtifactStore: Send + Sync {
    /// Loads bounded ACIR bytecode for the supplied manifest.
    fn bytecode_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError>;

    /// Loads a bounded verification key for the supplied manifest.
    fn verification_key_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError>;
}

/// Resolver that binds a caller-configured manifest trust root to a byte store.
///
/// The manifest is not authenticated by this constructor. The caller must
/// derive it from a reviewed release index, an equivalently authenticated
/// configuration channel, or another explicitly documented trust root.
#[derive(Debug, Clone)]
pub struct ManifestBackedArtifactResolver<S> {
    bundle_manifest: ProductionBundleManifest,
    store: S,
}

impl<S> ManifestBackedArtifactResolver<S> {
    /// Creates a resolver from a caller-authenticated production bundle
    /// manifest and byte store.
    ///
    /// The explicit name prevents a decoded or locally discovered manifest
    /// from being mistaken for release-index-derived trust.
    #[must_use]
    pub const fn from_configured_trust_root(
        bundle_manifest: ProductionBundleManifest,
        store: S,
    ) -> Self {
        Self {
            bundle_manifest,
            store,
        }
    }

    /// Borrows the production bundle manifest.
    #[must_use]
    pub const fn bundle_manifest(&self) -> &ProductionBundleManifest {
        &self.bundle_manifest
    }

    /// Borrows the byte store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Consumes this resolver and returns its parts.
    #[must_use]
    pub fn into_parts(self) -> (ProductionBundleManifest, S) {
        (self.bundle_manifest, self.store)
    }

    fn resolve_manifest(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<&ProductionArtifactManifest, ZkError> {
        if self.bundle_manifest.bundle_kind() != profile
            || self.bundle_manifest.credential_hash_algorithm()
                != circuit_ref.credential_hash_algorithm
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if self.bundle_manifest.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let manifest = self.bundle_manifest.stage_manifest(stage)?;
        if manifest.circuit_ref() != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(manifest)
    }
}

impl<S> BarretenbergArtifactResolver for ManifestBackedArtifactResolver<S>
where
    S: BarretenbergArtifactStore,
{
    fn resolve_stage_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError> {
        let manifest = self.resolve_manifest(profile, stage, circuit_ref, proof_suite)?;

        let bytecode = VerifiedArtifactBytes::try_from_bounded(
            self.store.bytecode_bytes(manifest)?,
            manifest.digests().bytecode_sha256,
        )?;
        let verification_key = VerifiedArtifactBytes::try_from_bounded(
            self.store.verification_key_bytes(manifest)?,
            manifest.digests().verification_key_sha256,
        )?;

        BbStageArtifacts::try_new(manifest.clone(), bytecode, verification_key)
    }

    fn resolve_stage_verification_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: reallyme_zk_api::proofs::ZkProofSuite,
    ) -> Result<BbStageVerificationArtifacts, ZkError> {
        let manifest = self.resolve_manifest(profile, stage, circuit_ref, proof_suite)?;
        let verification_key = VerifiedArtifactBytes::try_from_bounded(
            self.store.verification_key_bytes(manifest)?,
            manifest.digests().verification_key_sha256,
        )?;
        BbStageVerificationArtifacts::try_new(manifest.clone(), verification_key)
    }
}

/// Bundle provider backed by a linked Barretenberg implementation.
#[derive(Debug, Clone)]
pub struct BarretenbergBundleProvider<B, R> {
    backend: B,
    artifact_resolver: R,
}

impl<B, R> BarretenbergBundleProvider<B, R> {
    /// Creates a bundle provider from a concrete linked backend and artifact
    /// resolver.
    #[must_use]
    pub const fn new(backend: B, artifact_resolver: R) -> Self {
        Self {
            backend,
            artifact_resolver,
        }
    }

    /// Borrows the linked backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Borrows the artifact resolver.
    #[must_use]
    pub const fn artifact_resolver(&self) -> &R {
        &self.artifact_resolver
    }

    /// Consumes this provider and returns its parts.
    #[must_use]
    pub fn into_parts(self) -> (B, R) {
        (self.backend, self.artifact_resolver)
    }
}

impl<B, R> ZkClaimProofBundleProver for BarretenbergBundleProvider<B, R>
where
    B: LinkedBarretenbergBackend,
    R: BarretenbergArtifactResolver,
{
    fn prove_claim_proof_bundle(
        &self,
        request: ZkClaimProofBundleProveRequest<'_>,
    ) -> Result<ZkClaimProofBundle, ZkError> {
        if request.witness_bundle().bundle_kind() != request.bundle_kind()
            || request.witness_bundle().credential_hash_algorithm()
                != request.credential_hash_algorithm()
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if !self.backend.supports_proof_suite(request.proof_suite()) {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let mut stage_proofs = Vec::new();
        stage_proofs
            .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;

        for stage in ZkClaimProofBundleStage::ALL {
            let circuit_ref = request
                .bundle_kind()
                .source_ref(request.credential_hash_algorithm(), *stage);
            request
                .session_binding()
                .validate_for_circuit(circuit_ref)?;
            let artifacts = self.artifact_resolver.resolve_stage_artifacts(
                request.bundle_kind(),
                *stage,
                circuit_ref,
                request.proof_suite(),
            )?;
            validate_resolved_artifacts(request.bundle_kind(), *stage, circuit_ref, &artifacts)?;
            if artifacts.manifest().proof_suite() != request.proof_suite() {
                return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
            }
            let witness = request.witness_bundle().stage_witness(*stage)?;
            let response = self.backend.prove_stage(BbStageProveRequest {
                bundle_kind: request.bundle_kind(),
                stage: *stage,
                circuit_ref,
                proof_suite: request.proof_suite(),
                artifacts: &artifacts,
                witness,
                session_binding: request.session_binding(),
            })?;
            request
                .session_binding()
                .decode_and_validate(circuit_ref, response.public_inputs())?;
            let (proof_bytes, public_inputs) = response.into_parts();
            let proof = reallyme_zk_api::proofs::ZkProof::try_from_exact_bounded_parts(
                request.bundle_kind().circuit_id(),
                circuit_ref,
                artifacts.manifest().proof_suite(),
                artifacts.manifest().manifest_sha256(),
                proof_bytes,
                public_inputs,
            )?;
            stage_proofs.push(ZkClaimProofBundleStageProof::try_from_parts(
                request.bundle_kind(),
                *stage,
                proof,
            )?);
        }

        ZkClaimProofBundle::try_from_stage_proofs(
            request.bundle_kind(),
            request.session_binding(),
            stage_proofs,
        )
    }
}

impl<B, R> ZkPresentationBoundClaimBundleVerifier for BarretenbergBundleProvider<B, R>
where
    B: LinkedBarretenbergBackend,
    R: BarretenbergArtifactResolver,
{
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        for stage_proof in request.bundle().stage_proofs() {
            request
                .expected_binding()
                .validate_for_circuit(stage_proof.proof().circuit_ref())?;
        }
        if request.bundle().session_binding() != request.expected_binding() {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        if request.bundle().proof_suite() != request.expected_proof_suite() {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if !self
            .backend
            .supports_proof_suite(request.expected_proof_suite())
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }

        let profile = request.bundle().bundle_kind();
        let statement = request.bundle().decode_claimed_statement()?;
        if !request.trusted_issuers().contains(&statement.issuer()) {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        validate_presentation_expiry(
            statement.presentation_expiry_unix(),
            request.verification_time_unix(),
        )?;
        let mut credential_hash_algorithm = None;

        for stage_proof in request.bundle().stage_proofs() {
            let circuit_ref = stage_proof.proof().circuit_ref();

            validate_stage_ref(profile, stage_proof.stage(), circuit_ref)?;
            validate_hash_lane(&mut credential_hash_algorithm, circuit_ref)?;
            request
                .expected_binding()
                .decode_and_validate(circuit_ref, stage_proof.proof().public_inputs())?;
            let artifacts = self
                .artifact_resolver
                .resolve_stage_verification_artifacts(
                    profile,
                    stage_proof.stage(),
                    circuit_ref,
                    stage_proof.proof().proof_suite(),
                )?;
            validate_resolved_manifest(
                profile,
                stage_proof.stage(),
                circuit_ref,
                artifacts.manifest(),
            )?;
            if stage_proof.proof().proof_suite() != artifacts.manifest().proof_suite() {
                return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
            }
            if stage_proof.proof().artifact_identity()
                != artifacts.manifest().manifest_sha256().into()
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }

            self.backend.verify_stage(BbStageVerifyRequest {
                bundle_kind: profile,
                stage: stage_proof.stage(),
                circuit_ref,
                proof_suite: stage_proof.proof().proof_suite(),
                artifacts: &artifacts,
                proof: stage_proof.proof(),
                expected_binding: request.expected_binding(),
            })?;
        }

        Ok(())
    }
}
