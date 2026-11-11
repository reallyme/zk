// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-stage Barretenberg provider for OpenID4VP ZK presentations.

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProveRequest, ZkProver},
};

use crate::{
    provider::validate_resolved_artifacts, BarretenbergArtifactResolver, BbStageProveRequest,
    LinkedBarretenbergBackend,
};

/// Artifact-backed provider for one production stage.
///
/// This adapter is intentionally prove-only. Production verification must use
/// `BarretenbergBundleProvider` so no single stage can be confused with the
/// authenticity and integrity guarantees of the complete family.
#[derive(Debug, Clone)]
pub struct BarretenbergStageProvider<B, R> {
    backend: B,
    artifact_resolver: R,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
}

impl<B, R> BarretenbergStageProvider<B, R> {
    /// Creates a provider pinned to one exact bundle_kind, hash lane, and stage.
    #[must_use]
    pub const fn new(
        backend: B,
        artifact_resolver: R,
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        stage: ZkClaimProofBundleStage,
    ) -> Self {
        Self {
            backend,
            artifact_resolver,
            bundle_kind,
            credential_hash_algorithm,
            stage,
        }
    }

    /// Production bundle_kind accepted by this provider.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Hash strategy accepted by this provider.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Production stage accepted by this provider.
    #[must_use]
    pub const fn stage(&self) -> ZkClaimProofBundleStage {
        self.stage
    }
}

impl<B, R> ZkProver for BarretenbergStageProvider<B, R>
where
    B: LinkedBarretenbergBackend,
    R: BarretenbergArtifactResolver,
{
    fn prove(&self, request: ZkProveRequest<'_>) -> Result<ZkProof, ZkError> {
        let circuit_ref = self.expected_circuit_ref();
        if request.circuit_id() != self.bundle_kind.circuit_id()
            || request.circuit_ref() != circuit_ref
            || request.witness().circuit_ref() != circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        if !self.backend.supports_proof_suite(request.proof_suite()) {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }

        request
            .session_binding()
            .decode_and_validate(circuit_ref, request.public_inputs())?;

        let artifacts = self.artifact_resolver.resolve_stage_artifacts(
            self.bundle_kind,
            self.stage,
            circuit_ref,
            request.proof_suite(),
        )?;
        validate_resolved_artifacts(self.bundle_kind, self.stage, circuit_ref, &artifacts)?;
        if artifacts.manifest().proof_suite() != request.proof_suite() {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let response = self.backend.prove_stage(BbStageProveRequest {
            bundle_kind: self.bundle_kind,
            stage: self.stage,
            circuit_ref,
            proof_suite: request.proof_suite(),
            artifacts: &artifacts,
            witness: request.witness(),
            session_binding: request.session_binding(),
        })?;
        request
            .session_binding()
            .decode_and_validate(circuit_ref, response.public_inputs())?;
        if response.public_inputs().as_bytes() != request.public_inputs().as_bytes() {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }

        let (proof_bytes, public_inputs) = response.into_parts();

        ZkProof::try_from_exact_bounded_parts(
            self.bundle_kind.circuit_id(),
            circuit_ref,
            request.proof_suite(),
            artifacts.manifest().manifest_sha256(),
            proof_bytes,
            public_inputs,
        )
    }
}

impl<B, R> BarretenbergStageProvider<B, R> {
    fn expected_circuit_ref(&self) -> reallyme_zk_api::circuits::ZkCircuitRef {
        self.bundle_kind
            .source_ref(self.credential_hash_algorithm, self.stage)
    }
}
