// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linked verification adapter for exact persona-credential-evidence source circuits.

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::ZkError,
    persona_evidence::{
        ZkPersonaCredentialEvidenceStageProof, ZkPersonaCredentialEvidenceStageVerifier,
    },
    proofs::ZkProofSuite,
};

use crate::{BbExactCircuitArtifacts, NativeBarretenbergBackend};

/// Resolver rooted in a reviewed release index, not presentation metadata.
/// A deployment must independently authenticate the circuit's manifest and
/// verification-key hash before returning `BbExactCircuitArtifacts`.
pub trait BarretenbergPersonaCredentialEvidenceArtifactResolver: Send + Sync {
    /// Resolve reviewed artifacts for this exact prepared source circuit.
    fn resolve_persona_credential_evidence_artifacts(
        &self,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError>;
}

/// Native linked verifier with injected, release-index-authenticated artifacts.
pub struct BarretenbergPersonaCredentialEvidenceProvider<R> {
    backend: NativeBarretenbergBackend,
    resolver: R,
}

impl<R> BarretenbergPersonaCredentialEvidenceProvider<R> {
    /// Keep trust-root selection outside the proof supplied by the holder.
    #[must_use]
    pub const fn new(backend: NativeBarretenbergBackend, resolver: R) -> Self {
        Self { backend, resolver }
    }
}

impl<R> ZkPersonaCredentialEvidenceStageVerifier
    for BarretenbergPersonaCredentialEvidenceProvider<R>
where
    R: BarretenbergPersonaCredentialEvidenceArtifactResolver,
{
    fn verify_persona_credential_evidence_stage_proof(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
    ) -> Result<(), ZkError> {
        let artifacts = self
            .resolver
            .resolve_persona_credential_evidence_artifacts(
                proof.public_inputs().circuit_ref(),
                proof.proof_suite(),
            )?;
        self.backend
            .verify_persona_credential_evidence_stage_exact_circuit(proof, &artifacts)
    }
}
