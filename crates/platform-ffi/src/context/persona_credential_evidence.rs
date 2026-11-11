// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_backend_bb::{
    BarretenbergPersonaCredentialEvidenceArtifactResolver, BbExactCircuitArtifacts,
};

use super::{exact_source, PlatformContext};

impl BarretenbergPersonaCredentialEvidenceArtifactResolver for PlatformContext {
    fn resolve_persona_credential_evidence_artifacts(
        &self,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        proof_suite.require_production()?;
        if self.release_index.proof_suite() != proof_suite
            || circuit_ref.family != ZkCircuitFamily::PersonaCredentialEvidenceV1
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let pin = self
            .release_index
            .persona_credential_evidence_artifacts()
            .iter()
            .copied()
            .find(|pin| pin.circuit_ref() == circuit_ref)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        exact_source::persona_credential_evidence_release_artifacts(
            &self.artifact_root,
            pin,
            proof_suite,
        )
    }
}
