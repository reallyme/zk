// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact-artifact verification of the nine common-credential-root presentation slots.

use crate::linked::{BbCommonCredentialRootRawVerifyRequest, LinkedBarretenbergBackend};
use reallyme_zk_api::{
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootVerifier, ZkCommonCredentialRootVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerCredentialStatusProof, ZkIssuerCredentialStatusVerifier},
};

use super::{BarretenbergBundleProvider, BarretenbergCommonCredentialRootArtifactResolver};

impl<B, R> ZkCommonCredentialRootVerifier for BarretenbergBundleProvider<B, R>
where
    B: LinkedBarretenbergBackend,
    R: BarretenbergCommonCredentialRootArtifactResolver,
{
    fn verify_common_credential_root_evidence(
        &self,
        request: &ZkCommonCredentialRootVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        if !self
            .backend
            .supports_proof_suite(request.expected_proof_suite())
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }

        for proof in request.proofs() {
            let circuit_ref = request
                .persona_mode()
                .source_ref(request.expected_credential_hash_algorithm(), proof.slot());
            if proof.public_inputs().circuit_ref() != circuit_ref {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            let artifacts = self
                .artifact_resolver
                .resolve_common_credential_root_artifacts(
                    request.persona_mode(),
                    proof.slot(),
                    circuit_ref,
                    request.expected_proof_suite(),
                )?;
            if artifacts.circuit_ref() != circuit_ref {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            if artifacts.artifact_identity() != proof.artifact_identity() {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }

            self.backend.verify_common_credential_root_raw(
                BbCommonCredentialRootRawVerifyRequest {
                    circuit_ref,
                    proof_suite: proof.proof_suite(),
                    artifact_identity: proof.artifact_identity(),
                    artifacts: &artifacts,
                    proof_bytes: proof.proof_bytes(),
                    public_inputs: proof.public_inputs(),
                },
            )?;
        }

        Ok(())
    }
}

impl<B, R> ZkIssuerCredentialStatusVerifier for BarretenbergBundleProvider<B, R>
where
    B: LinkedBarretenbergBackend,
    R: BarretenbergCommonCredentialRootArtifactResolver,
{
    fn verify_issuer_credential_status(
        &self,
        proof: &ZkIssuerCredentialStatusProof,
    ) -> Result<(), ZkError> {
        if !self.backend.supports_proof_suite(proof.proof_suite()) {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let circuit_ref = proof.public_inputs().circuit_ref();
        // Both common-credential-root slots and the request-bound fifth stage use one
        // exact source circuit and VK. Slot 0 is its canonical artifact lookup.
        let artifacts = self
            .artifact_resolver
            .resolve_common_credential_root_artifacts(
                ZkCommonCredentialRootPersonaMode::PrivatePersona,
                ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
                circuit_ref,
                proof.proof_suite(),
            )?;
        if artifacts.circuit_ref() != circuit_ref
            || artifacts.artifact_identity() != proof.artifact_set_identity_sha256().into()
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        self.backend
            .verify_common_credential_root_raw(BbCommonCredentialRootRawVerifyRequest {
                circuit_ref,
                proof_suite: proof.proof_suite(),
                artifact_identity: proof.artifact_set_identity_sha256().into(),
                artifacts: &artifacts,
                proof_bytes: proof.proof_bytes(),
                public_inputs: proof.public_inputs(),
            })
    }
}
