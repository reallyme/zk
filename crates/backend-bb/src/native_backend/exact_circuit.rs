// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage,
        ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::{ZkProof, ZkProofSuite, ZkPublicInputs},
};

use crate::{
    bbapi_abi::{
        decode_circuit_prove_raw_common_credential_root_response,
        decode_circuit_prove_raw_prepared_response, decode_circuit_prove_response,
        decode_circuit_verify_response, BbapiCircuitProveCommand, BbapiCircuitVerifyCommand,
    },
    BbCommonCredentialRootRawProveRequest, BbCommonCredentialRootRawProveResponse,
    BbCommonCredentialRootRawVerifyRequest, BbExactCircuitProveRequest,
    BbExactCircuitVerifyRequest, BbPersonaCredentialEvidenceStageProveRequest,
    BbStageProveResponse,
};

use super::{
    lock_bbapi_process_state, BarretenbergProcessCrsIdentity, BbapiProcessCrsState,
    NativeBarretenbergBackend,
};

impl NativeBarretenbergBackend {
    /// Prove one prepared stage and verify the returned proof before it leaves
    /// the native backend. Artifact identity and mode are caller selected;
    /// neither is inferred from untrusted Barretenberg response bytes.
    pub fn prove_persona_credential_evidence_stage_exact_circuit(
        &self,
        request: BbPersonaCredentialEvidenceStageProveRequest<'_>,
    ) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
        request.proof_suite.require_production()?;
        let claim_stage = match request.mode {
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
                ZkPersonaCredentialEvidenceSourceStage::PublicClaim
            }
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
                ZkPersonaCredentialEvidenceSourceStage::PrivateClaim
            }
        };
        let credential_hash_algorithm = request.circuit_ref.credential_hash_algorithm;
        if request.circuit_ref != claim_stage.source_ref(credential_hash_algorithm)
            && request.circuit_ref
                != ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
                    .source_ref(credential_hash_algorithm)
            && request.circuit_ref
                != ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
                    .source_ref(credential_hash_algorithm)
            && request.circuit_ref
                != ZkPersonaCredentialEvidenceSourceStage::SignedValidity
                    .source_ref(credential_hash_algorithm)
            && request.circuit_ref
                != ZkPersonaCredentialEvidenceSourceStage::CurrentState
                    .source_ref(credential_hash_algorithm)
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.artifacts.circuit_ref() != request.circuit_ref
            || request.witness.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.artifacts.artifact_identity() != request.artifact_identity {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let command = BbapiCircuitProveCommand::try_new_exact(
            request.artifacts,
            request.witness,
            request.proof_suite,
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::FullProver(_)) => {}
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::VerifierOnly(_))
            | BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        let proof = decode_circuit_prove_raw_prepared_response(
            request.mode,
            request.circuit_ref,
            request.proof_suite,
            request.artifact_identity.require_artifact_set()?,
            request.artifacts.verification_key(),
            response.as_bytes(),
        )?;
        // Verification takes the same process-state lock. The prover response
        // owns its bytes, so releasing the guard here cannot invalidate them.
        drop(state);
        self.verify_persona_credential_evidence_stage_exact_circuit(&proof, request.artifacts)?;
        Ok(proof)
    }

    /// Verify a prepared proof against reviewed exact-circuit artifacts.
    /// The API owner validates the public ABI; the resolver must authenticate
    /// the artifact identity and verification-key bytes before this call.
    pub fn verify_persona_credential_evidence_stage_exact_circuit(
        &self,
        proof: &ZkPersonaCredentialEvidenceStageProof,
        artifacts: &crate::BbExactCircuitArtifacts,
    ) -> Result<(), ZkError> {
        if proof.proof_suite() != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let circuit_ref = proof.public_inputs().circuit_ref();
        if artifacts.circuit_ref() != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if artifacts.artifact_identity() != proof.artifact_set_identity_sha256().into() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let command = BbapiCircuitVerifyCommand::try_new_raw_prepared(
            artifacts.verification_key(),
            circuit_ref,
            proof.proof_suite(),
            proof.proof_bytes(),
            proof.public_inputs(),
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(_) => {}
            BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }

    /// Proves one exact imported source circuit with the linked BBAPI shim.
    /// Artifact admission against source locks or release manifests belongs
    /// to the resolver that constructs `BbExactCircuitArtifacts`.
    pub fn prove_exact_circuit(
        &self,
        request: BbExactCircuitProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.artifacts.circuit_ref() != request.circuit_ref
            || request.witness.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.artifacts.artifact_identity() != request.artifact_identity {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let command = BbapiCircuitProveCommand::try_new_exact(
            request.artifacts,
            request.witness,
            request.proof_suite,
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::FullProver(_)) => {}
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::VerifierOnly(_))
            | BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        let proof = decode_circuit_prove_response(
            request.circuit_ref,
            request.artifacts.verification_key(),
            response.as_bytes(),
        )?;
        request
            .session_binding
            .decode_and_validate(request.circuit_ref, proof.public_inputs())?;
        self.verify_proved_exact_response(request, &proof)?;
        Ok(proof)
    }

    /// Proves one common-credential-root raw source circuit and preserves raw public inputs.
    pub fn prove_common_credential_root_raw_exact_circuit(
        &self,
        request: BbCommonCredentialRootRawProveRequest<'_>,
    ) -> Result<BbCommonCredentialRootRawProveResponse, ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.artifacts.circuit_ref() != request.circuit_ref
            || request.witness.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.artifacts.artifact_identity() != request.artifact_identity {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let command = BbapiCircuitProveCommand::try_new_exact(
            request.artifacts,
            request.witness,
            request.proof_suite,
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::FullProver(_)) => {}
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::VerifierOnly(_))
            | BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        let proof = decode_circuit_prove_raw_common_credential_root_response(
            request.circuit_ref,
            request.artifacts.verification_key(),
            response.as_bytes(),
        )?;
        self.verify_proved_common_credential_root_raw_response(request, &proof)?;
        Ok(proof)
    }

    /// Verifies one exact imported source circuit with already initialized CRS.
    pub fn verify_exact_circuit(
        &self,
        request: BbExactCircuitVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION
            || request.proof.proof_suite() != ZkProofSuite::PRODUCTION
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.proof.circuit_ref() != request.circuit_ref
            || request.artifacts.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.proof.artifact_identity() != request.artifact_identity {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if request.artifacts.artifact_identity() != request.artifact_identity {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        request
            .expected_binding
            .decode_and_validate(request.circuit_ref, request.proof.public_inputs())?;

        let command = BbapiCircuitVerifyCommand::try_new(
            request.artifacts.verification_key(),
            request.proof,
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(_) => {}
            BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }

    /// Verifies one common-credential-root raw source circuit with already initialized CRS.
    pub fn verify_common_credential_root_raw_exact_circuit(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.artifacts.circuit_ref() != request.circuit_ref
            || request.public_inputs.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.artifacts.artifact_identity() != request.artifact_identity {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let command = BbapiCircuitVerifyCommand::try_new_raw_common_credential_root(
            request.artifacts.verification_key(),
            request.circuit_ref,
            request.proof_suite,
            request.proof_bytes,
            request.public_inputs,
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(_) => {}
            BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }

    fn verify_proved_exact_response(
        &self,
        request: BbExactCircuitProveRequest<'_>,
        response: &BbStageProveResponse,
    ) -> Result<(), ZkError> {
        let public_inputs =
            ZkPublicInputs::try_copy_from_slice(response.public_inputs().as_bytes())?;
        let proof = ZkProof::try_from_exact_parts(
            request.circuit_ref.circuit_id(),
            request.circuit_ref,
            request.proof_suite,
            request.artifact_identity.require_artifact_set()?,
            response.proof_bytes().as_bytes().to_vec(),
            public_inputs,
        )?;
        let command =
            BbapiCircuitVerifyCommand::try_new(request.artifacts.verification_key(), &proof)?;
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }

    fn verify_proved_common_credential_root_raw_response(
        &self,
        request: BbCommonCredentialRootRawProveRequest<'_>,
        response: &BbCommonCredentialRootRawProveResponse,
    ) -> Result<(), ZkError> {
        let command = BbapiCircuitVerifyCommand::try_new_raw_common_credential_root(
            request.artifacts.verification_key(),
            request.circuit_ref,
            request.proof_suite,
            response.proof_bytes(),
            response.public_inputs(),
        )?;
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }
}
