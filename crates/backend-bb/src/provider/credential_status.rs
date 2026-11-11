// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pinned linked-library proving for issuer validity and current status.

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerCredentialStatusProof, ZkIssuerCredentialStatusProver},
    proofs::{ZkProofSuite, ZkSessionBinding, ZkWitness},
};

use crate::{BbCommonCredentialRootRawProveRequest, NativeBarretenbergBackend};

use super::{BarretenbergBundleProvider, BarretenbergCommonCredentialRootArtifactResolver};

impl<R> BarretenbergBundleProvider<NativeBarretenbergBackend, R>
where
    R: BarretenbergCommonCredentialRootArtifactResolver,
{
    /// Prove the exact issuer-signed validity and hidden-index status circuit.
    ///
    /// The resolver must authenticate the reviewed artifact identity. The
    /// returned public inputs are checked against the active request after
    /// the linked backend has verified its own newly generated proof.
    pub fn prove_issuer_credential_status(
        &self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        witness: &ZkWitness,
        session_binding: ZkSessionBinding,
    ) -> Result<ZkIssuerCredentialStatusProof, ZkError> {
        let circuit_ref = ZkCircuitRef::new(
            credential_hash_algorithm,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::IssuerCredentialStatus,
        );
        if witness.circuit_ref() != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        let artifacts = self
            .artifact_resolver
            .resolve_common_credential_root_artifacts(
                ZkCommonCredentialRootPersonaMode::PrivatePersona,
                ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
                circuit_ref,
                ZkProofSuite::PRODUCTION,
            )?;
        let identity = artifacts.artifact_identity();
        let proved = self
            .backend
            .prove_common_credential_root_raw_exact_circuit(
                BbCommonCredentialRootRawProveRequest {
                    circuit_ref,
                    proof_suite: ZkProofSuite::PRODUCTION,
                    artifact_identity: identity,
                    artifacts: &artifacts,
                    witness,
                },
            )?;
        proved
            .public_inputs()
            .validate_session_binding(session_binding)?;
        let (proof_bytes, public_inputs) = proved.into_parts();
        ZkIssuerCredentialStatusProof::try_from_parts(
            ZkProofSuite::PRODUCTION,
            identity.require_artifact_set()?,
            proof_bytes,
            public_inputs,
        )
    }
}

impl<R> ZkIssuerCredentialStatusProver for BarretenbergBundleProvider<NativeBarretenbergBackend, R>
where
    R: BarretenbergCommonCredentialRootArtifactResolver,
{
    fn prove_issuer_credential_status(
        &self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        witness: &ZkWitness,
        session_binding: ZkSessionBinding,
    ) -> Result<ZkIssuerCredentialStatusProof, ZkError> {
        BarretenbergBundleProvider::prove_issuer_credential_status(
            self,
            credential_hash_algorithm,
            witness,
            session_binding,
        )
    }
}
