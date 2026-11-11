// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in linked regression for transaction-bound session proofs.

#![cfg(feature = "native")]

use std::env;

#[path = "support/modern_all30.rs"]
mod modern_all30;

use modern_all30::{
    binding_from_prover_toml, generate_witness, load_circuit_evidence, read_g2,
    read_prover_g1_prefix, required_path, MatrixError, G1_PATH_ENV, G2_PATH_ENV, ROOT_ENV,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding,
    },
};
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BbExactCircuitProveRequest, BbExactCircuitVerifyRequest,
    NativeBarretenbergBackend,
};

const ENABLE_ENV: &str = "REALLYME_NATIVE_TRANSACTION_BOUND_SESSION";

#[test]
fn native_backend_rejects_transaction_replay_for_representative_session() -> Result<(), MatrixError>
{
    if env::var_os(ENABLE_ENV).is_none() {
        return Ok(());
    }

    let root = required_path(ROOT_ENV)?;
    let g1_path = required_path(G1_PATH_ENV)?;
    let g2_path = required_path(G2_PATH_ENV)?;
    let g1 = read_prover_g1_prefix(&g1_path)?;
    let g2 = read_g2(&g2_path)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1.as_slice(), &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(crs)?;

    let circuit_ref = ZkCircuitRef {
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        family: ZkCircuitFamily::CredentialSubjectClaimV1,
        stage: ZkCircuitStage::Session,
        revision: ZkCircuitRef::CURRENT_REVISION,
    };
    let evidence = load_circuit_evidence(&root, circuit_ref)?;
    let binding = binding_from_prover_toml(&root, evidence.circuit_ref)?;
    if binding.transaction_data_hash.is_none() {
        return Err(MatrixError::MissingField);
    }
    binding.decode_and_validate(evidence.circuit_ref, &evidence.public_inputs)?;

    let witness = generate_witness(&root, &evidence)?;
    let proved = backend.prove_exact_circuit(BbExactCircuitProveRequest {
        circuit_ref: evidence.circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifact_identity: (evidence.artifact_identity).into(),
        artifacts: &evidence.artifacts,
        witness: &witness,
        session_binding: binding,
    })?;
    let (proof_bytes, public_inputs) = proved.into_parts();
    let proof = ZkProof::try_from_exact_bounded_parts(
        evidence.circuit_ref.circuit_id(),
        evidence.circuit_ref,
        ZkProofSuite::PRODUCTION,
        evidence.artifact_identity,
        proof_bytes,
        public_inputs,
    )?;
    backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
        circuit_ref: evidence.circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifact_identity: (evidence.artifact_identity).into(),
        artifacts: &evidence.artifacts,
        proof: &proof,
        expected_binding: binding,
    })?;

    let wrong_binding = flip_transaction(binding)?;
    expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &proof,
            expected_binding: wrong_binding,
        }),
        ZkErrorReason::BindingMismatch,
    )?;

    let tampered_proof = proof_with_transaction_public_input(
        evidence.circuit_ref,
        evidence.artifact_identity,
        &proof,
    )?;
    expect_one_of(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &tampered_proof,
            expected_binding: wrong_binding,
        }),
        &[
            ZkErrorReason::InvalidProof,
            ZkErrorReason::InvalidProofEncoding,
            ZkErrorReason::BackendFailure,
        ],
    )?;
    Ok(())
}

fn flip_transaction(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    let Some(transaction_data_hash) = binding.transaction_data_hash.as_mut() else {
        return Err(MatrixError::MissingField);
    };
    let Some(first) = transaction_data_hash.first_mut() else {
        return Err(MatrixError::UnexpectedLength);
    };
    *first ^= 1;
    Ok(binding)
}

fn proof_with_transaction_public_input(
    circuit_ref: ZkCircuitRef,
    artifact_identity: reallyme_zk_api::artifacts::ZkArtifactSetIdentity,
    proof: &ZkProof,
) -> Result<ZkProof, MatrixError> {
    let mut public_inputs = proof.public_inputs().as_bytes().to_vec();
    let tx_range = ZkPublicInputDescriptor::for_circuit(circuit_ref)?
        .field_range(ZkPublicInputName::TransactionDataHash)?;
    let Some(first) = public_inputs
        .get_mut(tx_range)
        .ok_or(MatrixError::UnexpectedLength)?
        .first_mut()
    else {
        return Err(MatrixError::UnexpectedLength);
    };
    *first ^= 1;
    ZkProof::try_from_exact_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        artifact_identity,
        proof.proof_bytes().to_vec(),
        ZkPublicInputs::try_from_bytes(public_inputs)?,
    )
    .map_err(MatrixError::from)
}

fn expect_reason(result: Result<(), ZkError>, expected: ZkErrorReason) -> Result<(), MatrixError> {
    match result {
        Ok(()) => Err(MatrixError::UnexpectedErrorReason {
            expected,
            actual: None,
        }),
        Err(error) if error.reason() == expected => Ok(()),
        Err(error) => Err(MatrixError::UnexpectedErrorReason {
            expected,
            actual: Some(error.reason()),
        }),
    }
}

fn expect_one_of(
    result: Result<(), ZkError>,
    expected: &[ZkErrorReason],
) -> Result<(), MatrixError> {
    match result {
        Ok(()) => Err(MatrixError::UnexpectedErrorReason {
            expected: expected.first().copied().ok_or(MatrixError::MissingField)?,
            actual: None,
        }),
        Err(error) if expected.contains(&error.reason()) => Ok(()),
        Err(error) => Err(MatrixError::UnexpectedErrorReason {
            expected: expected.first().copied().ok_or(MatrixError::MissingField)?,
            actual: Some(error.reason()),
        }),
    }
}
