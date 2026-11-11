// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in retained request-bound prove/verify gate through linked Barretenberg.

#![cfg(feature = "native")]

use std::{env, path::PathBuf, time::Instant};

#[path = "support/modern_all30.rs"]
mod modern_all30;

use modern_all30::{
    binding_for, binding_from_prover_toml, generate_witness, load_circuit_evidence,
    negative_outcomes, process_rss_kib, read_g2, read_prover_g1_prefix, required_path,
    retained_request_bound_circuit_refs, write_summary, MatrixError, MatrixRowMeasurements,
    MatrixSummaryRow, G1_PATH_ENV, G2_PATH_ENV, PROVE_SUMMARY_ENV,
    RETAINED_REQUEST_BOUND_CIRCUIT_COUNT, ROOT_ENV,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCircuitStage},
    proofs::{ZkProof, ZkProofSuite},
};
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BbExactCircuitProveRequest, BbExactCircuitVerifyRequest,
    NativeBarretenbergBackend,
};

const ENABLE_ENV: &str = "REALLYME_NATIVE_ALL30_PROVE_VERIFY";

#[test]
fn native_backend_proves_and_verifies_retained_request_bound_circuits() -> Result<(), MatrixError> {
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

    let circuit_refs: Vec<_> = retained_request_bound_circuit_refs().collect();
    assert_eq!(circuit_refs.len(), RETAINED_REQUEST_BOUND_CIRCUIT_COUNT);
    let mut rows = Vec::new();
    let mut ordinary_repeat_ref = None;
    let mut largest_repeat_ref = None;
    let mut largest_witness_bytes = 0_usize;
    for circuit_ref in circuit_refs {
        let evidence = load_circuit_evidence(&root, *circuit_ref)?;
        let binding = binding_from_prover_toml(&root, evidence.circuit_ref)?;
        binding.decode_and_validate(evidence.circuit_ref, &evidence.public_inputs)?;
        let fixture_binding = binding_for(&evidence.public_inputs, evidence.circuit_ref)?;
        assert_eq!(binding, fixture_binding);
        let witness_start = Instant::now();
        let witness = generate_witness(&root, &evidence)?;
        let witness_ms = witness_start.elapsed().as_millis();
        let witness_bytes = witness.expose_bytes().len();
        if ordinary_repeat_ref.is_none()
            && evidence.circuit_ref.stage != ZkCircuitStage::ClaimBundle4
        {
            ordinary_repeat_ref = Some(evidence.circuit_ref);
        }
        if witness_bytes > largest_witness_bytes {
            largest_witness_bytes = witness_bytes;
            largest_repeat_ref = Some(evidence.circuit_ref);
        }
        let prove_start = Instant::now();
        let proved = backend.prove_exact_circuit(BbExactCircuitProveRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            witness: &witness,
            session_binding: binding,
        })?;
        let prove_ms = prove_start.elapsed().as_millis();
        assert_eq!(
            proved.public_inputs().as_bytes(),
            evidence.public_inputs.as_bytes()
        );
        let (proof_bytes, public_inputs) = proved.into_parts();
        let proof_bytes_len = proof_bytes.as_bytes().len();
        let proof = ZkProof::try_from_exact_bounded_parts(
            evidence.circuit_ref.circuit_id(),
            evidence.circuit_ref,
            ZkProofSuite::PRODUCTION,
            evidence.artifact_identity,
            proof_bytes,
            public_inputs,
        )?;
        let verify_start = Instant::now();
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &proof,
            expected_binding: binding,
        })?;
        let verify_ms = verify_start.elapsed().as_millis();
        let negatives = negative_outcomes(&backend, &root, &evidence, &proof, binding)?;
        rows.push(MatrixSummaryRow::from_evidence(
            &evidence,
            MatrixRowMeasurements {
                witness_bytes,
                proof_bytes: proof_bytes_len,
                witness_ms,
                prove_ms,
                verify_ms,
                process_rss_kib: process_rss_kib()?,
            },
            negatives,
        ));
    }

    let ordinary_repeat_ref = ordinary_repeat_ref.ok_or(MatrixError::MissingField)?;
    let largest_repeat_ref = largest_repeat_ref.ok_or(MatrixError::MissingField)?;
    if largest_repeat_ref.stage != ZkCircuitStage::ClaimBundle4 {
        return Err(MatrixError::MissingField);
    }
    repeat_circuit(
        &backend,
        &root,
        ordinary_repeat_ref,
        "repeat-ordinary",
        &mut rows,
    )?;
    repeat_circuit(
        &backend,
        &root,
        largest_repeat_ref,
        "repeat-largest-bundle",
        &mut rows,
    )?;

    if let Some(path) = env::var_os(PROVE_SUMMARY_ENV).map(PathBuf::from) {
        write_summary(&path, rows.as_slice())?;
    }
    Ok(())
}

fn repeat_circuit(
    backend: &NativeBarretenbergBackend,
    root: &std::path::Path,
    circuit_ref: ZkCircuitRef,
    label: &str,
    rows: &mut Vec<MatrixSummaryRow>,
) -> Result<(), MatrixError> {
    for iteration in 0..2 {
        let evidence = load_circuit_evidence(root, circuit_ref)?;
        let binding = binding_from_prover_toml(root, evidence.circuit_ref)?;
        let witness_start = Instant::now();
        let witness = generate_witness(root, &evidence)?;
        let witness_ms = witness_start.elapsed().as_millis();
        let witness_bytes = witness.expose_bytes().len();
        let prove_start = Instant::now();
        let proved = backend.prove_exact_circuit(BbExactCircuitProveRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            witness: &witness,
            session_binding: binding,
        })?;
        let prove_ms = prove_start.elapsed().as_millis();
        let (proof_bytes, public_inputs) = proved.into_parts();
        let proof_bytes_len = proof_bytes.as_bytes().len();
        let proof = ZkProof::try_from_exact_bounded_parts(
            evidence.circuit_ref.circuit_id(),
            evidence.circuit_ref,
            ZkProofSuite::PRODUCTION,
            evidence.artifact_identity,
            proof_bytes,
            public_inputs,
        )?;
        let verify_start = Instant::now();
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &proof,
            expected_binding: binding,
        })?;
        let verify_ms = verify_start.elapsed().as_millis();
        let negatives = negative_outcomes(backend, root, &evidence, &proof, binding)?;
        let mut row = MatrixSummaryRow::from_evidence(
            &evidence,
            MatrixRowMeasurements {
                witness_bytes,
                proof_bytes: proof_bytes_len,
                witness_ms,
                prove_ms,
                verify_ms,
                process_rss_kib: process_rss_kib()?,
            },
            negatives,
        );
        row.circuit_name = format!("{}-{}:{}", label, iteration + 1, row.circuit_name);
        rows.push(row);
    }
    Ok(())
}
