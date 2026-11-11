// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in retained request-bound verification gate for the verifier-only CRS.

#![cfg(feature = "native")]

use std::{env, fs, path::PathBuf, time::Instant};

#[path = "support/modern_all30.rs"]
mod modern_all30;

use modern_all30::{
    binding_for, binding_from_prover_toml, circuit_name, load_circuit_evidence,
    load_circuit_evidence_from_lock, negative_outcomes, process_rss_kib, read_g2,
    read_verifier_g1_prefix, required_path, retained_request_bound_circuit_refs, write_summary,
    MatrixError, MatrixRowMeasurements, MatrixSummaryRow, G1_PATH_ENV, G2_PATH_ENV,
    RETAINED_REQUEST_BOUND_CIRCUIT_COUNT, ROOT_ENV, VERIFY_SUMMARY_ENV,
};
use reallyme_zk_api::proofs::ZkProofSuite;
use reallyme_zk_backend_bb::{
    BarretenbergVerifierCrs, BbExactCircuitVerifyRequest, NativeBarretenbergBackend,
};

const ENABLE_ENV: &str = "REALLYME_NATIVE_ALL30_VERIFY_ONLY";

#[test]
fn native_backend_verifies_retained_request_bound_circuits_with_one_point_crs(
) -> Result<(), MatrixError> {
    if env::var_os(ENABLE_ENV).is_none() {
        return Ok(());
    }

    let root = required_path(ROOT_ENV)?;
    let g1_path = required_path(G1_PATH_ENV)?;
    let g2_path = required_path(G2_PATH_ENV)?;
    let g1 = read_verifier_g1_prefix(&g1_path)?;
    let g2 = read_g2(&g2_path)?;
    let crs = BarretenbergVerifierCrs::try_from_pinned_slices(&g1, &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_verifier_crs(crs)?;

    let circuit_refs: Vec<_> = retained_request_bound_circuit_refs().collect();
    assert_eq!(circuit_refs.len(), RETAINED_REQUEST_BOUND_CIRCUIT_COUNT);
    let mut rows = Vec::new();
    for circuit_ref in circuit_refs {
        let evidence = load_circuit_evidence(&root, *circuit_ref)?;
        let binding = binding_from_prover_toml(&root, evidence.circuit_ref)?;
        binding.decode_and_validate(evidence.circuit_ref, &evidence.public_inputs)?;
        let fixture_binding = binding_for(&evidence.public_inputs, evidence.circuit_ref)?;
        assert_eq!(binding, fixture_binding);
        let verify_start = Instant::now();
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &evidence.proof,
            expected_binding: binding,
        })?;
        let verify_ms = verify_start.elapsed().as_millis();
        let negatives = negative_outcomes(&backend, &root, &evidence, &evidence.proof, binding)?;
        let proof_bytes = evidence.proof.proof_bytes().len();
        rows.push(MatrixSummaryRow::from_evidence(
            &evidence,
            MatrixRowMeasurements {
                witness_bytes: 0,
                proof_bytes,
                witness_ms: 0,
                prove_ms: 0,
                verify_ms,
                process_rss_kib: process_rss_kib()?,
            },
            negatives,
        ));
    }

    if let Some(path) = env::var_os(VERIFY_SUMMARY_ENV).map(PathBuf::from) {
        write_summary(&path, rows.as_slice())?;
    }
    Ok(())
}

#[test]
fn retained_evidence_loader_rejects_stale_source_lock() -> Result<(), MatrixError> {
    if env::var_os(ENABLE_ENV).is_none() {
        return Ok(());
    }

    let root = required_path(ROOT_ENV)?;
    let target_circuit_ref = *retained_request_bound_circuit_refs()
        .next()
        .ok_or(MatrixError::MissingField)?;
    let target_circuit = circuit_name(target_circuit_ref);
    let lock_path = root.join("modern-circuit-source-lock.tsv");
    let lock = fs::read_to_string(lock_path)?;
    let mut stale = String::new();
    let mut lines = lock.lines();
    let header = lines.next().ok_or(MatrixError::MissingField)?;
    stale.push_str(header);
    stale.push('\n');
    let mut corrupted = false;
    for line in lines {
        let mut fields = line.split('\t');
        let circuit = fields.next().ok_or(MatrixError::MissingField)?;
        let package = fields.next().ok_or(MatrixError::MissingField)?;
        let digest = fields.next().ok_or(MatrixError::MissingField)?;
        if fields.next().is_some() {
            return Err(MatrixError::AmbiguousField);
        }
        stale.push_str(circuit);
        stale.push('\t');
        stale.push_str(package);
        stale.push('\t');
        if circuit == target_circuit {
            stale.push_str("0000000000000000000000000000000000000000000000000000000000000000");
            corrupted = true;
        } else {
            stale.push_str(digest);
        }
        stale.push('\n');
    }
    if !corrupted {
        return Err(MatrixError::MissingField);
    }

    let target_dir = root
        .parent()
        .ok_or(MatrixError::MissingField)?
        .join("target")
        .join("modern-linked-all30-matrix");
    fs::create_dir_all(&target_dir)?;
    let stale_lock_path = target_dir.join("stale-source-lock.tsv");
    fs::write(&stale_lock_path, stale)?;
    let result = load_circuit_evidence_from_lock(&root, &stale_lock_path, target_circuit_ref);
    assert!(matches!(result, Err(MatrixError::SourceLockMismatch)));
    Ok(())
}
