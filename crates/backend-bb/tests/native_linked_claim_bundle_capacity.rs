// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in evidence for current-source claim_bundle_4 capacity.

#![cfg(feature = "native")]

use std::{env, fs, path::PathBuf, time::Instant};

#[path = "support/modern_all30.rs"]
mod modern_all30;

use modern_all30::{
    binding_from_prover_toml, generate_witness, load_circuit_evidence, process_rss_kib, read_g2,
    read_prover_g1_prefix, required_path, CircuitEvidence, MatrixError, G1_PATH_ENV, G2_PATH_ENV,
    ROOT_ENV,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProofSuite, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BbExactCircuitProveRequest, BbExactCircuitVerifyRequest,
    NativeBarretenbergBackend,
};

const SUMMARY_ENV: &str = "REALLYME_CLAIM_BUNDLE_CAPACITY_SUMMARY";

#[test]
#[ignore = "requires linked Barretenberg, all-circuit artifacts, and pinned full-prover CRS"]
fn claim_bundle_4_capacity_is_measured_with_negative_binding_checks() -> Result<(), MatrixError> {
    let root = required_path(ROOT_ENV)?;
    let g1_path = required_path(G1_PATH_ENV)?;
    let g2_path = required_path(G2_PATH_ENV)?;
    let summary_path = env::var_os(SUMMARY_ENV).map(PathBuf::from);
    let g1 = read_prover_g1_prefix(&g1_path)?;
    let g2 = read_g2(&g2_path)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1.as_slice(), &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(crs)?;

    let mut rows = Vec::new();
    for circuit_ref in ZkCircuitRef::ALL {
        if circuit_ref.stage != ZkCircuitStage::ClaimBundle4 {
            continue;
        }
        rows.push(measure_claim_bundle(&backend, &root, *circuit_ref)?);
    }
    let expected_count = reallyme_zk_api::claim_bundle::ZkClaimProofBundleKind::ALL
        .len()
        .checked_mul(reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::ALL.len())
        .ok_or(MatrixError::MissingField)?;
    if rows.len() != expected_count {
        return Err(MatrixError::MissingField);
    }
    if let Some(path) = summary_path {
        write_capacity_summary(&path, rows.as_slice())?;
    }

    Ok(())
}

fn measure_claim_bundle(
    backend: &NativeBarretenbergBackend,
    root: &std::path::Path,
    circuit_ref: ZkCircuitRef,
) -> Result<CapacityRow, MatrixError> {
    let baseline_rss_kib = process_rss_kib()?;
    let evidence = load_circuit_evidence(root, circuit_ref)?;
    let binding = binding_from_prover_toml(root, evidence.circuit_ref)?;
    binding.decode_and_validate(evidence.circuit_ref, &evidence.public_inputs)?;
    let witness_start = Instant::now();
    let witness = generate_witness(root, &evidence)?;
    let witness_ms = witness_start.elapsed().as_millis();
    let witness_bytes = witness.expose_bytes().len();
    let after_witness_rss_kib = process_rss_kib()?;
    prove_verify_and_measure(
        backend,
        evidence,
        witness,
        binding,
        CapacityStart {
            witness_bytes,
            witness_ms,
            baseline_rss_kib,
            after_witness_rss_kib,
        },
    )
}

fn prove_verify_and_measure(
    backend: &NativeBarretenbergBackend,
    evidence: CircuitEvidence,
    witness: ZkWitness,
    binding: ZkSessionBinding,
    start: CapacityStart,
) -> Result<CapacityRow, MatrixError> {
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
    let after_prove_rss_kib = process_rss_kib()?;
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
    let after_verify_rss_kib = process_rss_kib()?;
    expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &proof,
            expected_binding: flip_nonce(binding)?,
        }),
        ZkErrorReason::BindingMismatch,
    )?;

    Ok(CapacityRow {
        circuit: evidence.circuit_name,
        package: evidence.package_name,
        source_closure_sha256: hex32(evidence.source_closure_sha256.as_bytes()),
        artifact_identity_sha256: hex32(evidence.artifact_identity.as_bytes()),
        witness_bytes: start.witness_bytes,
        proof_bytes: proof_bytes_len,
        public_input_bytes: evidence.public_inputs.as_bytes().len(),
        vk_bytes: evidence.artifacts.verification_key().as_bytes().len(),
        witness_ms: start.witness_ms,
        prove_ms,
        verify_ms,
        baseline_rss_kib: start.baseline_rss_kib,
        after_witness_rss_kib: start.after_witness_rss_kib,
        after_prove_rss_kib,
        after_verify_rss_kib,
        wrong_binding: ZkErrorReason::BindingMismatch,
    })
}

struct CapacityStart {
    witness_bytes: usize,
    witness_ms: u128,
    baseline_rss_kib: u64,
    after_witness_rss_kib: u64,
}

struct CapacityRow {
    circuit: String,
    package: String,
    source_closure_sha256: String,
    artifact_identity_sha256: String,
    witness_bytes: usize,
    proof_bytes: usize,
    public_input_bytes: usize,
    vk_bytes: usize,
    witness_ms: u128,
    prove_ms: u128,
    verify_ms: u128,
    baseline_rss_kib: u64,
    after_witness_rss_kib: u64,
    after_prove_rss_kib: u64,
    after_verify_rss_kib: u64,
    wrong_binding: ZkErrorReason,
}

fn write_capacity_summary(path: &std::path::Path, rows: &[CapacityRow]) -> Result<(), MatrixError> {
    let parent = path.parent().ok_or(MatrixError::MissingField)?;
    fs::create_dir_all(parent)?;
    let mut output = String::from(
        "circuit\tpackage\tsource_closure_sha256\tartifact_identity_sha256\twitness_bytes\tproof_bytes\tpublic_input_bytes\tvk_bytes\twitness_ms\tprove_ms\tverify_ms\tbaseline_cumulative_process_rss_high_water_kib\tafter_witness_cumulative_process_rss_high_water_kib\tafter_prove_cumulative_process_rss_high_water_kib\tafter_verify_cumulative_process_rss_high_water_kib\twrong_binding\n",
    );
    for row in rows {
        push_row(&mut output, row);
    }
    fs::write(path, output)?;
    Ok(())
}

fn push_row(output: &mut String, row: &CapacityRow) {
    output.push_str(&row.circuit);
    output.push('\t');
    output.push_str(&row.package);
    output.push('\t');
    output.push_str(&row.source_closure_sha256);
    output.push('\t');
    output.push_str(&row.artifact_identity_sha256);
    output.push('\t');
    output.push_str(&row.witness_bytes.to_string());
    output.push('\t');
    output.push_str(&row.proof_bytes.to_string());
    output.push('\t');
    output.push_str(&row.public_input_bytes.to_string());
    output.push('\t');
    output.push_str(&row.vk_bytes.to_string());
    output.push('\t');
    output.push_str(&row.witness_ms.to_string());
    output.push('\t');
    output.push_str(&row.prove_ms.to_string());
    output.push('\t');
    output.push_str(&row.verify_ms.to_string());
    output.push('\t');
    output.push_str(&row.baseline_rss_kib.to_string());
    output.push('\t');
    output.push_str(&row.after_witness_rss_kib.to_string());
    output.push('\t');
    output.push_str(&row.after_prove_rss_kib.to_string());
    output.push('\t');
    output.push_str(&row.after_verify_rss_kib.to_string());
    output.push('\t');
    output.push_str(row.wrong_binding.proto_name());
    output.push('\n');
}

fn flip_nonce(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    let first = binding
        .nonce_hash
        .first_mut()
        .ok_or(MatrixError::UnexpectedLength)?;
    *first ^= 1;
    Ok(binding)
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

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
