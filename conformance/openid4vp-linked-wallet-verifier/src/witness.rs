// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::ZkClaimProofBundleKind,
    proofs::{ZkSessionBinding, ZkWitness},
};
use reallyme_zk_noir_witness_core::{
    generate_witness_from_artifact_json_and_toml, CompiledProgramArtifactJson,
};
use zeroize::Zeroizing;

use crate::error::HarnessError;
use crate::fixture::CredentialFixture;
use crate::modern_all30::CircuitEvidence;

pub(crate) fn witness_bundle_from_tomls(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stages: &[CircuitEvidence],
    fixture: &CredentialFixture,
    binding: ZkSessionBinding,
) -> Result<reallyme_zk_api::claim_bundle::ZkClaimProofBundleWitness, HarnessError> {
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(stages.len())
        .map_err(|_| HarnessError::InvalidLength)?;
    for evidence in stages {
        witnesses.push(generate_witness_from_toml(
            evidence,
            fixture.prover_toml_for(evidence.circuit_ref.stage)?,
            binding,
        )?);
    }
    Ok(
        reallyme_zk_api::claim_bundle::ZkClaimProofBundleWitness::try_from_stage_witnesses(
            bundle_kind,
            credential_hash_algorithm,
            witnesses,
        )?,
    )
}

fn generate_witness_from_toml(
    evidence: &CircuitEvidence,
    prover_toml_path: PathBuf,
    binding: ZkSessionBinding,
) -> Result<ZkWitness, HarnessError> {
    generate_exact_witness_from_toml(
        evidence.circuit_ref,
        evidence.artifacts.bytecode().as_bytes(),
        prover_toml_path,
        binding,
    )
}

pub(crate) fn generate_exact_witness_from_toml(
    circuit_ref: ZkCircuitRef,
    program_json: &[u8],
    prover_toml_path: PathBuf,
    binding: ZkSessionBinding,
) -> Result<ZkWitness, HarnessError> {
    let artifact_json = CompiledProgramArtifactJson::try_from_bytes(program_json)?;
    let source = Zeroizing::new(fs::read_to_string(prover_toml_path)?);
    let prover_toml = Zeroizing::new(bind_prover_toml(source.as_str(), binding)?);
    let witness =
        generate_witness_from_artifact_json_and_toml(artifact_json, prover_toml.as_str())?;
    Ok(ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
        circuit_ref,
        witness.into_zeroizing_bytes(),
    )?)
}

fn bind_prover_toml(source: &str, binding: ZkSessionBinding) -> Result<String, HarnessError> {
    let mut challenge = false;
    let mut audience = false;
    let mut transaction = false;
    let mut out = String::new();
    for line in source.lines() {
        if field_line_is(line, "challenge") {
            write_bound_field(&mut out, "challenge", &binding.nonce_hash)?;
            challenge = true;
        } else if field_line_is(line, "audience_hash") {
            write_bound_field(&mut out, "audience_hash", &binding.audience_hash)?;
            audience = true;
        } else if field_line_is(line, "transaction_data_hash") {
            write_bound_field(
                &mut out,
                "transaction_data_hash",
                &binding.transaction_data_public_input(),
            )?;
            transaction = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !challenge || !audience || !transaction {
        return Err(HarnessError::MissingField);
    }
    Ok(out)
}

fn write_bound_field(out: &mut String, name: &str, bytes: &[u8; 32]) -> Result<(), HarnessError> {
    out.push_str(name);
    out.push_str(" = [");
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write!(out, "{byte}").map_err(|_| HarnessError::InvalidLength)?;
    }
    out.push_str("]\n");
    Ok(())
}

fn field_line_is(line: &str, name: &str) -> bool {
    line.split_once('=')
        .map(|(key, _value)| key.trim() == name)
        .unwrap_or(false)
}
