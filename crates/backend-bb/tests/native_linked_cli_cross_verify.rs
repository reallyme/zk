// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emits a linked-generated proof triplet for isolated official-CLI verification.

#![cfg(feature = "native")]

#[path = "support/modern_all30.rs"]
mod modern_all30;

use std::{fs, path::PathBuf};

use modern_all30::{
    binding_from_prover_toml_path, generate_witness_for_artifacts_with_toml,
    load_common_credential_root_public_session_evidence, read_g2, read_prover_g1_prefix,
    required_path, MatrixError, G1_PATH_ENV, G2_PATH_ENV, ROOT_ENV,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    proofs::ZkProofSuite,
};
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BbCommonCredentialRootRawProveRequest, NativeBarretenbergBackend,
};

const OUTPUT_DIR_ENV: &str = "REALLYME_LINKED_CLI_CROSS_VERIFY_OUTPUT_DIR";

#[test]
#[ignore = "requires linked Barretenberg, all-circuit artifacts, pinned BN254 CRS, and an output directory"]
fn linked_generated_common_credential_root_public_session_triplet_is_exported_for_cli_verify(
) -> Result<(), MatrixError> {
    let root = required_path(ROOT_ENV)?;
    let g1_path = required_path(G1_PATH_ENV)?;
    let g2_path = required_path(G2_PATH_ENV)?;
    let output_dir = required_output_dir()?;

    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::PublicSession,
    );
    let evidence = load_common_credential_root_public_session_evidence(&root, circuit_ref)?;
    let fixture_toml =
        root.join("sha256/families/common_credential_root_v1/session_fixtures/public/Prover.toml");
    let binding = binding_from_prover_toml_path(&fixture_toml)?;
    evidence.public_inputs.validate_session_binding(binding)?;

    let g1 = read_prover_g1_prefix(&g1_path)?;
    let g2 = read_g2(&g2_path)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1.as_slice(), &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(crs)?;

    let witness = generate_witness_for_artifacts_with_toml(
        evidence.circuit_ref,
        &evidence.artifacts,
        &fixture_toml,
    )?;
    let proved = backend.prove_common_credential_root_raw_exact_circuit(
        BbCommonCredentialRootRawProveRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            witness: &witness,
        },
    )?;
    let (proof_bytes, public_inputs) = proved.into_parts();
    public_inputs.validate_session_binding(binding)?;
    if public_inputs != evidence.public_inputs {
        return Err(MatrixError::EvidenceMismatch);
    }

    write_output_file(&output_dir, "proof", proof_bytes.as_bytes())?;
    write_output_file(&output_dir, "public_inputs", public_inputs.as_bytes())?;
    write_output_file(
        &output_dir,
        "vk",
        evidence.artifacts.verification_key().as_bytes(),
    )?;

    Ok(())
}

fn write_output_file(
    output_dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), MatrixError> {
    let path = output_dir.join(name);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(MatrixError::MissingField);
        }
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn required_output_dir() -> Result<PathBuf, MatrixError> {
    let output_dir = required_path(OUTPUT_DIR_ENV)?;
    if !output_dir.is_absolute() || output_dir.is_symlink() || !output_dir.is_dir() {
        return Err(MatrixError::MissingField);
    }
    Ok(output_dir)
}
