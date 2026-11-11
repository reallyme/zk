// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the ReallyMe ZK runtime CLI.

#[path = "support/retained_cli_fixture.rs"]
mod retained_cli_fixture;

use std::fs;

use reallyme_zk_api::{circuits::ZkCircuitRef, errors::ZkError};
use reallyme_zk_cli::{run, CliError, CliErrorReason, CliExit};
use retained_cli_fixture::{
    RetainedCliFixture, RetainedCliFixturePaths, TestWorkspace, PROOF_FILE,
};
use thiserror::Error;

#[derive(Debug, Error)]
enum CliTestError {
    #[error("CLI output was not valid UTF-8")]
    InvalidUtf8,
    #[error("I/O failed")]
    Io(#[from] std::io::Error),
    #[error("missing fixture")]
    MissingFixture,
    #[error("unexpected retained fixture schema")]
    UnexpectedSchema,
    #[error("missing retained fixture field")]
    MissingField,
    #[error("unexpected retained fixture length")]
    UnexpectedLength,
    #[error("resource exhausted")]
    ResourceExhausted,
    #[error("length overflow")]
    LengthOverflow,
    #[error("zk failure")]
    Zk(#[from] ZkError),
}

fn decode_output(bytes: Vec<u8>) -> Result<String, CliTestError> {
    String::from_utf8(bytes).map_err(|_| CliTestError::InvalidUtf8)
}

#[test]
fn help_lists_supported_commands() -> Result<(), CliTestError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(["reallyme-zk", "help"], &mut stdout, &mut stderr);

    assert_eq!(exit, Ok(CliExit::Success));
    assert!(stderr.is_empty());
    let text = decode_output(stdout)?;
    assert!(text.contains("toolchain"));
    assert!(text.contains("circuits"));
    assert!(text.contains("witness"));
    assert!(text.contains("prove-stage"));
    assert!(text.contains("verify-stage"));
    assert!(text.contains("validate-artifacts"));
    assert!(text.contains("doctor"));
    Ok(())
}

#[test]
fn circuits_lists_all_registered_circuit_refs() -> Result<(), CliTestError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(["reallyme-zk", "circuits"], &mut stdout, &mut stderr);

    assert_eq!(exit, Ok(CliExit::Success));
    assert!(stderr.is_empty());
    let text = decode_output(stdout)?;
    assert_eq!(text.lines().count(), ZkCircuitRef::ALL.len() + 1);
    assert!(text.contains("sha256:credential_subject_claim_v1:session:v1"));
    assert!(text.contains("poseidon2:persona_credential_evidence_v1:public_claim:v1"));
    assert!(text.contains("sha256:common_credential_root_v1:lineage:v1"));
    assert!(text.contains("poseidon2:common_credential_root_v1:root_status:v1"));
    Ok(())
}

#[test]
fn circuits_paths_export_matches_source_layout() -> Result<(), CliTestError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(
        ["reallyme-zk", "circuits", "--paths"],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, Ok(CliExit::Success));
    assert!(stderr.is_empty());
    let text = decode_output(stdout)?;
    assert_eq!(text.lines().count(), ZkCircuitRef::ALL.len() + 1);
    assert!(text.contains("sha256/families/credential_subject_claim_v1/session"));
    assert!(text.contains("poseidon2/families/persona_credential_evidence_v1/public_claim"));
    assert!(text.contains("sha256/families/common_credential_root_v1/lineage"));
    Ok(())
}

#[test]
fn doctor_reports_pending_gate_as_not_ready() -> Result<(), CliTestError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(["reallyme-zk", "doctor"], &mut stdout, &mut stderr);

    assert_eq!(exit, Ok(CliExit::Failure));
    assert!(stderr.is_empty());
    let text = decode_output(stdout)?;
    assert!(text.contains("doctor: not-ready"));
    assert!(text.contains("provider_backend: linked-barretenberg-required"));
    assert!(text.contains("modern_gate: pending"));
    Ok(())
}

#[test]
fn unknown_command_returns_usage_status() -> Result<(), CliTestError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(["reallyme-zk", "prove"], &mut stdout, &mut stderr);

    assert_eq!(exit, Ok(CliExit::Usage));
    assert!(stdout.is_empty());
    let text = decode_output(stderr)?;
    assert_eq!(text, "error: unknown-command\n");
    Ok(())
}

#[test]
fn witness_rejects_duplicate_flags_without_reading_files() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(
        [
            "reallyme-zk",
            "witness",
            "--circuit",
            "sha256:private_persona_claim_v1:session:v1",
            "--circuit",
            "sha256:private_persona_claim_v1:session:v1",
        ],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, Err(CliError::new(CliErrorReason::UnexpectedArgument)));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn verify_stage_rejects_prove_only_inputs() {
    let digest = "0101010101010101010101010101010101010101010101010101010101010101";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(
        [
            "reallyme-zk",
            "verify-stage",
            "--bundle-kind",
            "private_persona_claim_v1",
            "--stage",
            "session",
            "--hash-strategy",
            "sha256",
            "--manifest",
            "/tmp/manifest.pb",
            "--bytecode",
            "/tmp/program.acir",
            "--verification-key",
            "/tmp/vk",
            "--proof",
            "/tmp/proof.pb",
            "--crs-g1",
            "/tmp/g1",
            "--crs-g2",
            "/tmp/g2",
            "--nonce-hash",
            digest,
            "--audience-hash",
            digest,
        ],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, Err(CliError::new(CliErrorReason::UnexpectedArgument)));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[cfg(not(feature = "native"))]
#[test]
fn valid_stage_command_reports_backend_unavailable() {
    let digest = "0101010101010101010101010101010101010101010101010101010101010101";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run(
        [
            "reallyme-zk",
            "verify-stage",
            "--bundle-kind",
            "private_persona_claim_v1",
            "--stage",
            "session",
            "--hash-strategy",
            "sha256",
            "--manifest",
            "/tmp/manifest.pb",
            "--verification-key",
            "/tmp/vk",
            "--proof",
            "/tmp/proof.pb",
            "--crs-g1",
            "/tmp/g1",
            "--crs-g2",
            "/tmp/g2",
            "--nonce-hash",
            digest,
            "--audience-hash",
            digest,
        ],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, Err(CliError::new(CliErrorReason::BackendUnavailable)));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());

    let mut prove_stdout = Vec::new();
    let mut prove_stderr = Vec::new();
    let prove_exit = run(
        [
            "reallyme-zk",
            "prove-stage",
            "--bundle-kind",
            "private_persona_claim_v1",
            "--stage",
            "session",
            "--hash-strategy",
            "sha256",
            "--manifest",
            "/tmp/manifest.pb",
            "--bytecode",
            "/tmp/program.acir",
            "--verification-key",
            "/tmp/vk",
            "--witness",
            "/tmp/witness",
            "--crs-g1",
            "/tmp/g1",
            "--crs-g2",
            "/tmp/g2",
            "--nonce-hash",
            digest,
            "--audience-hash",
            digest,
            "--out",
            "/tmp/proof.pb",
        ],
        &mut prove_stdout,
        &mut prove_stderr,
    );
    assert_eq!(
        prove_exit,
        Err(CliError::new(CliErrorReason::BackendUnavailable))
    );
    assert!(prove_stdout.is_empty());
    assert!(prove_stderr.is_empty());
}

#[test]
fn opt_in_witness_command_generates_retained_fixture_witness() -> Result<(), CliTestError> {
    let Some(root) = std::env::var_os("REALLYME_ZK_ALL_CIRCUITS_V1_ROOT") else {
        return Ok(());
    };
    let circuit_dir = std::path::PathBuf::from(root)
        .join("sha256")
        .join("families")
        .join("private_persona_claim_v1")
        .join("session");
    let artifact_json = single_file_with_extension(&circuit_dir.join("target"), "json")?;
    let prover_toml = circuit_dir.join("Prover.toml");
    let output = std::env::temp_dir().join(format!(
        "reallyme-zk-cli-witness-{}-{}.gz",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    match std::fs::remove_file(&output) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CliTestError::Io(error)),
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(
        [
            std::ffi::OsString::from("reallyme-zk"),
            std::ffi::OsString::from("witness"),
            std::ffi::OsString::from("--circuit"),
            std::ffi::OsString::from("sha256:private_persona_claim_v1:session:v1"),
            std::ffi::OsString::from("--artifact-json"),
            artifact_json.into_os_string(),
            std::ffi::OsString::from("--prover-toml"),
            prover_toml.into_os_string(),
            std::ffi::OsString::from("--out"),
            output.clone().into_os_string(),
        ],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, Ok(CliExit::Success));
    assert!(stderr.is_empty());
    assert_eq!(decode_output(stdout)?, "witness: ok\n");
    let metadata = std::fs::metadata(&output)?;
    assert!(metadata.len() > 0);
    std::fs::remove_file(output)?;
    Ok(())
}

#[test]
fn opt_in_prove_and_verify_commands_use_linked_backend() -> Result<(), CliTestError> {
    let Some(paths) = RetainedCliFixturePaths::from_environment() else {
        return Ok(());
    };
    let fixture = RetainedCliFixture::load(paths)?;
    let workspace = TestWorkspace::create("reallyme-zk-cli-prove-verify")?;
    fixture.write_inputs(workspace.path())?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let prove_exit = run(
        fixture.prove_args(workspace.path()),
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(prove_exit, Ok(CliExit::Success));
    assert!(stderr.is_empty());
    assert_eq!(decode_output(stdout)?, "prove-stage: ok\n");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let verify_exit = run(
        fixture.verify_args(workspace.path()),
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(verify_exit, Ok(CliExit::Success));
    assert!(stderr.is_empty());
    assert_eq!(
        decode_output(stdout)?,
        "verify-stage: diagnostic-stage-proof-ok; not-presentation-admission\n"
    );

    let mut wrong_nonce = fixture.binding;
    wrong_nonce[0] ^= 1;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let wrong_binding_exit = run(
        fixture.verify_args_with_nonce(workspace.path(), wrong_nonce),
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(
        wrong_binding_exit,
        Err(CliError::new(CliErrorReason::VerificationFailed))
    );
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());

    let tampered_proof = workspace.path().join("tampered-proof.pb");
    let mut proof_bytes = fs::read(workspace.path().join(PROOF_FILE))?;
    let Some(last) = proof_bytes.last_mut() else {
        return Err(CliTestError::UnexpectedLength);
    };
    *last ^= 1;
    fs::write(&tampered_proof, proof_bytes)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let tampered_exit = run(
        fixture.verify_args_with_proof(workspace.path(), &tampered_proof),
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(
        tampered_exit,
        Err(CliError::new(CliErrorReason::VerificationFailed))
    );
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    Ok(())
}

fn single_file_with_extension(
    directory: &std::path::Path,
    extension: &str,
) -> Result<std::path::PathBuf, CliTestError> {
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .extension()
            .and_then(|actual| actual.to_str())
            .is_some_and(|actual| actual == extension)
        {
            matches.push(path);
        }
    }
    matches.sort();
    if matches.len() != 1 {
        return Err(CliTestError::MissingFixture);
    }
    matches.pop().ok_or(CliTestError::MissingFixture)
}
