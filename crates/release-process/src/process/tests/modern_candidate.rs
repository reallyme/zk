// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    artifact_version, contains, fs, modern_compiled_artifact, Fixture, OsString, PathBuf,
    PinnedReleaseProcess, RecordingRunner, ReleaseCommand, ReleaseProcessError,
    ReleaseProcessErrorReason, ReleaseProcessRunner, ReleaseTool, ReleaseToolDigests,
    ReleaseToolOperation, ReleaseToolPaths, ReleaseToolchainProfile, SystemReleaseProcessRunner,
    ZkProofSuite,
};

#[test]
fn modern_candidate_versions_are_explicitly_attested() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new_for_profile(
        RecordingRunner::matching_for_profile(ReleaseToolchainProfile::ModernCandidate),
        fixture.paths()?,
        ReleaseToolchainProfile::ModernCandidate,
    )?;

    assert_eq!(process.profile(), ReleaseToolchainProfile::ModernCandidate);
    assert_eq!(process.toolchain().nargo_version().as_bytes(), b"1.0.0");
    assert_eq!(
        process.toolchain().barretenberg_version().as_bytes(),
        b"6.0.0"
    );
    let commands = process.runner.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].operation, ReleaseToolOperation::Version);
    assert_eq!(commands[1].operation, ReleaseToolOperation::Version);
    drop(commands);
    fixture.cleanup()
}
#[test]
fn version_self_report_cannot_override_executable_digest_identity(
) -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let runner = RecordingRunner::matching();
    let paths = ReleaseToolPaths::try_new(
        &fixture.nargo,
        &fixture.barretenberg,
        ReleaseToolDigests::new([7_u8; 32], [8_u8; 32]),
    );

    assert_eq!(
        paths.err().map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::ToolDigestMismatch(
            ReleaseTool::Nargo
        ))
    );
    assert!(runner.commands.borrow().is_empty());
    fixture.cleanup()
}

#[test]
fn post_admission_atomic_tool_replacement_is_rejected_before_invocation(
) -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let replacement = fixture.root.join("replacement-nargo");
    fs::write(&replacement, [1_u8, 2, 3, 4])?;
    fs::rename(&replacement, &fixture.nargo)?;
    let command = process.compile_command(&fixture.circuit, artifact_version("circuit_name")?)?;

    assert_eq!(
        process.run(&command).err().map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::ToolDigestMismatch(
            ReleaseTool::Nargo
        ))
    );
    assert_eq!(process.runner.commands.borrow().len(), 2);
    fixture.cleanup()
}

#[test]
fn compile_command_keeps_constraint_checks_enabled() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let command = process.compile_command(&fixture.circuit, artifact_version("circuit_name")?)?;

    assert_eq!(command.tool(), ReleaseTool::Nargo);
    assert_eq!(command.operation(), ReleaseToolOperation::Compile);
    assert_eq!(
        command.arguments(),
        [
            "compile",
            "--package",
            "circuit_name",
            "--deny-warnings",
            "--force"
        ]
        .map(OsString::from)
    );
    assert!(!contains(
        command.arguments(),
        "--skip-underconstrained-check"
    ));
    assert!(!contains(
        command.arguments(),
        "--skip-brillig-constraints-check"
    ));
    fixture.cleanup()
}

#[test]
fn execute_command_keeps_constraint_checks_enabled() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let command = process.execute_command(
        &fixture.circuit,
        artifact_version("circuit_name")?,
        artifact_version("Prover")?,
        artifact_version("release_witness")?,
    )?;

    assert_eq!(command.operation(), ReleaseToolOperation::Execute);
    assert!(contains(command.arguments(), "--deny-warnings"));
    assert!(!contains(command.arguments(), "--force"));
    assert!(!contains(
        command.arguments(),
        "--skip-underconstrained-check"
    ));
    assert!(!contains(
        command.arguments(),
        "--skip-brillig-constraints-check"
    ));
    fixture.cleanup()
}

#[test]
fn proof_command_pins_production_suite_without_ipa() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let output = fixture.root.join("proof-output");
    let command =
        process.prove_command(&fixture.crs, &fixture.bytecode, &fixture.witness, &output)?;

    assert_eq!(command.tool(), ReleaseTool::Barretenberg);
    assert_eq!(command.operation(), ReleaseToolOperation::Prove);
    assert!(contains(command.arguments(), "evm"));
    assert!(contains(command.arguments(), "binary"));
    assert!(!contains(command.arguments(), "--zk"));
    assert!(!contains(command.arguments(), "ultra_honk"));
    assert!(!contains(command.arguments(), "bytes_and_fields"));
    assert!(!contains(command.arguments(), "--ipa_accumulation"));
    assert!(!contains(command.arguments(), "poseidon2"));
    fixture.cleanup()
}

#[test]
fn modern_candidate_commands_match_barretenberg_five_target_cli() -> Result<(), ReleaseProcessError>
{
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new_for_profile(
        RecordingRunner::matching_for_profile(ReleaseToolchainProfile::ModernCandidate),
        fixture.paths()?,
        ReleaseToolchainProfile::ModernCandidate,
    )?;
    let key_output = fixture.root.join("modern-key-output");
    let proof_output = fixture.root.join("modern-proof-output");
    let write_key =
        process.write_verification_key_command(&fixture.crs, &fixture.bytecode, &key_output)?;
    let prove = process.prove_command_with_verification_key_for_suite(
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &proof_output,
        &fixture.verification_key,
        ZkProofSuite::PRODUCTION,
    )?;
    let verify = process.verify_command(
        &fixture.crs,
        &fixture.proof,
        &fixture.public_inputs,
        &fixture.verification_key,
    )?;

    assert_eq!(
        write_key.arguments(),
        [
            "write_vk",
            "-c",
            fixture.crs.to_str().unwrap_or_default(),
            "-b",
            fixture.bytecode.to_str().unwrap_or_default(),
            "-o",
            key_output.to_str().unwrap_or_default(),
            "-t",
            "evm",
            "--output_format",
            "binary"
        ]
        .map(OsString::from)
    );
    assert_eq!(
        prove.arguments(),
        [
            "prove",
            "-c",
            fixture.crs.to_str().unwrap_or_default(),
            "-b",
            fixture.bytecode.to_str().unwrap_or_default(),
            "-w",
            fixture.witness.to_str().unwrap_or_default(),
            "-o",
            proof_output.to_str().unwrap_or_default(),
            "-t",
            "evm",
            "--output_format",
            "binary",
            "-k",
            fixture.verification_key.to_str().unwrap_or_default(),
            "--verify"
        ]
        .map(OsString::from)
    );
    assert!(!contains(prove.arguments(), "--zk"));
    assert!(contains(verify.arguments(), "verify"));
    assert!(contains(verify.arguments(), "evm"));
    assert!(contains(verify.arguments(), "-c"));
    assert!(!contains(verify.arguments(), "--zk"));
    fixture.cleanup()
}

#[test]
fn modern_candidate_runner_rejects_missing_or_mismatched_crs_before_execution(
) -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let missing = fixture.root.join("missing-crs");
    let mismatch = fixture.root.join("mismatched-crs");
    fs::create_dir(&mismatch)?;
    fs::write(mismatch.join("bn254_g1.dat"), [1_u8, 2, 3])?;
    fs::write(mismatch.join("bn254_g2.dat"), [4_u8, 5, 6])?;
    let runner = SystemReleaseProcessRunner;

    for operation in [
        ReleaseToolOperation::WriteVerificationKey,
        ReleaseToolOperation::Prove,
        ReleaseToolOperation::Verify,
    ] {
        let missing_command = modern_candidate_barretenberg_command(operation, &missing);
        let mismatched_command = modern_candidate_barretenberg_command(operation, &mismatch);
        assert_eq!(
            runner
                .run(&missing_command)
                .err()
                .map(|error| error.reason()),
            Some(ReleaseProcessErrorReason::CrsIdentityMismatch)
        );
        assert_eq!(
            runner
                .run(&mismatched_command)
                .err()
                .map(|error| error.reason()),
            Some(ReleaseProcessErrorReason::CrsIdentityMismatch)
        );
    }

    fixture.cleanup()
}

fn modern_candidate_barretenberg_command(
    operation: ReleaseToolOperation,
    crs_directory: &std::path::Path,
) -> ReleaseCommand {
    let verb = match operation {
        ReleaseToolOperation::WriteVerificationKey => "write_vk",
        ReleaseToolOperation::Prove => "prove",
        ReleaseToolOperation::Verify => "verify",
        _ => "prove",
    };
    ReleaseCommand {
        tool: ReleaseTool::Barretenberg,
        operation,
        executable: PathBuf::from("/usr/bin/false"),
        current_directory: None,
        arguments: vec![
            OsString::from(verb),
            OsString::from("-c"),
            crs_directory.as_os_str().to_os_string(),
        ],
        capture_stdout: false,
    }
}

#[test]
fn verification_command_matches_the_production_proof_suite() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let command = process.verify_command(
        &fixture.crs,
        &fixture.proof,
        &fixture.public_inputs,
        &fixture.verification_key,
    )?;

    assert_eq!(command.operation(), ReleaseToolOperation::Verify);
    assert!(contains(command.arguments(), "evm"));
    assert!(!contains(command.arguments(), "ultra_honk"));
    assert!(!contains(command.arguments(), "--zk"));
    assert!(!contains(command.arguments(), "--ipa_accumulation"));
    assert!(!contains(command.arguments(), "poseidon2"));
    fixture.cleanup()
}

#[test]
fn poseidon2_unmasked_commands_are_explicit_and_do_not_enable_zk() -> Result<(), ReleaseProcessError>
{
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let proof_output = fixture.root.join("poseidon2-proof-output");
    let key_output = fixture.root.join("poseidon2-key-output");
    let suite = ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa;
    let write_key = process.write_verification_key_command_for_suite(
        &fixture.crs,
        &fixture.bytecode,
        &key_output,
        suite,
    )?;
    let prove = process.prove_command_for_suite(
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &proof_output,
        suite,
    )?;
    let verify = process.verify_command_for_suite(
        &fixture.crs,
        &fixture.proof,
        &fixture.public_inputs,
        &fixture.verification_key,
        suite,
    )?;

    for command in [&write_key, &prove, &verify] {
        assert!(contains(command.arguments(), "noir-recursive-no-zk"));
        assert!(!contains(command.arguments(), "evm"));
        assert!(!contains(command.arguments(), "--zk"));
        assert!(!contains(command.arguments(), "--ipa_accumulation"));
    }
    fixture.cleanup()
}

#[test]
fn keccak_unmasked_commands_never_enable_zk() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let proof_output = fixture.root.join("keccak-unmasked-proof-output");
    let key_output = fixture.root.join("keccak-unmasked-key-output");
    let suite = ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa;
    let write_key = process.write_verification_key_command_for_suite(
        &fixture.crs,
        &fixture.bytecode,
        &key_output,
        suite,
    )?;
    let prove = process.prove_command_for_suite(
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &proof_output,
        suite,
    )?;
    let verify = process.verify_command_for_suite(
        &fixture.crs,
        &fixture.proof,
        &fixture.public_inputs,
        &fixture.verification_key,
        suite,
    )?;

    for command in [&write_key, &prove, &verify] {
        assert!(contains(command.arguments(), "evm-no-zk"));
        assert!(!contains(command.arguments(), "noir-recursive"));
        assert!(!contains(command.arguments(), "--zk"));
        assert!(!contains(command.arguments(), "--ipa_accumulation"));
    }
    fixture.cleanup()
}

#[test]
fn poseidon2_zk_commands_select_recursive_target() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;
    let output = fixture.root.join("poseidon2-zk-proof-output");
    let command = process.prove_command_for_suite(
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &output,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa,
    )?;

    assert!(contains(command.arguments(), "noir-recursive"));
    assert!(!contains(command.arguments(), "noir-recursive-no-zk"));
    assert!(!contains(command.arguments(), "--zk"));
    fixture.cleanup()
}

#[test]
fn modern_candidate_accepts_beta25_artifact_identity() -> Result<(), ReleaseProcessError> {
    let fresh = modern_compiled_artifact(32, "acir", 1);
    let packaged = modern_compiled_artifact(32, "acir", 2);

    crate::artifact_compatibility::ensure_compiled_program_execution_compatible_for_profile(
        &fresh,
        &packaged,
        ReleaseToolchainProfile::ModernCandidate,
    )?;
    crate::artifact_compatibility::validate_compiled_program_artifact_for_profile(
        &fresh,
        ReleaseToolchainProfile::ModernCandidate,
    )?;
    let normalized =
        crate::artifact_compatibility::normalize_compiled_program_artifact_for_profile(
            &fresh,
            ReleaseToolchainProfile::ModernCandidate,
        )?;
    crate::artifact_compatibility::validate_compiled_program_artifact_for_profile(
        &normalized,
        ReleaseToolchainProfile::ModernCandidate,
    )
}
