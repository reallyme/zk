// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    artifact_version, compiled_artifact, fs, test_circuit_ref, BarretenbergPublicInputCodec,
    ExistingReleaseProofPaths, Fixture, GeneratingRunner, PinnedReleaseProcess,
    ReleaseGenerationPaths, ReleaseProcessError, ReleaseProcessErrorReason, ReleaseTool,
    ReleaseToolOperation, ReleaseWitnessMaterialPaths,
};

#[test]
fn complete_generation_cycle_destroys_witness_after_verification() -> Result<(), ReleaseProcessError>
{
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(
        GeneratingRunner::new(fixture.circuit.clone(), fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let generation = ReleaseGenerationPaths::try_new(
        test_circuit_ref(),
        &fixture.circuit,
        &fixture.crs,
        &fixture.proof_cycle_output,
        artifact_version("circuit_name")?,
    )?;

    let completed = process.generate_and_verify(generation)?;

    assert!(!fixture
        .circuit
        .join("target/release_witness.gz")
        .try_exists()?);
    assert_eq!(completed.material().proof().as_bytes(), [4_u8]);
    let operations = process
        .runner
        .recording
        .commands
        .borrow()
        .iter()
        .map(|command| command.operation)
        .collect::<Vec<_>>();
    assert_eq!(
        operations,
        [
            ReleaseToolOperation::Version,
            ReleaseToolOperation::Version,
            ReleaseToolOperation::Compile,
            ReleaseToolOperation::Execute,
            ReleaseToolOperation::WriteVerificationKey,
            ReleaseToolOperation::Prove,
            ReleaseToolOperation::Verify,
        ]
    );
    drop(completed);
    fixture.cleanup()
}

#[test]
fn complete_generation_admits_exact_witness_before_destroying_file(
) -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(
        GeneratingRunner::new(fixture.circuit.clone(), fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let generation = ReleaseGenerationPaths::try_new(
        test_circuit_ref(),
        &fixture.circuit,
        &fixture.crs,
        &fixture.proof_cycle_output,
        artifact_version("circuit_name")?,
    )?;

    let material = process.generate_verify_and_load_material(generation)?;

    assert_eq!(material.witness().circuit_ref(), test_circuit_ref());
    assert_eq!(material.witness().expose_bytes(), [1_u8, 2, 3, 4]);
    assert_eq!(material.proof_material().circuit_ref(), test_circuit_ref());
    assert!(!fixture
        .circuit
        .join("target/release_witness.gz")
        .try_exists()?);
    drop(material);
    fixture.cleanup()
}

#[test]
fn retained_proof_reverification_regenerates_only_the_witness() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let target = fixture.circuit.join("target");
    fs::create_dir(&target)?;
    let compiled_program = target.join("circuit_name.json");
    fs::write(&compiled_program, compiled_artifact(32, "acir", 1))?;
    fs::write(&fixture.verification_key, [3_u8])?;
    fs::write(&fixture.proof, [4_u8])?;
    let public_input_len = BarretenbergPublicInputCodec::serialized_len(test_circuit_ref())
        .map_err(|_| {
            ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidReleaseOutput(
                crate::ReleaseOutputKind::PublicInputs,
            ))
        })?;
    fs::write(&fixture.public_inputs, vec![0_u8; public_input_len])?;
    let process = PinnedReleaseProcess::try_new(
        GeneratingRunner::new(fixture.circuit.clone(), fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let proof_paths = ExistingReleaseProofPaths::try_new(
        test_circuit_ref(),
        &fixture.crs,
        &compiled_program,
        &fixture.verification_key,
        &fixture.proof,
        &fixture.public_inputs,
    )?;
    let paths = ReleaseWitnessMaterialPaths::try_new(
        &fixture.circuit,
        artifact_version("circuit_name")?,
        proof_paths,
    )?;

    let material = process.regenerate_witness_and_load_material(paths)?;

    assert_eq!(material.witness().expose_bytes(), [1_u8, 2, 3, 4]);
    assert_eq!(material.proof_material().proof().as_bytes(), [4_u8]);
    assert!(!fixture
        .circuit
        .join("target/release_witness.gz")
        .try_exists()?);
    let operations = process
        .runner
        .recording
        .commands
        .borrow()
        .iter()
        .map(|command| command.operation)
        .collect::<Vec<_>>();
    assert_eq!(
        operations,
        [
            ReleaseToolOperation::Version,
            ReleaseToolOperation::Version,
            ReleaseToolOperation::Execute,
            ReleaseToolOperation::WriteVerificationKey,
            ReleaseToolOperation::Verify,
        ]
    );
    drop(material);
    fixture.cleanup()
}

#[test]
fn failed_generation_cycle_still_destroys_witness() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(
        GeneratingRunner::failing(
            fixture.circuit.clone(),
            fixture.proof_cycle_output.clone(),
            ReleaseToolOperation::Prove,
        ),
        fixture.paths()?,
    )?;
    let generation = ReleaseGenerationPaths::try_new(
        test_circuit_ref(),
        &fixture.circuit,
        &fixture.crs,
        &fixture.proof_cycle_output,
        artifact_version("circuit_name")?,
    )?;

    let reason = process
        .generate_and_verify(generation)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ReleaseProcessErrorReason::ProcessFailed {
            tool: ReleaseTool::Barretenberg,
            operation: ReleaseToolOperation::Prove,
        })
    );
    assert!(!fixture
        .circuit
        .join("target/release_witness.gz")
        .try_exists()?);
    fixture.cleanup()
}

#[cfg(unix)]
#[test]
fn generation_rejects_dangling_witness_symlink_before_execute() -> Result<(), ReleaseProcessError> {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::create()?;
    let target = fixture.circuit.join("target");
    fs::create_dir(&target)?;
    let external = fixture.root.join("must-not-be-created");
    symlink(&external, target.join("release_witness.gz"))?;
    let process = PinnedReleaseProcess::try_new(
        GeneratingRunner::new(fixture.circuit.clone(), fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let generation = ReleaseGenerationPaths::try_new(
        test_circuit_ref(),
        &fixture.circuit,
        &fixture.crs,
        &fixture.proof_cycle_output,
        artifact_version("circuit_name")?,
    )?;

    let reason = process
        .generate_and_verify(generation)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ReleaseProcessErrorReason::InvalidPath));
    assert!(!external.try_exists()?);
    assert!(!process
        .runner
        .recording
        .commands
        .borrow()
        .iter()
        .any(|command| command.operation == ReleaseToolOperation::Execute));
    fixture.cleanup()
}

#[cfg(unix)]
#[test]
fn generation_forces_private_target_directory_permissions() -> Result<(), ReleaseProcessError> {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::create()?;
    let target = fixture.circuit.join("target");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
    let process = PinnedReleaseProcess::try_new(
        GeneratingRunner::new(fixture.circuit.clone(), fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let generation = ReleaseGenerationPaths::try_new(
        test_circuit_ref(),
        &fixture.circuit,
        &fixture.crs,
        &fixture.proof_cycle_output,
        artifact_version("circuit_name")?,
    )?;

    let completed = process.generate_and_verify(generation)?;
    let mode = fs::symlink_metadata(&target)?.permissions().mode() & 0o777;

    assert_eq!(mode, 0o700);
    drop(completed);
    fixture.cleanup()
}
