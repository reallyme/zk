// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    cell::RefCell,
    ffi::OsString,
    fs::{self, File},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{ArtifactVersion, Digest32};
use reallyme_zk_backend_bb::BarretenbergPublicInputCodec;

use super::profile::{
    MODERN_CANDIDATE_BARRETENBERG_VERSION_LINE, MODERN_CANDIDATE_NARGO_VERSION_LINE,
    MODERN_CANDIDATE_NOIRC_VERSION_LINE, PINNED_BARRETENBERG_VERSION_LINE,
    PINNED_NARGO_VERSION_LINE, PINNED_NOIRC_VERSION_LINE,
};
use crate::{
    ensure_compiled_program_execution_compatible, normalize_compiled_program_artifact,
    validate_compiled_program_artifact, ExistingReleaseProofPaths, PinnedReleaseProcess,
    ReleaseCommand, ReleaseGenerationPaths, ReleaseProcessError, ReleaseProcessErrorReason,
    ReleaseProcessOutput, ReleaseProcessRunner, ReleaseProofCyclePaths, ReleaseTool,
    ReleaseToolDigests, ReleaseToolOperation, ReleaseToolPaths, ReleaseToolchainProfile,
    ReleaseWitnessMaterialPaths, SystemReleaseProcessRunner, MAX_COMPILED_PROGRAM_ARTIFACT_BYTES,
};

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RecordedCommand {
    tool: ReleaseTool,
    operation: ReleaseToolOperation,
    arguments: Vec<OsString>,
}

struct RecordingRunner {
    mismatch: Option<ReleaseTool>,
    profile: ReleaseToolchainProfile,
    commands: RefCell<Vec<RecordedCommand>>,
}

impl RecordingRunner {
    fn matching() -> Self {
        Self::matching_for_profile(ReleaseToolchainProfile::LegacyProduction)
    }

    fn matching_for_profile(profile: ReleaseToolchainProfile) -> Self {
        Self {
            mismatch: None,
            profile,
            commands: RefCell::new(Vec::new()),
        }
    }

    fn mismatching(tool: ReleaseTool) -> Self {
        Self {
            mismatch: Some(tool),
            profile: ReleaseToolchainProfile::LegacyProduction,
            commands: RefCell::new(Vec::new()),
        }
    }
}

impl ReleaseProcessRunner for RecordingRunner {
    fn run(&self, command: &ReleaseCommand) -> Result<ReleaseProcessOutput, ReleaseProcessError> {
        self.commands.borrow_mut().push(RecordedCommand {
            tool: command.tool(),
            operation: command.operation(),
            arguments: command.arguments().to_vec(),
        });
        let stdout = match command.tool() {
            ReleaseTool::Nargo if self.mismatch == Some(ReleaseTool::Nargo) => b"wrong".to_vec(),
            ReleaseTool::Nargo => match self.profile {
                ReleaseToolchainProfile::LegacyProduction => {
                    [PINNED_NARGO_VERSION_LINE, PINNED_NOIRC_VERSION_LINE].join(&b'\n')
                }
                ReleaseToolchainProfile::ModernCandidate => [
                    MODERN_CANDIDATE_NARGO_VERSION_LINE,
                    MODERN_CANDIDATE_NOIRC_VERSION_LINE,
                ]
                .join(&b'\n'),
            },
            ReleaseTool::Barretenberg if self.mismatch == Some(ReleaseTool::Barretenberg) => {
                b"wrong".to_vec()
            }
            ReleaseTool::Barretenberg => match self.profile {
                ReleaseToolchainProfile::LegacyProduction => PINNED_BARRETENBERG_VERSION_LINE,
                ReleaseToolchainProfile::ModernCandidate => {
                    MODERN_CANDIDATE_BARRETENBERG_VERSION_LINE
                }
            }
            .to_vec(),
        };
        Ok(ReleaseProcessOutput { stdout })
    }
}

struct MaterializingRunner {
    recording: RecordingRunner,
    output: PathBuf,
}

impl MaterializingRunner {
    fn new(output: PathBuf) -> Self {
        Self {
            recording: RecordingRunner::matching(),
            output,
        }
    }
}

impl ReleaseProcessRunner for MaterializingRunner {
    fn run(&self, command: &ReleaseCommand) -> Result<ReleaseProcessOutput, ReleaseProcessError> {
        let output = self.recording.run(command)?;
        match command.operation() {
            ReleaseToolOperation::WriteVerificationKey => {
                let directory = output_directory(command)?;
                fs::create_dir(&directory)?;
                fs::write(directory.join("vk"), [3_u8])?;
                fs::write(directory.join("vk_hash"), [5_u8])?;
            }
            ReleaseToolOperation::Prove => {
                let directory = self.output.join("proof");
                fs::create_dir(&directory)?;
                fs::write(directory.join("proof"), [4_u8])?;
                let public_input_len = BarretenbergPublicInputCodec::serialized_len(
                    test_circuit_ref(),
                )
                .map_err(|_| {
                    ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidReleaseOutput(
                        crate::ReleaseOutputKind::PublicInputs,
                    ))
                })?;
                fs::write(
                    directory.join("public_inputs"),
                    vec![0_u8; public_input_len],
                )?;
            }
            ReleaseToolOperation::Version
            | ReleaseToolOperation::Compile
            | ReleaseToolOperation::Execute
            | ReleaseToolOperation::Verify => {}
        }
        Ok(output)
    }
}

struct GeneratingRunner {
    recording: RecordingRunner,
    circuit: PathBuf,
    output: PathBuf,
    fail_operation: Option<ReleaseToolOperation>,
}

impl GeneratingRunner {
    fn new(circuit: PathBuf, output: PathBuf) -> Self {
        Self {
            recording: RecordingRunner::matching(),
            circuit,
            output,
            fail_operation: None,
        }
    }

    fn failing(circuit: PathBuf, output: PathBuf, operation: ReleaseToolOperation) -> Self {
        Self {
            recording: RecordingRunner::matching(),
            circuit,
            output,
            fail_operation: Some(operation),
        }
    }
}

impl ReleaseProcessRunner for GeneratingRunner {
    fn run(&self, command: &ReleaseCommand) -> Result<ReleaseProcessOutput, ReleaseProcessError> {
        let output = self.recording.run(command)?;
        if self.fail_operation == Some(command.operation()) {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::ProcessFailed {
                    tool: command.tool(),
                    operation: command.operation(),
                },
            ));
        }
        match command.operation() {
            ReleaseToolOperation::Compile => {
                let target = self.circuit.join("target");
                match fs::create_dir(&target) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&target)?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(ReleaseProcessError::new(
                                ReleaseProcessErrorReason::InvalidPath,
                            ));
                        }
                    }
                    Err(error) => return Err(ReleaseProcessError::from(error)),
                }
                fs::write(
                    target.join("circuit_name.json"),
                    compiled_artifact(32, "acir", 1),
                )?;
            }
            ReleaseToolOperation::Execute => {
                fs::write(
                    self.circuit.join("target/release_witness.gz"),
                    [1_u8, 2, 3, 4],
                )?;
            }
            ReleaseToolOperation::WriteVerificationKey => {
                let directory = output_directory(command)?;
                fs::create_dir(&directory)?;
                fs::write(directory.join("vk"), [3_u8])?;
                fs::write(directory.join("vk_hash"), [5_u8])?;
            }
            ReleaseToolOperation::Prove => {
                let directory = self.output.join("proof");
                fs::create_dir(&directory)?;
                fs::write(directory.join("proof"), [4_u8])?;
                let public_input_len = BarretenbergPublicInputCodec::serialized_len(
                    test_circuit_ref(),
                )
                .map_err(|_| {
                    ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidReleaseOutput(
                        crate::ReleaseOutputKind::PublicInputs,
                    ))
                })?;
                fs::write(
                    directory.join("public_inputs"),
                    vec![0_u8; public_input_len],
                )?;
            }
            ReleaseToolOperation::Version | ReleaseToolOperation::Verify => {}
        }
        Ok(output)
    }
}

struct Fixture {
    root: PathBuf,
    nargo: PathBuf,
    barretenberg: PathBuf,
    circuit: PathBuf,
    crs: PathBuf,
    bytecode: PathBuf,
    witness: PathBuf,
    proof: PathBuf,
    public_inputs: PathBuf,
    verification_key: PathBuf,
    proof_cycle_output: PathBuf,
}

impl Fixture {
    fn create() -> Result<Self, ReleaseProcessError> {
        let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "reallyme-zk-release-process-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        let nargo = root.join("nargo");
        let barretenberg = root.join("bb");
        let circuit = root.join("circuit");
        let crs = root.join("crs");
        let bytecode = root.join("program.json");
        let witness = root.join("witness.gz");
        let proof = root.join("proof");
        let public_inputs = root.join("public-inputs");
        let verification_key = root.join("verification-key");
        let proof_cycle_output = root.join("proof-cycle-output");
        let _nargo_file = File::create(&nargo)?;
        let _barretenberg_file = File::create(&barretenberg)?;
        fs::write(&bytecode, compiled_artifact(32, "acir", 1))?;
        let _witness_file = File::create(&witness)?;
        let _proof_file = File::create(&proof)?;
        let _public_inputs_file = File::create(&public_inputs)?;
        let _verification_key_file = File::create(&verification_key)?;
        fs::create_dir(&circuit)?;
        fs::create_dir(&crs)?;
        fs::create_dir(&proof_cycle_output)?;
        Ok(Self {
            root,
            nargo,
            barretenberg,
            circuit,
            crs,
            bytecode,
            witness,
            proof,
            public_inputs,
            verification_key,
            proof_cycle_output,
        })
    }

    fn paths(&self) -> Result<ReleaseToolPaths<'_>, ReleaseProcessError> {
        ReleaseToolPaths::try_new(&self.nargo, &self.barretenberg, self.tool_digests()?)
    }

    fn tool_digests(&self) -> Result<ReleaseToolDigests, ReleaseProcessError> {
        let nargo = fs::read(&self.nargo)?;
        let barretenberg = fs::read(&self.barretenberg)?;
        Ok(ReleaseToolDigests::new(
            *Digest32::sha256(&nargo).as_bytes(),
            *Digest32::sha256(&barretenberg).as_bytes(),
        ))
    }

    fn cleanup(self) -> Result<(), ReleaseProcessError> {
        fs::remove_dir_all(self.root)?;
        Ok(())
    }
}

fn artifact_version(value: &str) -> Result<ArtifactVersion, ReleaseProcessError> {
    ArtifactVersion::try_from_token(value)
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidPath))
}

const fn test_circuit_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    )
}

fn contains(arguments: &[OsString], value: &str) -> bool {
    arguments.iter().any(|argument| argument == value)
}

fn output_directory(command: &ReleaseCommand) -> Result<PathBuf, ReleaseProcessError> {
    let output_flag_index = command
        .arguments()
        .iter()
        .position(|argument| argument == "-o")
        .ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ))?;
    let output_index = output_flag_index
        .checked_add(1)
        .ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ))?;
    command
        .arguments()
        .get(output_index)
        .map(PathBuf::from)
        .ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ))
}

fn compiled_artifact(abi_width: u8, bytecode: &str, metadata_marker: u8) -> Vec<u8> {
    compiled_artifact_for_noirc(
        "1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c",
        abi_width,
        bytecode,
        metadata_marker,
    )
}

fn modern_compiled_artifact(abi_width: u8, bytecode: &str, metadata_marker: u8) -> Vec<u8> {
    compiled_artifact_for_noirc(
        "1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c",
        abi_width,
        bytecode,
        metadata_marker,
    )
}

fn compiled_artifact_for_noirc(
    noirc_version: &str,
    abi_width: u8,
    bytecode: &str,
    metadata_marker: u8,
) -> Vec<u8> {
    format!(
        "{{\"noir_version\":\"{noirc_version}\",\"hash\":\"{metadata_marker}\",\"abi\":{{\"width\":{abi_width}}},\"bytecode\":\"{bytecode}\",\"debug_symbols\":\"{metadata_marker}\",\"file_map\":{{\"1\":{{\"source\":\"fn main() {{}}\",\"path\":\"/tmp/build-{metadata_marker}/src/main.nr\"}}}}}}"
    )
    .into_bytes()
}

#[test]
fn compiled_artifact_compatibility_allows_only_metadata_drift() -> Result<(), ReleaseProcessError> {
    let freshly_compiled = compiled_artifact(32, "acir", 1);
    let packaged = compiled_artifact(32, "acir", 2);

    ensure_compiled_program_execution_compatible(&freshly_compiled, &packaged)
}

#[test]
fn compiled_artifact_compatibility_rejects_abi_and_bytecode_drift() {
    let baseline = compiled_artifact(32, "acir", 1);
    let abi_drift = compiled_artifact(64, "acir", 1);
    let bytecode_drift = compiled_artifact(32, "different", 1);

    assert_eq!(
        ensure_compiled_program_execution_compatible(&baseline, &abi_drift)
            .err()
            .map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch)
    );
    assert_eq!(
        ensure_compiled_program_execution_compatible(&baseline, &bytecode_drift)
            .err()
            .map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch)
    );
}

#[test]
fn compiled_artifact_compatibility_rejects_unpinned_noirc() {
    let baseline = compiled_artifact(32, "acir", 1);
    let unpinned = baseline
        .iter()
        .copied()
        .map(|byte| if byte == b'6' { b'7' } else { byte })
        .collect::<Vec<_>>();

    assert_eq!(
        ensure_compiled_program_execution_compatible(&baseline, &unpinned)
            .err()
            .map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::CompiledArtifactToolchainMismatch)
    );
}

#[test]
fn compiled_artifact_boundary_rejects_duplicate_and_recursive_fields() {
    const VERSION: &str = "1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c";
    let duplicate = format!(
        "{{\"noir_version\":\"{VERSION}\",\"noir_version\":\"{VERSION}\",\"abi\":{{}},\"bytecode\":\"acir\"}}"
    );
    let recursive_abi = format!(
        "{{\"noir_version\":\"{VERSION}\",\"abi\":{}0{},\"bytecode\":\"acir\"}}",
        "[".repeat(129),
        "]".repeat(129),
    );

    for artifact in [duplicate.as_bytes(), recursive_abi.as_bytes()] {
        assert_eq!(
            validate_compiled_program_artifact(artifact)
                .err()
                .map(|error| error.reason()),
            Some(ReleaseProcessErrorReason::MalformedCompiledArtifact)
        );
    }
}

#[test]
fn compiled_artifact_boundary_rejects_empty_and_oversized_inputs() {
    let oversized = vec![b' '; MAX_COMPILED_PROGRAM_ARTIFACT_BYTES + 1];
    for artifact in [&[][..], oversized.as_slice()] {
        assert_eq!(
            validate_compiled_program_artifact(artifact)
                .err()
                .map(|error| error.reason()),
            Some(ReleaseProcessErrorReason::MalformedCompiledArtifact)
        );
    }
}

#[test]
fn exact_versions_are_attested_before_commands_are_available() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;

    assert_eq!(process.toolchain().nargo_version().as_bytes(), b"1.0.0");
    assert_eq!(
        process.toolchain().barretenberg_version().as_bytes(),
        b"6.0.0"
    );
    let commands = process.runner.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].tool, ReleaseTool::Nargo);
    assert_eq!(commands[0].operation, ReleaseToolOperation::Version);
    assert_eq!(commands[0].arguments, [OsString::from("--version")]);
    assert_eq!(commands[1].tool, ReleaseTool::Barretenberg);
    assert_eq!(commands[1].operation, ReleaseToolOperation::Version);
    assert_eq!(commands[1].arguments, [OsString::from("--version")]);
    drop(commands);
    fixture.cleanup()
}

#[test]
fn proof_cycle_returns_only_outputs_accepted_by_the_pinned_verifier(
) -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(
        MaterializingRunner::new(fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let paths = ReleaseProofCyclePaths::try_new(
        test_circuit_ref(),
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &fixture.proof_cycle_output,
    )?;

    let completed = process.prove_and_verify(paths)?;

    assert_eq!(completed.proof_suite(), ZkProofSuite::PRODUCTION);
    assert_eq!(completed.circuit_ref(), test_circuit_ref());
    assert_eq!(completed.material().proof().as_bytes(), [4_u8]);
    assert_eq!(completed.material().verification_key().as_bytes(), [3_u8]);
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
            ReleaseToolOperation::WriteVerificationKey,
            ReleaseToolOperation::Prove,
            ReleaseToolOperation::Verify,
        ]
    );
    drop(completed);
    fixture.cleanup()
}

#[test]
fn verified_outputs_load_into_exact_bounded_material() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(
        MaterializingRunner::new(fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let paths = ReleaseProofCyclePaths::try_new(
        test_circuit_ref(),
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &fixture.proof_cycle_output,
    )?;
    let completed = process.prove_and_verify(paths)?;

    let material = completed.load_material();

    assert_eq!(material.circuit_ref(), test_circuit_ref());
    assert_eq!(material.proof().as_bytes(), [4_u8]);
    assert_eq!(material.verification_key().as_bytes(), [3_u8]);
    assert!(!material.compiled_program().as_bytes().is_empty());
    assert!(!material.public_inputs().as_bytes().is_empty());
    drop(material);
    fixture.cleanup()
}

#[test]
fn verified_material_is_immune_to_post_verification_path_replacement(
) -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(
        MaterializingRunner::new(fixture.proof_cycle_output.clone()),
        fixture.paths()?,
    )?;
    let paths = ReleaseProofCyclePaths::try_new(
        test_circuit_ref(),
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &fixture.proof_cycle_output,
    )?;
    let completed = process.prove_and_verify(paths)?;
    fs::write(&fixture.public_inputs, [0_u8])?;
    let material = completed.load_material();
    assert!(!material.public_inputs().as_bytes().is_empty());
    drop(material);
    fixture.cleanup()
}

#[test]
fn proof_cycle_rejects_reused_output_directory() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let _existing = File::create(fixture.proof_cycle_output.join("existing"))?;

    let reason = ReleaseProofCyclePaths::try_new(
        test_circuit_ref(),
        &fixture.crs,
        &fixture.bytecode,
        &fixture.witness,
        &fixture.proof_cycle_output,
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(reason, Some(ReleaseProcessErrorReason::InvalidPath));
    fixture.cleanup()
}

mod artifact_normalization;
mod modern_candidate;
mod system_runner_tests;
mod witness_lifecycle;
