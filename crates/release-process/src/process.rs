// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pinned, typed external-tool boundary for deterministic release generation.
//!
//! Runtime proving and verification remain linked-library operations. This
//! publish-disabled crate exists only for reviewed release artifact and vector
//! generation, and it never performs ambient-provider fallback.

use std::{ffi::OsString, path::Path};

use crate::{
    ReleaseCommand, ReleaseProcessError, ReleaseProcessErrorReason, ReleaseProcessRunner,
    ReleaseTool, ReleaseToolOperation,
};
use reallyme_zk_api::proofs::ZkProofSuite;
use reallyme_zk_artifacts::{ArtifactToolchain, ArtifactVersion};

pub(crate) mod crs_identity;
mod profile;
mod suite;
mod tool_identity;
mod tool_paths;
mod validation;

pub use profile::{
    ReleaseToolchainProfile, MODERN_CANDIDATE_BARRETENBERG_VERSION, MODERN_CANDIDATE_NARGO_VERSION,
    MODERN_CANDIDATE_NOIRC_GIT_COMMIT, PINNED_BARRETENBERG_VERSION, PINNED_NARGO_VERSION,
    PINNED_NOIRC_GIT_COMMIT,
};
pub use tool_paths::{ReleaseToolDigests, ReleaseToolPaths};

use suite::{require_profile_suite, verifier_target_name};
use tool_identity::require_tool_digest;
use validation::{path_component, validate_new_output};
pub(crate) use validation::{validate_directory, validate_regular_file};

#[cfg(test)]
mod tests;

/// Version-attested release toolchain with injectable execution.
pub struct PinnedReleaseProcess<R> {
    runner: R,
    nargo: OsString,
    barretenberg: OsString,
    profile: ReleaseToolchainProfile,
    toolchain: ArtifactToolchain,
    tool_digests: ReleaseToolDigests,
}

impl<R: ReleaseProcessRunner> PinnedReleaseProcess<R> {
    /// Attests both configured tools before allowing release operations.
    pub fn try_new(runner: R, paths: ReleaseToolPaths<'_>) -> Result<Self, ReleaseProcessError> {
        Self::try_new_for_profile(runner, paths, ReleaseToolchainProfile::ModernCandidate)
    }

    /// Attests both configured tools for one explicit release-toolchain lane.
    pub fn try_new_for_profile(
        runner: R,
        paths: ReleaseToolPaths<'_>,
        profile: ReleaseToolchainProfile,
    ) -> Result<Self, ReleaseProcessError> {
        let nargo = paths.nargo.as_os_str().to_os_string();
        let barretenberg = paths.barretenberg.as_os_str().to_os_string();
        let process = Self {
            runner,
            nargo,
            barretenberg,
            profile,
            toolchain: profile.toolchain()?,
            tool_digests: paths.digests,
        };
        process.attest_tool_versions()?;
        Ok(process)
    }

    /// Exact versions subsequently sealed into artifact manifests.
    #[must_use]
    pub const fn toolchain(&self) -> ArtifactToolchain {
        self.toolchain
    }

    /// Release-toolchain lane selected for commands and artifact admission.
    #[must_use]
    pub const fn profile(&self) -> ReleaseToolchainProfile {
        self.profile
    }

    /// Builds a constraint-checked Nargo compile command.
    pub fn compile_command(
        &self,
        circuit_directory: &Path,
        package_name: ArtifactVersion,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        validate_directory(circuit_directory)?;
        let package = path_component(package_name)?;
        Ok(ReleaseCommand {
            tool: ReleaseTool::Nargo,
            operation: ReleaseToolOperation::Compile,
            executable: self.nargo.clone().into(),
            current_directory: Some(circuit_directory.to_path_buf()),
            arguments: vec![
                OsString::from("compile"),
                OsString::from("--package"),
                package,
                OsString::from("--deny-warnings"),
                OsString::from("--force"),
            ],
            capture_stdout: false,
        })
    }

    /// Builds a constraint-checked Nargo witness-generation command.
    pub fn execute_command(
        &self,
        circuit_directory: &Path,
        package_name: ArtifactVersion,
        prover_name: ArtifactVersion,
        witness_name: ArtifactVersion,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        validate_directory(circuit_directory)?;
        let package = path_component(package_name)?;
        let prover = path_component(prover_name)?;
        let witness = path_component(witness_name)?;
        Ok(ReleaseCommand {
            tool: ReleaseTool::Nargo,
            operation: ReleaseToolOperation::Execute,
            executable: self.nargo.clone().into(),
            current_directory: Some(circuit_directory.to_path_buf()),
            arguments: vec![
                OsString::from("execute"),
                witness,
                OsString::from("--prover-name"),
                prover,
                OsString::from("--package"),
                package,
                OsString::from("--deny-warnings"),
            ],
            capture_stdout: false,
        })
    }

    /// Builds an UltraHonk/Keccak verification-key command with no IPA.
    pub fn write_verification_key_command(
        &self,
        crs_directory: &Path,
        bytecode_path: &Path,
        output_path: &Path,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        self.write_verification_key_command_for_suite(
            crs_directory,
            bytecode_path,
            output_path,
            ZkProofSuite::PRODUCTION,
        )
    }

    /// Builds a verification-key command for an exact supported suite.
    pub fn write_verification_key_command_for_suite(
        &self,
        crs_directory: &Path,
        bytecode_path: &Path,
        output_path: &Path,
        proof_suite: ZkProofSuite,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        require_profile_suite(self.profile, proof_suite)?;
        validate_directory(crs_directory)?;
        validate_regular_file(bytecode_path)?;
        validate_new_output(output_path)?;
        Ok(self.barretenberg_command(
            ReleaseToolOperation::WriteVerificationKey,
            vec![
                OsString::from("write_vk"),
                OsString::from("-c"),
                crs_directory.as_os_str().to_os_string(),
                OsString::from("-b"),
                bytecode_path.as_os_str().to_os_string(),
                OsString::from("-o"),
                output_path.as_os_str().to_os_string(),
                OsString::from("-t"),
                OsString::from(verifier_target_name(proof_suite)),
                OsString::from("--output_format"),
                OsString::from("binary"),
            ],
        ))
    }

    /// Builds an UltraHonk/Keccak/ZK proof command with no IPA accumulation.
    pub fn prove_command(
        &self,
        crs_directory: &Path,
        bytecode_path: &Path,
        witness_path: &Path,
        output_path: &Path,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        self.prove_command_for_suite(
            crs_directory,
            bytecode_path,
            witness_path,
            output_path,
            ZkProofSuite::PRODUCTION,
        )
    }

    /// Builds an UltraHonk proof command for an exact supported suite.
    pub fn prove_command_for_suite(
        &self,
        crs_directory: &Path,
        bytecode_path: &Path,
        witness_path: &Path,
        output_path: &Path,
        proof_suite: ZkProofSuite,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        require_profile_suite(self.profile, proof_suite)?;
        validate_directory(crs_directory)?;
        validate_regular_file(bytecode_path)?;
        validate_regular_file(witness_path)?;
        validate_new_output(output_path)?;
        self.prove_command_with_optional_key(
            crs_directory,
            bytecode_path,
            witness_path,
            output_path,
            None,
            proof_suite,
        )
    }

    /// Builds an UltraHonk/Keccak/ZK verification command with no IPA.
    pub fn verify_command(
        &self,
        crs_directory: &Path,
        proof_path: &Path,
        public_inputs_path: &Path,
        verification_key_path: &Path,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        self.verify_command_for_suite(
            crs_directory,
            proof_path,
            public_inputs_path,
            verification_key_path,
            ZkProofSuite::PRODUCTION,
        )
    }

    /// Builds an UltraHonk verification command for an exact supported suite.
    pub fn verify_command_for_suite(
        &self,
        crs_directory: &Path,
        proof_path: &Path,
        public_inputs_path: &Path,
        verification_key_path: &Path,
        proof_suite: ZkProofSuite,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        require_profile_suite(self.profile, proof_suite)?;
        validate_directory(crs_directory)?;
        validate_regular_file(proof_path)?;
        validate_regular_file(public_inputs_path)?;
        validate_regular_file(verification_key_path)?;
        Ok(self.barretenberg_command(
            ReleaseToolOperation::Verify,
            vec![
                OsString::from("verify"),
                OsString::from("-c"),
                crs_directory.as_os_str().to_os_string(),
                OsString::from("-p"),
                proof_path.as_os_str().to_os_string(),
                OsString::from("-i"),
                public_inputs_path.as_os_str().to_os_string(),
                OsString::from("-k"),
                verification_key_path.as_os_str().to_os_string(),
                OsString::from("-t"),
                OsString::from(verifier_target_name(proof_suite)),
            ],
        ))
    }

    /// Executes a previously validated typed release command.
    pub fn run(&self, command: &ReleaseCommand) -> Result<(), ReleaseProcessError> {
        let _output = self.run_checked(command)?;
        Ok(())
    }

    fn attest_tool_versions(&self) -> Result<(), ReleaseProcessError> {
        let nargo = self.run_checked(&self.version_command(ReleaseTool::Nargo))?;
        require_line(
            &nargo.stdout,
            self.profile.nargo_version_line(),
            ReleaseTool::Nargo,
        )?;
        require_line(
            &nargo.stdout,
            self.profile.noirc_version_line(),
            ReleaseTool::Nargo,
        )?;
        let barretenberg = self.run_checked(&self.version_command(ReleaseTool::Barretenberg))?;
        require_line(
            &barretenberg.stdout,
            self.profile.barretenberg_version_line(),
            ReleaseTool::Barretenberg,
        )
    }

    fn run_checked(
        &self,
        command: &ReleaseCommand,
    ) -> Result<crate::ReleaseProcessOutput, ReleaseProcessError> {
        let path = Path::new(&command.executable);
        require_tool_digest(path, self.tool_digests.for_tool(command.tool), command.tool)?;
        self.runner.run(command)
    }

    fn version_command(&self, tool: ReleaseTool) -> ReleaseCommand {
        let (executable, arguments) = match tool {
            ReleaseTool::Nargo => (self.nargo.clone(), vec![OsString::from("--version")]),
            ReleaseTool::Barretenberg => {
                (self.barretenberg.clone(), vec![OsString::from("--version")])
            }
        };
        ReleaseCommand {
            tool,
            operation: ReleaseToolOperation::Version,
            executable: executable.into(),
            current_directory: None,
            arguments,
            capture_stdout: true,
        }
    }

    fn barretenberg_command(
        &self,
        operation: ReleaseToolOperation,
        arguments: Vec<OsString>,
    ) -> ReleaseCommand {
        ReleaseCommand {
            tool: ReleaseTool::Barretenberg,
            operation,
            executable: self.barretenberg.clone().into(),
            current_directory: None,
            arguments,
            capture_stdout: false,
        }
    }

    pub(crate) fn prove_command_with_verification_key_for_suite(
        &self,
        crs_directory: &Path,
        bytecode_path: &Path,
        witness_path: &Path,
        output_path: &Path,
        verification_key_path: &Path,
        proof_suite: ZkProofSuite,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        validate_regular_file(verification_key_path)?;
        self.prove_command_with_optional_key(
            crs_directory,
            bytecode_path,
            witness_path,
            output_path,
            Some(verification_key_path),
            proof_suite,
        )
    }

    fn prove_command_with_optional_key(
        &self,
        crs_directory: &Path,
        bytecode_path: &Path,
        witness_path: &Path,
        output_path: &Path,
        verification_key_path: Option<&Path>,
        proof_suite: ZkProofSuite,
    ) -> Result<ReleaseCommand, ReleaseProcessError> {
        require_profile_suite(self.profile, proof_suite)?;
        validate_directory(crs_directory)?;
        validate_regular_file(bytecode_path)?;
        validate_regular_file(witness_path)?;
        validate_new_output(output_path)?;
        let mut arguments = vec![
            OsString::from("prove"),
            OsString::from("-c"),
            crs_directory.as_os_str().to_os_string(),
            OsString::from("-b"),
            bytecode_path.as_os_str().to_os_string(),
            OsString::from("-w"),
            witness_path.as_os_str().to_os_string(),
            OsString::from("-o"),
            output_path.as_os_str().to_os_string(),
            OsString::from("-t"),
            OsString::from(verifier_target_name(proof_suite)),
            OsString::from("--output_format"),
            OsString::from("binary"),
        ];
        if let Some(path) = verification_key_path {
            arguments.push(OsString::from("-k"));
            arguments.push(path.as_os_str().to_os_string());
            arguments.push(OsString::from("--verify"));
        }
        Ok(self.barretenberg_command(ReleaseToolOperation::Prove, arguments))
    }
}

fn require_line(
    output: &[u8],
    expected: &[u8],
    tool: ReleaseTool,
) -> Result<(), ReleaseProcessError> {
    if !output
        .split(|byte| *byte == b'\n')
        .any(|line| line == expected)
    {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::VersionMismatch(tool),
        ));
    }
    Ok(())
}
