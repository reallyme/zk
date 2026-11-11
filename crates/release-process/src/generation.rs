// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Circuit compilation, witness generation, proof creation, and witness cleanup.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use reallyme_zk_api::{circuits::ZkCircuitRef, proofs::ZkProofSuite};
use reallyme_zk_artifacts::ArtifactVersion;

use crate::{
    validate_directory, validate_regular_file, CompletedReleaseProofCycle,
    CompletedReleaseProvingMaterial, ExistingReleaseProofPaths, PinnedReleaseProcess,
    ReleaseProcessError, ReleaseProcessErrorReason, ReleaseProcessRunner, ReleaseProofCyclePaths,
};

const PROVER_FILE_NAME: &str = "Prover";
const RELEASE_WITNESS_NAME: &str = "release_witness";
const TARGET_DIRECTORY_NAME: &str = "target";
const COMPILED_PROGRAM_EXTENSION: &str = ".json";
const WITNESS_EXTENSION: &str = ".gz";
const FILE_ZEROIZE_CHUNK_BYTES: usize = 16 * 1024;

/// Validated locations and package identity for one complete release proof.
///
/// This type omits `Debug` so host paths cannot enter logs accidentally.
pub struct ReleaseGenerationPaths<'a> {
    circuit_ref: ZkCircuitRef,
    circuit_directory: &'a Path,
    crs_directory: &'a Path,
    output_directory: &'a Path,
    package_name: ArtifactVersion,
}

impl<'a> ReleaseGenerationPaths<'a> {
    /// Creates a release-generation request from explicit typed inputs.
    pub fn try_new(
        circuit_ref: ZkCircuitRef,
        circuit_directory: &'a Path,
        crs_directory: &'a Path,
        output_directory: &'a Path,
        package_name: ArtifactVersion,
    ) -> Result<Self, ReleaseProcessError> {
        validate_directory(circuit_directory)?;
        validate_directory(crs_directory)?;
        // The proof-cycle constructor performs the authoritative empty-output
        // check immediately before any Barretenberg output is created.
        validate_directory(output_directory)?;
        Ok(Self {
            circuit_ref,
            circuit_directory,
            crs_directory,
            output_directory,
            package_name,
        })
    }
}

/// Retained verified outputs plus the circuit needed to regenerate only their
/// serialized witness stack.
///
/// This type enables resumable release assembly. It deliberately provides no
/// compile, verification-key, or prove operation; the exact retained proof is
/// reverified after Nargo regenerates its matching witness.
pub struct ReleaseWitnessMaterialPaths<'a> {
    circuit_directory: &'a Path,
    package_name: ArtifactVersion,
    proof_suite: ZkProofSuite,
    proof_paths: ExistingReleaseProofPaths<'a>,
}

impl<'a> ReleaseWitnessMaterialPaths<'a> {
    /// Requires the retained compiled program to be the exact package target
    /// used by witness generation.
    pub fn try_new(
        circuit_directory: &'a Path,
        package_name: ArtifactVersion,
        proof_paths: ExistingReleaseProofPaths<'a>,
    ) -> Result<Self, ReleaseProcessError> {
        Self::try_new_for_suite(
            circuit_directory,
            package_name,
            ZkProofSuite::PRODUCTION,
            proof_paths,
        )
    }

    /// Validates retained paths for one exact proof suite.
    pub fn try_new_for_suite(
        circuit_directory: &'a Path,
        package_name: ArtifactVersion,
        proof_suite: ZkProofSuite,
        proof_paths: ExistingReleaseProofPaths<'a>,
    ) -> Result<Self, ReleaseProcessError> {
        validate_directory(circuit_directory)?;
        let expected_program = circuit_directory
            .join(TARGET_DIRECTORY_NAME)
            .join(file_name(package_name, COMPILED_PROGRAM_EXTENSION)?);
        if proof_paths.compiled_program() != expected_program {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::InvalidPath,
            ));
        }
        Ok(Self {
            circuit_directory,
            package_name,
            proof_suite,
            proof_paths,
        })
    }
}

impl<R: ReleaseProcessRunner> PinnedReleaseProcess<R> {
    /// Compiles, solves, proves, verifies, and then destroys the witness file.
    ///
    /// Witness cleanup runs after both successful and failed proof generation.
    /// If proof generation and cleanup both fail, the cleanup error wins because
    /// residual witness material is the higher-priority security condition.
    pub fn generate_and_verify(
        &self,
        paths: ReleaseGenerationPaths<'_>,
    ) -> Result<CompletedReleaseProofCycle, ReleaseProcessError> {
        self.generate_and_verify_for_suite(paths, ZkProofSuite::PRODUCTION)
    }

    /// Compiles, solves, proves, and verifies under one exact supported suite.
    pub fn generate_and_verify_for_suite(
        &self,
        paths: ReleaseGenerationPaths<'_>,
        proof_suite: ZkProofSuite,
    ) -> Result<CompletedReleaseProofCycle, ReleaseProcessError> {
        self.generate_verify_and_finalize(paths, proof_suite, |completed, _witness_path| {
            Ok(completed)
        })
    }

    /// Generates, verifies, and admits real proof plus witness material before
    /// destroying the temporary witness file.
    ///
    /// The returned witness is the same serialized `WitnessStack` format
    /// produced by the pinned witness solver, bound to the supplied exact
    /// circuit ABI.
    pub fn generate_verify_and_load_material(
        &self,
        paths: ReleaseGenerationPaths<'_>,
    ) -> Result<CompletedReleaseProvingMaterial, ReleaseProcessError> {
        self.generate_verify_and_load_material_for_suite(paths, ZkProofSuite::PRODUCTION)
    }

    /// Generates and admits proof material under one exact supported suite.
    pub fn generate_verify_and_load_material_for_suite(
        &self,
        paths: ReleaseGenerationPaths<'_>,
        proof_suite: ZkProofSuite,
    ) -> Result<CompletedReleaseProvingMaterial, ReleaseProcessError> {
        self.generate_verify_and_finalize(paths, proof_suite, |completed, witness_path| {
            completed.load_proving_material(witness_path)
        })
    }

    /// Regenerates only a witness, reverifies retained proof outputs, admits
    /// both into bounded owners, and destroys the temporary witness file.
    pub fn regenerate_witness_and_load_material(
        &self,
        paths: ReleaseWitnessMaterialPaths<'_>,
    ) -> Result<CompletedReleaseProvingMaterial, ReleaseProcessError> {
        let prover_name = artifact_version(PROVER_FILE_NAME)?;
        let witness_name = artifact_version(RELEASE_WITNESS_NAME)?;
        let witness_path = paths
            .circuit_directory
            .join(TARGET_DIRECTORY_NAME)
            .join(file_name(witness_name, WITNESS_EXTENSION)?);
        let target_directory = paths.circuit_directory.join(TARGET_DIRECTORY_NAME);
        ensure_private_directory(&target_directory)?;
        prepare_witness_path(&witness_path)?;

        let execute = self.execute_command(
            paths.circuit_directory,
            paths.package_name,
            prover_name,
            witness_name,
        )?;
        if let Err(error) = self.run(&execute) {
            return cleanup_after_failure(&witness_path, error);
        }
        if let Err(error) = validate_regular_file(&witness_path) {
            return cleanup_after_failure(&witness_path, error);
        }

        let material_result = self
            .verify_existing_for_suite(paths.proof_paths, paths.proof_suite)
            .and_then(|completed| completed.load_proving_material(&witness_path));
        let cleanup_result = zeroize_and_remove_file(&witness_path);
        match (material_result, cleanup_result) {
            (Ok(material), Ok(())) => Ok(material),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) | (Err(_), Err(cleanup_error)) => Err(cleanup_error),
        }
    }

    fn generate_verify_and_finalize<T, F>(
        &self,
        paths: ReleaseGenerationPaths<'_>,
        proof_suite: ZkProofSuite,
        finalize: F,
    ) -> Result<T, ReleaseProcessError>
    where
        F: FnOnce(CompletedReleaseProofCycle, &Path) -> Result<T, ReleaseProcessError>,
    {
        let prover_name = artifact_version(PROVER_FILE_NAME)?;
        let witness_name = artifact_version(RELEASE_WITNESS_NAME)?;
        let target_directory = paths.circuit_directory.join(TARGET_DIRECTORY_NAME);
        let bytecode_path =
            target_directory.join(file_name(paths.package_name, COMPILED_PROGRAM_EXTENSION)?);
        let witness_path = target_directory.join(file_name(witness_name, WITNESS_EXTENSION)?);

        let compile = self.compile_command(paths.circuit_directory, paths.package_name)?;
        self.run(&compile)?;
        ensure_private_directory(&target_directory)?;
        prepare_witness_path(&witness_path)?;
        validate_regular_file(&bytecode_path)?;

        let execute = self.execute_command(
            paths.circuit_directory,
            paths.package_name,
            prover_name,
            witness_name,
        )?;
        if let Err(error) = self.run(&execute) {
            return cleanup_after_failure(&witness_path, error);
        }
        if let Err(error) = validate_regular_file(&witness_path) {
            return cleanup_after_failure(&witness_path, error);
        }

        let cycle = match ReleaseProofCyclePaths::try_new(
            paths.circuit_ref,
            paths.crs_directory,
            &bytecode_path,
            &witness_path,
            paths.output_directory,
        ) {
            Ok(cycle) => cycle,
            Err(error) => return cleanup_after_failure(&witness_path, error),
        };
        let proof_result = self
            .prove_and_verify_for_suite(cycle, proof_suite)
            .and_then(|completed| finalize(completed, &witness_path));
        let cleanup_result = zeroize_and_remove_file(&witness_path);
        match (proof_result, cleanup_result) {
            (Ok(completed), Ok(())) => Ok(completed),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) | (Err(_), Err(cleanup_error)) => Err(cleanup_error),
        }
    }
}

fn artifact_version(value: &str) -> Result<ArtifactVersion, ReleaseProcessError> {
    ArtifactVersion::try_from_token(value)
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidPath))
}

fn file_name(component: ArtifactVersion, extension: &str) -> Result<OsString, ReleaseProcessError> {
    let value = core::str::from_utf8(component.as_bytes())
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidPath))?;
    let mut file_name = OsString::from(value);
    file_name.push(extension);
    Ok(file_name)
}

fn cleanup_after_failure<T>(
    witness_path: &Path,
    primary_error: ReleaseProcessError,
) -> Result<T, ReleaseProcessError> {
    if !path_entry_exists_no_follow(witness_path)? {
        return Err(primary_error);
    }
    match zeroize_and_remove_file(witness_path) {
        Ok(()) => Err(primary_error),
        Err(cleanup_failure) => Err(cleanup_failure),
    }
}

fn prepare_witness_path(path: &Path) -> Result<(), ReleaseProcessError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidPath),
        ),
        Ok(_) => zeroize_and_remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ReleaseProcessError::from(error)),
    }
}

fn path_entry_exists_no_follow(path: &Path) -> Result<bool, ReleaseProcessError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(cleanup_error(error)),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), ReleaseProcessError> {
    validate_directory(path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let mode = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::InvalidPath,
            ));
        }
    }
    Ok(())
}

fn zeroize_and_remove_file(path: &Path) -> Result<(), ReleaseProcessError> {
    validate_regular_file(path).map_err(|error| cleanup_error_kind(error.reason()))?;
    let mut file = open_sensitive_file_no_follow(path).map_err(cleanup_error)?;
    let mut remaining = file.metadata().map_err(cleanup_error)?.len();
    let zeroes = [0_u8; FILE_ZEROIZE_CHUNK_BYTES];
    while remaining != 0 {
        let chunk_u64 = remaining.min(u64::try_from(FILE_ZEROIZE_CHUNK_BYTES).map_err(|_| {
            ReleaseProcessError::new(ReleaseProcessErrorReason::SensitiveFileCleanup(
                std::io::ErrorKind::InvalidData,
            ))
        })?);
        let chunk = usize::try_from(chunk_u64).map_err(|_| {
            ReleaseProcessError::new(ReleaseProcessErrorReason::SensitiveFileCleanup(
                std::io::ErrorKind::InvalidData,
            ))
        })?;
        file.write_all(&zeroes[..chunk]).map_err(cleanup_error)?;
        remaining = remaining
            .checked_sub(chunk_u64)
            .ok_or(ReleaseProcessError::new(
                ReleaseProcessErrorReason::SensitiveFileCleanup(std::io::ErrorKind::InvalidData),
            ))?;
    }
    file.flush().map_err(cleanup_error)?;
    file.set_len(0).map_err(cleanup_error)?;
    file.sync_all().map_err(cleanup_error)?;
    drop(file);
    fs::remove_file(path).map_err(cleanup_error)?;
    let parent = path.parent().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::SensitiveFileCleanup(std::io::ErrorKind::InvalidInput),
    ))?;
    validate_directory(parent).map_err(|error| cleanup_error_kind(error.reason()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(cleanup_error)
}

fn open_sensitive_file_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).truncate(false);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

fn cleanup_error(error: std::io::Error) -> ReleaseProcessError {
    ReleaseProcessError::new(ReleaseProcessErrorReason::SensitiveFileCleanup(
        error.kind(),
    ))
}

fn cleanup_error_kind(reason: ReleaseProcessErrorReason) -> ReleaseProcessError {
    let kind = match reason {
        ReleaseProcessErrorReason::Filesystem(kind)
        | ReleaseProcessErrorReason::SensitiveFileCleanup(kind) => kind,
        ReleaseProcessErrorReason::InvalidPath => std::io::ErrorKind::InvalidInput,
        ReleaseProcessErrorReason::InvalidArguments
        | ReleaseProcessErrorReason::ProcessIo { .. }
        | ReleaseProcessErrorReason::ProcessFailed { .. }
        | ReleaseProcessErrorReason::ProcessTimedOut { .. }
        | ReleaseProcessErrorReason::VersionOutputTooLarge(_)
        | ReleaseProcessErrorReason::VersionMismatch(_)
        | ReleaseProcessErrorReason::ToolDigestMismatch(_)
        | ReleaseProcessErrorReason::CrsIdentityMismatch
        | ReleaseProcessErrorReason::UnsupportedProofSuite
        | ReleaseProcessErrorReason::MalformedCompiledArtifact
        | ReleaseProcessErrorReason::CompiledArtifactToolchainMismatch
        | ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch
        | ReleaseProcessErrorReason::InvalidReleaseOutput(_) => std::io::ErrorKind::Other,
    };
    ReleaseProcessError::new(ReleaseProcessErrorReason::SensitiveFileCleanup(kind))
}
