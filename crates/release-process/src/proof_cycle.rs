// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fail-closed orchestration for one production proof and verification cycle.

use std::{fs, path::Path};

use reallyme_zk_api::{circuits::ZkCircuitRef, proofs::ZkProofSuite};
use reallyme_zk_artifacts::MAX_VERIFICATION_KEY_BYTES;

use crate::{
    proof_material::{load_verified_material, read_bounded_file},
    validate_directory, validate_regular_file, CompletedReleaseProofMaterial, PinnedReleaseProcess,
    ReleaseOutputKind, ReleaseProcessError, ReleaseProcessErrorReason, ReleaseProcessRunner,
};

const VERIFICATION_KEY_DIRECTORY_NAME: &str = "verification_key";
const VERIFICATION_KEY_FILE_NAME: &str = "vk";
const VERIFICATION_KEY_HASH_FILE_NAME: &str = "vk_hash";
const PROOF_DIRECTORY_NAME: &str = "proof";
const PROOF_FILE_NAME: &str = "proof";
const PUBLIC_INPUTS_FILE_NAME: &str = "public_inputs";
const REDERIVED_VERIFICATION_KEY_DIRECTORY_NAME: &str = ".rederived-verification-key";

/// Validated inputs for one production UltraHonk proof cycle.
///
/// This type intentionally omits `Debug`: local paths can disclose account or
/// build-host information and do not belong in release diagnostics.
pub struct ReleaseProofCyclePaths<'a> {
    circuit_ref: ZkCircuitRef,
    crs_directory: &'a Path,
    bytecode_path: &'a Path,
    witness_path: &'a Path,
    output_directory: &'a Path,
}

/// Existing proof outputs that must be reverified before release admission.
///
/// This path set supports resumable release assembly without rerunning the
/// expensive proving operation. It does not trust prior process history: the
/// pinned verifier must accept the exact proof, public inputs, and key again.
pub struct ExistingReleaseProofPaths<'a> {
    circuit_ref: ZkCircuitRef,
    crs_directory: &'a Path,
    compiled_program: &'a Path,
    verification_key: &'a Path,
    proof: &'a Path,
    public_inputs: &'a Path,
}

impl<'a> ExistingReleaseProofPaths<'a> {
    /// Validates explicit non-symlinked paths for one retained proof output.
    pub fn try_new(
        circuit_ref: ZkCircuitRef,
        crs_directory: &'a Path,
        compiled_program: &'a Path,
        verification_key: &'a Path,
        proof: &'a Path,
        public_inputs: &'a Path,
    ) -> Result<Self, ReleaseProcessError> {
        validate_directory(crs_directory)?;
        validate_regular_file(compiled_program)?;
        validate_regular_file(verification_key)?;
        validate_regular_file(proof)?;
        validate_regular_file(public_inputs)?;
        Ok(Self {
            circuit_ref,
            crs_directory,
            compiled_program,
            verification_key,
            proof,
            public_inputs,
        })
    }

    pub(crate) const fn compiled_program(&self) -> &Path {
        self.compiled_program
    }
}

impl<'a> ReleaseProofCyclePaths<'a> {
    /// Requires explicit existing inputs and a new, empty output directory.
    pub fn try_new(
        circuit_ref: ZkCircuitRef,
        crs_directory: &'a Path,
        bytecode_path: &'a Path,
        witness_path: &'a Path,
        output_directory: &'a Path,
    ) -> Result<Self, ReleaseProcessError> {
        validate_directory(crs_directory)?;
        validate_regular_file(bytecode_path)?;
        validate_regular_file(witness_path)?;
        validate_empty_directory(output_directory)?;
        Ok(Self {
            circuit_ref,
            crs_directory,
            bytecode_path,
            witness_path,
            output_directory,
        })
    }
}

/// Files produced and cryptographically verified by one proof cycle.
///
/// The paths remain opaque to diagnostics for the same reason as the input
/// paths. Consumers can pass these files directly into bounded package owners.
pub struct CompletedReleaseProofCycle {
    material: CompletedReleaseProofMaterial,
}

impl CompletedReleaseProofCycle {
    /// Exact suite used for proof construction and verification.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.material.proof_suite()
    }

    /// Exact circuit ABI used by the verified proof cycle.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.material.circuit_ref()
    }

    /// Borrows immutable material admitted immediately after verification.
    #[must_use]
    pub const fn material(&self) -> &CompletedReleaseProofMaterial {
        &self.material
    }

    /// Consumes the cycle and transfers its immutable verified material.
    #[must_use]
    pub fn into_material(self) -> CompletedReleaseProofMaterial {
        self.material
    }
}

impl<R: ReleaseProcessRunner> PinnedReleaseProcess<R> {
    /// Generates a verification key and proof, then verifies that exact output.
    ///
    /// Verification is part of the operation contract: a generated proof is
    /// never returned as release material until the pinned backend accepts it.
    pub fn prove_and_verify(
        &self,
        paths: ReleaseProofCyclePaths<'_>,
    ) -> Result<CompletedReleaseProofCycle, ReleaseProcessError> {
        self.prove_and_verify_for_suite(paths, ZkProofSuite::PRODUCTION)
    }

    /// Generates and verifies a proof under one exact supported suite.
    pub fn prove_and_verify_for_suite(
        &self,
        paths: ReleaseProofCyclePaths<'_>,
        proof_suite: ZkProofSuite,
    ) -> Result<CompletedReleaseProofCycle, ReleaseProcessError> {
        let verification_key_output = paths.output_directory.join(VERIFICATION_KEY_DIRECTORY_NAME);
        let proof_output = paths.output_directory.join(PROOF_DIRECTORY_NAME);

        let write_key = self.write_verification_key_command_for_suite(
            paths.crs_directory,
            paths.bytecode_path,
            &verification_key_output,
            proof_suite,
        )?;
        self.run(&write_key)?;

        let verification_key = verification_key_output.join(VERIFICATION_KEY_FILE_NAME);
        let prove = self.prove_command_with_verification_key_for_suite(
            paths.crs_directory,
            paths.bytecode_path,
            paths.witness_path,
            &proof_output,
            &verification_key,
            proof_suite,
        )?;
        self.run(&prove)?;

        let proof = proof_output.join(PROOF_FILE_NAME);
        let public_inputs = proof_output.join(PUBLIC_INPUTS_FILE_NAME);
        let verify = self.verify_command_for_suite(
            paths.crs_directory,
            &proof,
            &public_inputs,
            &verification_key,
            proof_suite,
        )?;
        self.run(&verify)?;

        let material = load_verified_material(
            paths.circuit_ref,
            proof_suite,
            self.profile(),
            paths.bytecode_path,
            &verification_key,
            &proof,
            &public_inputs,
        )?;
        Ok(CompletedReleaseProofCycle { material })
    }

    /// Reverifies retained proof outputs without regenerating the proof or key.
    ///
    /// Successful return is the same admission capability produced by a fresh
    /// proof cycle. No release material can distinguish or bypass verification.
    pub fn verify_existing(
        &self,
        paths: ExistingReleaseProofPaths<'_>,
    ) -> Result<CompletedReleaseProofCycle, ReleaseProcessError> {
        self.verify_existing_for_suite(paths, ZkProofSuite::PRODUCTION)
    }

    /// Reverifies retained outputs under one exact supported suite.
    pub fn verify_existing_for_suite(
        &self,
        paths: ExistingReleaseProofPaths<'_>,
        proof_suite: ZkProofSuite,
    ) -> Result<CompletedReleaseProofCycle, ReleaseProcessError> {
        self.require_verification_key_matches_program(&paths, proof_suite)?;
        let verify = self.verify_command_for_suite(
            paths.crs_directory,
            paths.proof,
            paths.public_inputs,
            paths.verification_key,
            proof_suite,
        )?;
        self.run(&verify)?;
        let material = load_verified_material(
            paths.circuit_ref,
            proof_suite,
            self.profile(),
            paths.compiled_program,
            paths.verification_key,
            paths.proof,
            paths.public_inputs,
        )?;
        Ok(CompletedReleaseProofCycle { material })
    }

    fn require_verification_key_matches_program(
        &self,
        paths: &ExistingReleaseProofPaths<'_>,
        proof_suite: ZkProofSuite,
    ) -> Result<(), ReleaseProcessError> {
        let output_parent = paths
            .verification_key
            .parent()
            .ok_or(ReleaseProcessError::new(
                ReleaseProcessErrorReason::InvalidPath,
            ))?;
        validate_directory(output_parent)?;
        let output = output_parent.join(REDERIVED_VERIFICATION_KEY_DIRECTORY_NAME);
        if output.try_exists()? {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::InvalidPath,
            ));
        }

        let write_key = self.write_verification_key_command_for_suite(
            paths.crs_directory,
            paths.compiled_program,
            &output,
            proof_suite,
        )?;
        if let Err(error) = self.run(&write_key) {
            return cleanup_rederived_key_after_failure(&output, error);
        }

        let derived_key_path = output.join(VERIFICATION_KEY_FILE_NAME);
        let comparison = (|| {
            let retained = read_bounded_file(
                paths.verification_key,
                MAX_VERIFICATION_KEY_BYTES,
                ReleaseOutputKind::VerificationKey,
            )?;
            let derived = read_bounded_file(
                &derived_key_path,
                MAX_VERIFICATION_KEY_BYTES,
                ReleaseOutputKind::VerificationKey,
            )?;
            if retained != derived {
                return Err(ReleaseProcessError::new(
                    ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch,
                ));
            }
            Ok(())
        })();
        let cleanup = remove_rederived_key(&output, &derived_key_path);
        match (comparison, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) | (Err(_), Err(error)) => Err(error),
        }
    }
}

fn cleanup_rederived_key_after_failure<T>(
    directory: &Path,
    primary: ReleaseProcessError,
) -> Result<T, ReleaseProcessError> {
    if !directory.try_exists()? {
        return Err(primary);
    }
    let key = directory.join(VERIFICATION_KEY_FILE_NAME);
    match remove_rederived_key(directory, &key) {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(cleanup),
    }
}

fn remove_rederived_key(directory: &Path, key: &Path) -> Result<(), ReleaseProcessError> {
    let key_hash = directory.join(VERIFICATION_KEY_HASH_FILE_NAME);
    for path in [key, key_hash.as_path()] {
        if path.try_exists()? {
            validate_regular_file(path)?;
            fs::remove_file(path)?;
        }
    }
    validate_directory(directory)?;
    fs::remove_dir(directory)?;
    Ok(())
}

fn validate_empty_directory(path: &Path) -> Result<(), ReleaseProcessError> {
    validate_directory(path)?;
    let mut entries = fs::read_dir(path)?;
    if entries.next().transpose()?.is_some() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    Ok(())
}
