// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded ownership boundary for cryptographically verified release outputs.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Take},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    proofs::{
        ZkProof, ZkProofBytes, ZkProofSuite, ZkPublicInputs, ZkWitness, MAX_PROOF_BYTES,
        MAX_WITNESS_BYTES,
    },
};
use reallyme_zk_artifacts::{
    ArtifactBytes, ArtifactKind, Digest32, ProductionArtifactManifest, MAX_VERIFICATION_KEY_BYTES,
};
use reallyme_zk_backend_bb::BarretenbergPublicInputCodec;
use zeroize::Zeroizing;

use crate::{
    artifact_compatibility::normalize_compiled_program_artifact_for_profile, validate_regular_file,
    CompletedReleaseProofCycle, ReleaseOutputKind, ReleaseProcessError, ReleaseProcessErrorReason,
    ReleaseToolchainProfile, MAX_COMPILED_PROGRAM_ARTIFACT_BYTES,
};

/// Owned, bounded material admitted from one already-verified proof cycle.
///
/// The type intentionally omits `Debug`: although proofs and public inputs are
/// release fixtures rather than secrets, dumping them through diagnostics
/// would bypass the repository's privacy-safe error and telemetry policy.
pub struct CompletedReleaseProofMaterial {
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    compiled_program: ArtifactBytes,
    verification_key: ArtifactBytes,
    proof: ZkProofBytes,
    public_inputs: ZkPublicInputs,
}

/// Verified release outputs plus the exact serialized witness stack that
/// produced them.
///
/// The witness file is admitted into the zeroizing API owner only after the
/// pinned proof verifies, and the caller removes the source file before this
/// value can be returned. This type intentionally omits `Debug` and `Clone`.
pub struct CompletedReleaseProvingMaterial {
    proof_material: CompletedReleaseProofMaterial,
    witness: ZkWitness,
}

impl CompletedReleaseProvingMaterial {
    /// Verified, bounded public release material.
    #[must_use]
    pub const fn proof_material(&self) -> &CompletedReleaseProofMaterial {
        &self.proof_material
    }

    /// Exact provider-compatible serialized witness stack.
    #[must_use]
    pub const fn witness(&self) -> &ZkWitness {
        &self.witness
    }

    /// Consumes this owner without copying either public or secret bytes.
    #[must_use]
    pub fn into_parts(self) -> (CompletedReleaseProofMaterial, ZkWitness) {
        (self.proof_material, self.witness)
    }
}

impl CompletedReleaseProofMaterial {
    /// Exact compiler/backend circuit coordinate for every retained payload.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Exact suite used for proof construction and verification.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Bounded pinned-Noirc program artifact.
    #[must_use]
    pub const fn compiled_program(&self) -> &ArtifactBytes {
        &self.compiled_program
    }

    /// Bounded verification key accepted by the proof cycle.
    #[must_use]
    pub const fn verification_key(&self) -> &ArtifactBytes {
        &self.verification_key
    }

    /// Bounded proof bytes accepted by the pinned verifier.
    #[must_use]
    pub const fn proof(&self) -> &ZkProofBytes {
        &self.proof
    }

    /// Canonical compact public inputs decoded from backend field elements.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkPublicInputs {
        &self.public_inputs
    }

    /// Consumes verified proof material into its exact manifest-pinned runtime
    /// proof without copying the proof or public-input allocations.
    pub fn into_manifest_bound_proof(
        self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ZkProof, ReleaseProcessError> {
        if manifest.circuit_ref() != self.circuit_ref
            || manifest.proof_suite() != self.proof_suite
            || manifest.digests().bytecode_sha256
                != Digest32::sha256(self.compiled_program.as_bytes())
            || manifest.digests().verification_key_sha256
                != Digest32::sha256(self.verification_key.as_bytes())
        {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::CompiledArtifactExecutionMismatch,
            ));
        }
        ZkProof::try_from_exact_bounded_parts(
            self.circuit_ref.circuit_id(),
            self.circuit_ref,
            self.proof_suite,
            manifest.manifest_sha256(),
            self.proof,
            self.public_inputs,
        )
        .map_err(|_| invalid_output(ReleaseOutputKind::Proof))
    }
}

pub(crate) fn load_verified_material(
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    profile: ReleaseToolchainProfile,
    compiled_program_path: &Path,
    verification_key_path: &Path,
    proof_path: &Path,
    public_inputs_path: &Path,
) -> Result<CompletedReleaseProofMaterial, ReleaseProcessError> {
    let compiled_program = read_bounded_file(
        compiled_program_path,
        MAX_COMPILED_PROGRAM_ARTIFACT_BYTES,
        ReleaseOutputKind::CompiledProgram,
    )?;
    let compiled_program =
        normalize_compiled_program_artifact_for_profile(&compiled_program, profile)?;
    let compiled_program =
        ArtifactBytes::try_from_bytes(ArtifactKind::AcirBytecode, compiled_program)
            .map_err(|_| invalid_output(ReleaseOutputKind::CompiledProgram))?;

    let verification_key = read_bounded_file(
        verification_key_path,
        MAX_VERIFICATION_KEY_BYTES,
        ReleaseOutputKind::VerificationKey,
    )?;
    let verification_key =
        ArtifactBytes::try_from_bytes(ArtifactKind::VerificationKey, verification_key)
            .map_err(|_| invalid_output(ReleaseOutputKind::VerificationKey))?;

    let proof = read_bounded_file(proof_path, MAX_PROOF_BYTES, ReleaseOutputKind::Proof)?;
    let proof = ZkProofBytes::try_from_bytes(proof)
        .map_err(|_| invalid_output(ReleaseOutputKind::Proof))?;

    let expected_public_inputs_len = BarretenbergPublicInputCodec::serialized_len(circuit_ref)
        .map_err(|_| invalid_output(ReleaseOutputKind::PublicInputs))?;
    let serialized_public_inputs = read_bounded_file(
        public_inputs_path,
        expected_public_inputs_len,
        ReleaseOutputKind::PublicInputs,
    )?;
    if serialized_public_inputs.len() != expected_public_inputs_len {
        return Err(invalid_output(ReleaseOutputKind::PublicInputs));
    }
    let public_inputs =
        BarretenbergPublicInputCodec::decode(circuit_ref, &serialized_public_inputs)
            .map_err(|_| invalid_output(ReleaseOutputKind::PublicInputs))?;
    let round_trip = BarretenbergPublicInputCodec::encode(circuit_ref, &public_inputs)
        .map_err(|_| invalid_output(ReleaseOutputKind::PublicInputs))?;
    if round_trip != serialized_public_inputs {
        return Err(invalid_output(ReleaseOutputKind::PublicInputs));
    }

    Ok(CompletedReleaseProofMaterial {
        circuit_ref,
        proof_suite,
        compiled_program,
        verification_key,
        proof,
        public_inputs,
    })
}

impl CompletedReleaseProofCycle {
    /// Transfers material admitted into immutable owners immediately after
    /// successful verification.
    ///
    /// The public-input file is decoded under the exact circuit reference and
    /// re-encoded byte-for-byte before the compact provider representation is
    /// retained. This prevents package/vector assembly from treating arbitrary
    /// backend bytes as a valid circuit ABI.
    pub fn load_material(self) -> CompletedReleaseProofMaterial {
        self.into_material()
    }

    /// Admits the verified proof outputs and their exact serialized witness.
    ///
    /// Nargo and the pinned witness solver both produce this payload with
    /// `WitnessStack::serialize()`. The exact circuit reference is attached at
    /// this boundary so a valid stack cannot later be reused across stage ABIs.
    pub(crate) fn load_proving_material(
        self,
        witness_path: &Path,
    ) -> Result<CompletedReleaseProvingMaterial, ReleaseProcessError> {
        let circuit_ref = self.circuit_ref();
        let proof_material = self.load_material();
        let witness_bytes =
            read_bounded_secret_file(witness_path, MAX_WITNESS_BYTES, ReleaseOutputKind::Witness)?;
        let witness =
            ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness_bytes)
                .map_err(|_| invalid_output(ReleaseOutputKind::Witness))?;
        Ok(CompletedReleaseProvingMaterial {
            proof_material,
            witness,
        })
    }
}

pub(crate) fn read_bounded_file(
    path: &Path,
    maximum: usize,
    kind: ReleaseOutputKind,
) -> Result<Vec<u8>, ReleaseProcessError> {
    validate_regular_file(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let declared_len = usize::try_from(metadata.len()).map_err(|_| invalid_output(kind))?;
    if declared_len == 0 || declared_len > maximum {
        return Err(invalid_output(kind));
    }

    let limit = u64::try_from(maximum)
        .map_err(|_| invalid_output(kind))?
        .checked_add(1)
        .ok_or_else(|| invalid_output(kind))?;
    let file = open_read_only_no_follow(path)?;
    let opened = file.metadata()?;
    if !same_file(&metadata, &opened) {
        return Err(invalid_output(kind));
    }
    let mut bounded: Take<File> = file.take(limit);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| invalid_output(kind))?;
    bounded.read_to_end(&mut bytes)?;
    if bytes.len() != declared_len || bytes.len() > maximum {
        return Err(invalid_output(kind));
    }
    Ok(bytes)
}

fn read_bounded_secret_file(
    path: &Path,
    maximum: usize,
    kind: ReleaseOutputKind,
) -> Result<Zeroizing<Vec<u8>>, ReleaseProcessError> {
    validate_regular_file(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let declared_len = usize::try_from(metadata.len()).map_err(|_| invalid_output(kind))?;
    if declared_len == 0 || declared_len > maximum {
        return Err(invalid_output(kind));
    }

    let limit = u64::try_from(maximum)
        .map_err(|_| invalid_output(kind))?
        .checked_add(1)
        .ok_or_else(|| invalid_output(kind))?;
    let file = open_read_only_no_follow(path)?;
    let opened = file.metadata()?;
    if !same_file(&metadata, &opened) {
        return Err(invalid_output(kind));
    }
    let mut bounded: Take<File> = file.take(limit);
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| invalid_output(kind))?;
    bounded.read_to_end(&mut bytes)?;
    if bytes.len() != declared_len || bytes.len() > maximum {
        return Err(invalid_output(kind));
    }
    Ok(bytes)
}

fn open_read_only_no_follow(path: &Path) -> Result<File, ReleaseProcessError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    Ok(options.open(path)?)
}

#[cfg(unix)]
fn same_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(_before: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    // No stable file identity is available at this boundary on non-Unix hosts.
    // Reject admission rather than accept a replaceable path as the same file.
    false
}

const fn invalid_output(kind: ReleaseOutputKind) -> ReleaseProcessError {
    ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidReleaseOutput(kind))
}
