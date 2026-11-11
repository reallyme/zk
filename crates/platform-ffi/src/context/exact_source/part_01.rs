// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Exact-source diagnostic artifact loading for imported `claim_bundle_4`.

#[cfg(feature = "diagnostic-exact-source")]
use std::path::PathBuf;
use std::{fs, io::Read, path::Path};

#[cfg(feature = "diagnostic-exact-source")]
use reallyme_zk_api::{artifacts::{ZkArtifactSetIdentity}, circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm}};
use reallyme_zk_api::{errors::{ZkError, ZkErrorReason}, proofs::{ZkProofSuite}};
#[cfg(feature = "diagnostic-exact-source")]
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_artifacts::{
    common_credential_root_source_closure_from_lock, ArtifactKind,
    CommonCredentialRootArtifactLayout, PersonaCredentialEvidenceArtifactLayout,
    VerifiedArtifactBytes,
};
use reallyme_zk_backend_bb::BbExactCircuitArtifacts;
use reallyme_zk_proto_codec::release::{
    ReleaseCommonCredentialRootArtifactPin, ReleasePersonaCredentialEvidenceArtifactPin,
};

use super::{map_filesystem_error, secure_open};

const MAX_EXACT_SOURCE_LOCK_BYTES: usize = 64 * 1024;
#[cfg(feature = "diagnostic-exact-source")]
const MAX_EXACT_SOURCE_FILE_BYTES: usize = 1024 * 1024;
#[cfg(feature = "diagnostic-exact-source")]
const MAX_EXACT_SOURCE_TOTAL_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "diagnostic-exact-source")]
const MAX_EXACT_SOURCE_FILES: usize = 4096;
#[cfg(feature = "diagnostic-exact-source")]
const MAX_EXACT_SOURCE_ENTRIES: usize = 8192;
#[cfg(feature = "diagnostic-exact-source")]
const MAX_EXACT_SOURCE_DIRECTORIES: usize = 1024;
#[cfg(feature = "diagnostic-exact-source")]
const MAX_EXACT_SOURCE_DEPTH: usize = 32;
#[cfg(feature = "diagnostic-exact-source")]
const EXACT_SOURCE_ARTIFACT_IDENTITY_DOMAIN: &[u8] = b"reallyme-zk-linked-all30-v1\n";
#[cfg(feature = "diagnostic-exact-source")]
pub(crate) const TRUSTED_EXACT_SOURCE_LOCK_SHA256: [u8; 32] = [
    0x30, 0x2c, 0x9a, 0x76, 0xc1, 0xce, 0xf9, 0x04, 0x5f, 0xf3, 0x62, 0x4e, 0xd8, 0x4b, 0xd7, 0xd9,
    0x01, 0x66, 0xd6, 0x9c, 0xa0, 0xd9, 0x2a, 0x85, 0x92, 0x4e, 0xdd, 0x7e, 0xa4, 0x2d, 0x46, 0xe5,
];

#[cfg(feature = "diagnostic-exact-source")]
pub(crate) fn claim_bundle4_exact_artifacts(
    artifact_root: &Path,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
) -> Result<BbExactCircuitArtifacts, ZkError> {
    if proof_suite != ZkProofSuite::PRODUCTION {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    if circuit_ref.stage != ZkCircuitStage::ClaimBundle4 {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    ensure_directory_not_symlink(artifact_root)?;

    let source_lock = artifact_root.join("modern-circuit-source-lock.tsv");
    let source_closure_sha256 = source_closure_digest_from_lock(&source_lock, circuit_ref)?;
    let recomputed_source_closure_sha256 =
        recompute_source_closure_digest(artifact_root, circuit_ref)?;
    if recomputed_source_closure_sha256 != source_closure_sha256 {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    let circuit_dir = exact_source_circuit_dir(artifact_root, circuit_ref);
    let target_dir = circuit_dir.join("target");
    let bytecode_path = single_program_json_path(&target_dir)?;
    let verification_key_path = target_dir.join("modern-run-01").join("vk");
    let bytecode_bytes = read_bounded_regular_file(&bytecode_path, ArtifactKind::AcirBytecode)?;
    let verification_key_bytes =
        read_bounded_regular_file(&verification_key_path, ArtifactKind::VerificationKey)?;
    let bytecode_sha256 = Digest32::sha256(bytecode_bytes.as_slice());
    let verification_key_sha256 = Digest32::sha256(verification_key_bytes.as_slice());
    let artifact_identity = exact_source_artifact_identity(
        circuit_ref,
        source_closure_sha256,
        bytecode_sha256,
        verification_key_sha256,
    )?;
    if artifact_identity != trusted_claim_bundle4_artifact_identity(circuit_ref)? {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        bytecode_bytes,
        bytecode_sha256,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key_bytes,
        verification_key_sha256,
    )?;
    BbExactCircuitArtifacts::try_new(circuit_ref, artifact_identity, bytecode, verification_key)
}

/// Loads only the exact program and VK admitted by the signed release index.
pub(crate) fn common_credential_root_release_artifacts(
    artifact_root: &Path,
    pin: ReleaseCommonCredentialRootArtifactPin,
    proof_suite: ZkProofSuite,
) -> Result<BbExactCircuitArtifacts, ZkError> {
    proof_suite.require_production()?;
    ensure_directory_not_symlink(artifact_root)?;
    let layout = CommonCredentialRootArtifactLayout::try_new(artifact_root, pin.circuit_ref())?;
    let source_lock =
        read_bounded_regular_file_with_limit(&layout.source_lock(), MAX_EXACT_SOURCE_LOCK_BYTES)?;
    if !pin.source_lock_sha256().matches_sha256(&source_lock)
        || common_credential_root_source_closure_from_lock(&source_lock, pin.circuit_ref())?
            != pin.source_closure_sha256()
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let program = read_bounded_regular_file(&layout.program(), ArtifactKind::AcirBytecode)?;
    let verification_key =
        read_bounded_regular_file(&layout.verification_key(), ArtifactKind::VerificationKey)?;
    if !pin.bytecode_sha256().matches_sha256(&program)
        || !pin
            .verification_key_sha256()
            .matches_sha256(&verification_key)
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        program,
        pin.bytecode_sha256(),
    )?;
    let key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key,
        pin.verification_key_sha256(),
    )?;
    BbExactCircuitArtifacts::try_new(
        pin.circuit_ref(),
        pin.artifact_identity_sha256(),
        bytecode,
        key,
    )
}

/// Loads one prepared program and VK only from the pinned release index.
pub(crate) fn persona_credential_evidence_release_artifacts(
    artifact_root: &Path,
    pin: ReleasePersonaCredentialEvidenceArtifactPin,
    proof_suite: ZkProofSuite,
) -> Result<BbExactCircuitArtifacts, ZkError> {
    proof_suite.require_production()?;
    ensure_directory_not_symlink(artifact_root)?;
    let layout =
        PersonaCredentialEvidenceArtifactLayout::try_new(artifact_root, pin.circuit_ref())?;
    let source_lock =
        read_bounded_regular_file_with_limit(&layout.source_lock(), MAX_EXACT_SOURCE_LOCK_BYTES)?;
    if !pin.source_lock_sha256().matches_sha256(&source_lock)
        || common_credential_root_source_closure_from_lock(&source_lock, pin.circuit_ref())?
            != pin.source_closure_sha256()
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let program = read_bounded_regular_file(&layout.program(), ArtifactKind::AcirBytecode)?;
    let verification_key =
        read_bounded_regular_file(&layout.verification_key(), ArtifactKind::VerificationKey)?;
    if !pin.bytecode_sha256().matches_sha256(&program)
        || !pin
            .verification_key_sha256()
            .matches_sha256(&verification_key)
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        program,
        pin.bytecode_sha256(),
    )?;
    let key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key,
        pin.verification_key_sha256(),
    )?;
    BbExactCircuitArtifacts::try_new(
        pin.circuit_ref(),
        pin.artifact_identity_sha256(),
        bytecode,
        key,
    )
}

fn read_bounded_regular_file(path: &Path, kind: ArtifactKind) -> Result<Vec<u8>, ZkError> {
    read_bounded_regular_file_with_limit(path, kind.max_bytes())
}

fn read_bounded_regular_file_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ZkError> {
    if max_bytes == 0 {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let file = secure_open::open_absolute_regular_file(path).map_err(map_filesystem_error)?;
    let metadata = file
        .metadata()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if !metadata.is_file() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let declared_len = usize::try_from(metadata.len())
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if declared_len == 0 || declared_len > max_bytes {
        return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
    }
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut reader = std::io::Read::take(file, read_limit);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if after.len() != metadata.len() || bytes.len() != declared_len {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(bytes)
}

#[cfg(feature = "diagnostic-exact-source")]
pub(crate) fn source_closure_digest_from_lock(
    lock_path: &Path,
    circuit_ref: ZkCircuitRef,
) -> Result<Digest32, ZkError> {
    let bytes = read_bounded_regular_file_with_limit(lock_path, MAX_EXACT_SOURCE_LOCK_BYTES)?;
    if Digest32::sha256(bytes.as_slice()).as_bytes() != &TRUSTED_EXACT_SOURCE_LOCK_SHA256 {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let lock = core::str::from_utf8(bytes.as_slice())
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let expected_circuit = exact_source_circuit_name(circuit_ref);
    for line in lock.lines().skip(1) {
        let mut fields = line.split('\t');
        if fields.next() == Some(expected_circuit.as_str()) {
            let _package = fields
                .next()
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            let digest = fields
                .next()
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            if fields.next().is_some() {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            return parse_digest32(digest);
        }
    }
    Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
}
