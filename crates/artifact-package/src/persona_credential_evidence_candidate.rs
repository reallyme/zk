// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admit the twelve persona-credential-evidence source programs to a local release candidate.

use std::path::Path;

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::{
    common_credential_root_source_closure_from_lock, exact_source_artifact_identity, ArtifactKind,
    ArtifactVersion, Digest32, PersonaCredentialEvidenceArtifactLayout,
};
use reallyme_zk_proto_codec::release::{
    encode_release_index, ReleaseIndex, ReleasePersonaCredentialEvidenceArtifactPin,
    MAX_ZK_RELEASE_INDEX_BYTES, RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT,
};

use crate::{
    candidate_util::{package_mismatch, replace_index},
    common_credential_root_candidate::{
        common_credential_root_pins, load_current_index_for_common_credential_root_reseal,
        validate_mobile_runtime_tree_against_index,
    },
    package::read_bounded_file,
    promotion::canonical_directory,
    ArtifactPackageError,
};

const MAX_EXACT_SOURCE_LOCK_BYTES: usize = 64 * 1024;
const PERSONA_CREDENTIAL_EVIDENCE_STAGES: [ZkCircuitStage; 6] = [
    ZkCircuitStage::EvidenceIssuerEnvelope,
    ZkCircuitStage::EvidenceClaimRoot,
    ZkCircuitStage::EvidenceSignedValidity,
    ZkCircuitStage::EvidencePublicClaim,
    ZkCircuitStage::EvidencePrivateClaim,
    ZkCircuitStage::EvidenceCurrentState,
];

/// Seal all twelve reviewed persona-credential-evidence programs into a local candidate.
///
/// The expected current-index and source-lock digests must come from a
/// separately reviewed build manifest. The candidate is checked as a closed
/// runtime tree before the new index is atomically installed.
pub fn seal_persona_credential_evidence_candidate(
    candidate_root: &Path,
    release_version: ArtifactVersion,
    expected_current_index_sha256: Digest32,
    expected_source_lock_sha256: Digest32,
) -> Result<Digest32, ArtifactPackageError> {
    canonical_directory(candidate_root)?;
    let (current, current_digest) =
        load_current_index_for_common_credential_root_reseal(candidate_root, release_version)?;
    if current_digest != expected_current_index_sha256
        || current.common_credential_root_artifacts().is_empty()
    {
        return package_mismatch();
    }
    let pins = persona_credential_evidence_pins(candidate_root, expected_source_lock_sha256)?;
    // Both exact-source families share one authenticated source lock. Rebuild
    // the common-credential-root pins in the same transaction to avoid a mixed-lock index.
    let common_credential_root_pins =
        common_credential_root_pins(candidate_root, expected_source_lock_sha256)?;
    let index = ReleaseIndex::try_new_with_exact_sources(
        current.release_version(),
        current.toolchain(),
        current.proof_suite(),
        current.capability_registry_sha256(),
        current.artifact_manifests().to_vec(),
        current.verification_vectors().to_vec(),
        common_credential_root_pins,
        pins,
    )?;
    validate_mobile_runtime_tree_against_index(candidate_root, release_version, &index)?;
    let bytes = encode_release_index(&index)?;
    if bytes.len() > MAX_ZK_RELEASE_INDEX_BYTES {
        return package_mismatch();
    }
    let digest = Digest32::sha256(&bytes);
    replace_index(candidate_root, release_version, &bytes)?;
    let (admitted, admitted_digest) =
        load_current_index_for_common_credential_root_reseal(candidate_root, release_version)?;
    if admitted != index || admitted_digest != digest {
        return package_mismatch();
    }
    validate_mobile_runtime_tree_against_index(candidate_root, release_version, &admitted)?;
    Ok(digest)
}

pub(crate) fn persona_credential_evidence_pins(
    root: &Path,
    expected_source_lock_sha256: Digest32,
) -> Result<Vec<ReleasePersonaCredentialEvidenceArtifactPin>, ArtifactPackageError> {
    let first = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::PersonaCredentialEvidenceV1,
        ZkCircuitStage::EvidencePublicClaim,
    );
    let layout = PersonaCredentialEvidenceArtifactLayout::try_new(root, first)?;
    let source_lock = read_bounded_file(&layout.source_lock(), MAX_EXACT_SOURCE_LOCK_BYTES)?;
    if !expected_source_lock_sha256.matches_sha256(&source_lock) {
        return package_mismatch();
    }
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for stage in PERSONA_CREDENTIAL_EVIDENCE_STAGES {
            let circuit_ref = ZkCircuitRef::new(
                *credential_hash_algorithm,
                ZkCircuitFamily::PersonaCredentialEvidenceV1,
                stage,
            );
            let layout = PersonaCredentialEvidenceArtifactLayout::try_new(root, circuit_ref)?;
            let source_closure =
                common_credential_root_source_closure_from_lock(&source_lock, circuit_ref)?;
            let program =
                read_bounded_file(&layout.program(), ArtifactKind::AcirBytecode.max_bytes())?;
            let key = read_bounded_file(
                &layout.verification_key(),
                ArtifactKind::VerificationKey.max_bytes(),
            )?;
            let bytecode_sha256 = Digest32::sha256(&program);
            let key_sha256 = Digest32::sha256(&key);
            pins.push(ReleasePersonaCredentialEvidenceArtifactPin::try_new(
                circuit_ref,
                expected_source_lock_sha256,
                source_closure,
                bytecode_sha256,
                key_sha256,
                exact_source_artifact_identity(
                    circuit_ref,
                    source_closure,
                    bytecode_sha256,
                    key_sha256,
                )?,
            )?);
        }
    }
    Ok(pins)
}

pub(crate) fn validate_mobile_runtime_persona_credential_evidence_artifact(
    root: &Path,
    pin: ReleasePersonaCredentialEvidenceArtifactPin,
) -> Result<(), ArtifactPackageError> {
    let layout = PersonaCredentialEvidenceArtifactLayout::try_new(root, pin.circuit_ref())?;
    let source_lock = read_bounded_file(&layout.source_lock(), MAX_EXACT_SOURCE_LOCK_BYTES)?;
    let program = read_bounded_file(&layout.program(), ArtifactKind::AcirBytecode.max_bytes())?;
    let key = read_bounded_file(
        &layout.verification_key(),
        ArtifactKind::VerificationKey.max_bytes(),
    )?;
    if !pin.source_lock_sha256().matches_sha256(&source_lock)
        || common_credential_root_source_closure_from_lock(&source_lock, pin.circuit_ref())?
            != pin.source_closure_sha256()
        || !pin.bytecode_sha256().matches_sha256(&program)
        || !pin.verification_key_sha256().matches_sha256(&key)
    {
        return package_mismatch();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
