// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admit compiled common-credential-root programs into a complete local release candidate.

use std::path::Path;

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    common_root::ZkCommonCredentialRootSourceStage,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::{
    common_credential_root_source_closure_from_lock, exact_source_artifact_identity, ArtifactKind,
    ArtifactPackageLayout, ArtifactVersion, CommonCredentialRootArtifactLayout, Digest32,
};
use reallyme_zk_proto_codec::artifact::{decode_artifact_manifest, MAX_ZK_ARTIFACT_MANIFEST_BYTES};
use reallyme_zk_proto_codec::release::{
    decode_release_index, encode_release_index, ReleaseCommonCredentialRootArtifactPin,
    ReleaseIndex, MAX_ZK_RELEASE_INDEX_BYTES, RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT,
};

use crate::{
    candidate_util::{package_mismatch, replace_index},
    package::read_bounded_file,
    persona_credential_evidence_candidate::{
        persona_credential_evidence_pins,
        validate_mobile_runtime_persona_credential_evidence_artifact,
    },
    promotion::canonical_directory,
    ArtifactPackageError, ReleasePackageLayout,
};

const MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES: usize = 64 * 1024;
mod runtime_tree;
use runtime_tree::{validate_mobile_runtime_exact_tree, validate_mobile_runtime_root_entries};

const MAX_MOBILE_RUNTIME_TREE_ENTRIES: usize = 512;

/// Seals fourteen staged exact programs into an existing local candidate.
///
/// The source-lock and current-index digests must come from a reviewed build
/// manifest. Re-running the seal replaces the complete common-credential-root pin block
/// from the candidate tree, which lets a reviewed source-lock refresh happen
/// without mutating the already sealed stage manifests or verification-vector
/// pins. The final index is atomically replaced after every input file and the
/// exact candidate tree have been validated.
pub fn seal_common_credential_root_candidate(
    candidate_root: &Path,
    release_version: ArtifactVersion,
    expected_current_index_sha256: Digest32,
    expected_source_lock_sha256: Digest32,
) -> Result<Digest32, ArtifactPackageError> {
    canonical_directory(candidate_root)?;
    let (current_index, current_index_sha256) =
        load_current_index_for_common_credential_root_reseal(candidate_root, release_version)?;
    if current_index_sha256 != expected_current_index_sha256 {
        return package_mismatch();
    }
    let pins = common_credential_root_pins(candidate_root, expected_source_lock_sha256)?;
    // Refresh both families atomically so the index cannot mix source-lock states.
    let persona_credential_evidence_pins = if current_index
        .persona_credential_evidence_artifacts()
        .is_empty()
    {
        Vec::new()
    } else {
        persona_credential_evidence_pins(candidate_root, expected_source_lock_sha256)?
    };
    let index = ReleaseIndex::try_new_with_exact_sources(
        current_index.release_version(),
        current_index.toolchain(),
        current_index.proof_suite(),
        current_index.capability_registry_sha256(),
        current_index.artifact_manifests().to_vec(),
        current_index.verification_vectors().to_vec(),
        pins,
        persona_credential_evidence_pins,
    )?;
    validate_mobile_runtime_tree_against_index(candidate_root, release_version, &index)?;
    let bytes = encode_release_index(&index)?;
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

pub(crate) fn load_current_index_for_common_credential_root_reseal(
    candidate_root: &Path,
    release_version: ArtifactVersion,
) -> Result<(ReleaseIndex, Digest32), ArtifactPackageError> {
    let layout = ReleasePackageLayout::try_new(candidate_root, release_version)?;
    let index_bytes = read_bounded_file(&layout.index(), MAX_ZK_RELEASE_INDEX_BYTES)?;
    let index_sha256 = Digest32::sha256(&index_bytes);
    let index = decode_release_index(&index_bytes)?;
    if index.release_version() != release_version {
        return package_mismatch();
    }
    Ok((index, index_sha256))
}

pub(crate) fn common_credential_root_pins(
    root: &Path,
    expected_source_lock_sha256: Digest32,
) -> Result<Vec<ReleaseCommonCredentialRootArtifactPin>, ArtifactPackageError> {
    let first_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::RootAttestation,
    );
    let first_layout = CommonCredentialRootArtifactLayout::try_new(root, first_ref)?;
    let source_lock = read_bounded_file(
        &first_layout.source_lock(),
        MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
    )?;
    if !expected_source_lock_sha256.matches_sha256(&source_lock) {
        return package_mismatch();
    }
    let mut pins = Vec::new();
    pins.try_reserve_exact(RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for source_stage in ZkCommonCredentialRootSourceStage::ALL {
            let stage = source_stage.circuit_stage();
            let circuit_ref = ZkCircuitRef::new(
                *credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                stage,
            );
            let layout = CommonCredentialRootArtifactLayout::try_new(root, circuit_ref)?;
            let source_closure =
                common_credential_root_source_closure_from_lock(&source_lock, circuit_ref)?;
            let program =
                read_bounded_file(&layout.program(), ArtifactKind::AcirBytecode.max_bytes())?;
            let verification_key = read_bounded_file(
                &layout.verification_key(),
                ArtifactKind::VerificationKey.max_bytes(),
            )?;
            let bytecode_sha256 = Digest32::sha256(&program);
            let verification_key_sha256 = Digest32::sha256(&verification_key);
            pins.push(ReleaseCommonCredentialRootArtifactPin::try_new(
                circuit_ref,
                expected_source_lock_sha256,
                source_closure,
                bytecode_sha256,
                verification_key_sha256,
                exact_source_artifact_identity(
                    circuit_ref,
                    source_closure,
                    bytecode_sha256,
                    verification_key_sha256,
                )?,
            )?);
        }
    }
    Ok(pins)
}

pub(crate) fn validate_mobile_runtime_tree_against_index(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
) -> Result<(), ArtifactPackageError> {
    validate_runtime_tree(
        root,
        release_version,
        index,
        RuntimeContents::CompleteRelease,
    )
}

pub(crate) fn validate_mobile_public_runtime_tree_against_index(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
) -> Result<(), ArtifactPackageError> {
    validate_runtime_tree(root, release_version, index, RuntimeContents::PublicRuntime)
}

#[derive(Clone, Copy)]
enum RuntimeContents {
    CompleteRelease,
    PublicRuntime,
}

fn validate_runtime_tree(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
    contents: RuntimeContents,
) -> Result<(), ArtifactPackageError> {
    validate_mobile_runtime_root_entries(root, release_version, index)?;
    for pin in index.artifact_manifests() {
        validate_mobile_runtime_stage_artifact(root, index, *pin)?;
    }
    for pin in index.common_credential_root_artifacts() {
        validate_mobile_runtime_common_credential_root_artifact(root, *pin)?;
    }
    for pin in index.persona_credential_evidence_artifacts() {
        validate_mobile_runtime_persona_credential_evidence_artifact(root, *pin)?;
    }
    validate_mobile_runtime_exact_tree(root, release_version, index, contents)
}

fn validate_mobile_runtime_stage_artifact(
    root: &Path,
    index: &ReleaseIndex,
    pin: reallyme_zk_proto_codec::release::ReleaseArtifactPin,
) -> Result<(), ArtifactPackageError> {
    let circuit_ref = pin.circuit_ref();
    let layout = ArtifactPackageLayout::try_new(
        root,
        circuit_ref.credential_hash_algorithm,
        pin.bundle_kind(),
        pin.stage(),
        pin.manifest_sha256(),
    )?;
    let manifest_bytes = read_bounded_file(&layout.manifest(), MAX_ZK_ARTIFACT_MANIFEST_BYTES)?;
    let manifest = decode_artifact_manifest(&manifest_bytes)?;
    if manifest.bundle_kind() != pin.bundle_kind()
        || manifest.stage() != pin.stage()
        || manifest.circuit_ref() != circuit_ref
        || manifest.manifest_sha256() != pin.manifest_sha256()
        || manifest.toolchain() != index.toolchain()
        || manifest.proof_suite() != index.proof_suite()
        || manifest.digests().capability_registry_sha256 != index.capability_registry_sha256()
    {
        return package_mismatch();
    }
    let program = read_bounded_file(&layout.program(), ArtifactKind::AcirBytecode.max_bytes())?;
    if !manifest.digests().bytecode_sha256.matches_sha256(&program) {
        return package_mismatch();
    }
    let verification_key = read_bounded_file(
        &layout.verification_key(),
        ArtifactKind::VerificationKey.max_bytes(),
    )?;
    if !manifest
        .digests()
        .verification_key_sha256
        .matches_sha256(&verification_key)
    {
        return package_mismatch();
    }
    Ok(())
}

fn validate_mobile_runtime_common_credential_root_artifact(
    root: &Path,
    pin: ReleaseCommonCredentialRootArtifactPin,
) -> Result<(), ArtifactPackageError> {
    let layout = CommonCredentialRootArtifactLayout::try_new(root, pin.circuit_ref())?;
    let source_lock = read_bounded_file(
        &layout.source_lock(),
        MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
    )?;
    let program = read_bounded_file(&layout.program(), ArtifactKind::AcirBytecode.max_bytes())?;
    let verification_key = read_bounded_file(
        &layout.verification_key(),
        ArtifactKind::VerificationKey.max_bytes(),
    )?;
    if !pin.source_lock_sha256().matches_sha256(&source_lock)
        || common_credential_root_source_closure_from_lock(&source_lock, pin.circuit_ref())?
            != pin.source_closure_sha256()
        || !pin.bytecode_sha256().matches_sha256(&program)
        || !pin
            .verification_key_sha256()
            .matches_sha256(&verification_key)
    {
        return package_mismatch();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
