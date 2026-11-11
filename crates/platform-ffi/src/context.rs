// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs::File,
    io::{Read, Take},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofSuite, ZkWitness},
};
use reallyme_zk_artifacts::{ArtifactPackageLayout, Digest32, ProductionBundleManifest};
use reallyme_zk_backend_bb::{
    BarretenbergArtifactResolver, BarretenbergProverCrs, BarretenbergVerifierCrs,
    BbExactCircuitArtifacts, ManifestBackedArtifactResolver, NativeBarretenbergBackend,
    NativeFilesystemArtifactStore,
};
use reallyme_zk_proto_codec::{
    artifact::{decode_artifact_manifest, MAX_ZK_ARTIFACT_MANIFEST_BYTES},
    release::ReleaseIndex,
};
use zeroize::Zeroizing;

pub(crate) const MAX_PLATFORM_PATH_BYTES: usize = 4096;

use crate::{input::crs_lengths_for_mode, retained_witness::RetainedStageWitnessStore};

mod common_credential_root;
mod exact_source;
mod persona_credential_evidence;
mod trust_root;
pub(crate) use trust_root::{decode_pinned_release_index, RELEASE_INDEX_SHA256_BYTES};

pub(crate) enum PlatformCrsMode {
    VerifierOnly,
    FullProver,
}

pub(crate) struct PlatformContext {
    backend: NativeBarretenbergBackend,
    artifact_root: PathBuf,
    release_index: ReleaseIndex,
    crs_mode: PlatformCrsMode,
    dispatch_active: AtomicBool,
    retained_witnesses: RetainedStageWitnessStore,
}

pub(crate) struct DispatchLease<'a> {
    active: &'a AtomicBool,
}

impl PlatformContext {
    pub(crate) fn try_new(
        artifact_root_bytes: &[u8],
        release_index_bytes: &[u8],
        expected_release_index_sha256_bytes: &[u8],
        crs_g1_bytes: &[u8],
        crs_g2_bytes: &[u8],
        crs_mode: PlatformCrsMode,
    ) -> Result<Self, ZkError> {
        let artifact_root = path_from_platform_bytes(artifact_root_bytes)?;
        let release_index =
            decode_pinned_release_index(release_index_bytes, expected_release_index_sha256_bytes)?;
        let backend = NativeBarretenbergBackend::try_new()?;
        initialize_backend_crs(&backend, crs_g1_bytes, crs_g2_bytes, &crs_mode)?;
        Ok(Self::from_initialized(
            backend,
            artifact_root,
            release_index,
            crs_mode,
        ))
    }

    pub(crate) fn try_new_from_crs_files(
        artifact_root_bytes: &[u8],
        release_index_bytes: &[u8],
        expected_release_index_sha256_bytes: &[u8],
        crs_g1_path_bytes: &[u8],
        crs_g2_path_bytes: &[u8],
        crs_mode: PlatformCrsMode,
    ) -> Result<Self, ZkError> {
        let artifact_root = path_from_platform_bytes(artifact_root_bytes)?;
        let release_index =
            decode_pinned_release_index(release_index_bytes, expected_release_index_sha256_bytes)?;
        let crs_g1_path = path_from_platform_bytes(crs_g1_path_bytes)?;
        let crs_g2_path = path_from_platform_bytes(crs_g2_path_bytes)?;
        let crs_lengths = crs_lengths_for_mode(&crs_mode);
        let crs_g1 = read_exact_regular_file(&crs_g1_path, crs_lengths.g1_prefix)?;
        let crs_g2 = read_exact_regular_file(&crs_g2_path, crs_lengths.g2)?;
        let backend = NativeBarretenbergBackend::try_new()?;
        initialize_backend_crs(&backend, crs_g1.as_slice(), crs_g2.as_slice(), &crs_mode)?;
        Ok(Self::from_initialized(
            backend,
            artifact_root,
            release_index,
            crs_mode,
        ))
    }

    fn from_initialized(
        backend: NativeBarretenbergBackend,
        artifact_root: PathBuf,
        release_index: ReleaseIndex,
        crs_mode: PlatformCrsMode,
    ) -> Self {
        Self {
            backend,
            artifact_root,
            release_index,
            crs_mode,
            dispatch_active: AtomicBool::new(false),
            retained_witnesses: RetainedStageWitnessStore::new(),
        }
    }

    pub(crate) const fn backend(&self) -> &NativeBarretenbergBackend {
        &self.backend
    }

    pub(crate) const fn crs_mode(&self) -> &PlatformCrsMode {
        &self.crs_mode
    }

    pub(crate) fn acquire_dispatch(&self) -> Result<DispatchLease<'_>, ZkError> {
        DispatchLease::try_acquire(&self.dispatch_active)
    }

    pub(crate) fn resolver(
        &self,
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
    ) -> Result<ManifestBackedArtifactResolver<NativeFilesystemArtifactStore>, ZkError> {
        if self.release_index.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        let mut manifests = Vec::new();
        manifests
            .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        for stage in ZkClaimProofBundleStage::ALL {
            manifests.push(self.stage_manifest(bundle_kind, *stage, credential_hash_algorithm)?);
        }
        let bundle = ProductionBundleManifest::try_from_stage_manifests(
            bundle_kind,
            credential_hash_algorithm,
            manifests,
        )?;
        let store = NativeFilesystemArtifactStore::try_new(&self.artifact_root)?;
        Ok(ManifestBackedArtifactResolver::from_configured_trust_root(
            bundle, store,
        ))
    }

    pub(crate) fn stage_manifest_for_ref(
        &self,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<reallyme_zk_artifacts::ProductionArtifactManifest, ZkError> {
        let (bundle_kind, stage) = coordinates_for_circuit_ref(circuit_ref)?;
        self.stage_manifest(bundle_kind, stage, circuit_ref.credential_hash_algorithm)
            .and_then(|manifest| {
                if manifest.proof_suite() == proof_suite {
                    Ok(manifest)
                } else {
                    Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite))
                }
            })
    }

    #[cfg(feature = "diagnostic-exact-source")]
    pub(crate) fn claim_bundle4_exact_artifacts(
        &self,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        exact_source::claim_bundle4_exact_artifacts(&self.artifact_root, circuit_ref, proof_suite)
    }

    pub(crate) fn production_exact_artifacts_for_ref(
        &self,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        let (bundle_kind, stage) = coordinates_for_circuit_ref(circuit_ref)?;
        let resolver = self.resolver(
            bundle_kind,
            circuit_ref.credential_hash_algorithm,
            proof_suite,
        )?;
        let artifacts =
            resolver.resolve_stage_artifacts(bundle_kind, stage, circuit_ref, proof_suite)?;
        BbExactCircuitArtifacts::try_new(
            circuit_ref,
            artifacts.manifest().manifest_sha256(),
            artifacts.bytecode().clone(),
            artifacts.verification_key().clone(),
        )
    }

    pub(crate) fn retain_stage_witness(
        &self,
        circuit_ref: ZkCircuitRef,
        witness: ZkWitness,
    ) -> Result<u64, ZkError> {
        self.retained_witnesses.retain(circuit_ref, witness)
    }

    pub(crate) fn take_stage_witness(
        &self,
        handle_id: u64,
        circuit_ref: ZkCircuitRef,
    ) -> Result<ZkWitness, ZkError> {
        self.retained_witnesses.take(handle_id, circuit_ref)
    }

    pub(crate) fn take_ordered_stage_witnesses_or_release_present(
        &self,
        handles: &[(u64, ZkCircuitRef)],
    ) -> Result<Vec<ZkWitness>, ZkError> {
        self.retained_witnesses
            .take_ordered_or_release_present(handles)
    }

    pub(crate) fn release_stage_witnesses_present(
        &self,
        handles: &[(u64, ZkCircuitRef)],
    ) -> Result<(), ZkError> {
        self.retained_witnesses.release_present(handles)
    }

    pub(crate) fn release_stage_witness(
        &self,
        handle_id: u64,
        circuit_ref: ZkCircuitRef,
    ) -> Result<(), ZkError> {
        self.retained_witnesses.release(handle_id, circuit_ref)
    }

    fn stage_manifest(
        &self,
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
    ) -> Result<reallyme_zk_artifacts::ProductionArtifactManifest, ZkError> {
        let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
        let pin = self
            .release_index
            .artifact_manifests()
            .iter()
            .copied()
            .find(|pin| pin.circuit_ref() == circuit_ref)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let layout = ArtifactPackageLayout::try_new(
            &self.artifact_root,
            credential_hash_algorithm,
            bundle_kind,
            stage,
            pin.manifest_sha256(),
        )?;
        let bytes = read_manifest_bytes(&self.artifact_root, &layout.manifest())?;
        if Digest32::sha256(bytes.as_slice()).as_bytes() != pin.manifest_sha256().as_bytes() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let manifest = decode_artifact_manifest(bytes.as_slice())?;
        if manifest.circuit_ref() != circuit_ref
            || manifest.manifest_sha256() != pin.manifest_sha256()
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(manifest)
    }
}

fn initialize_backend_crs(
    backend: &NativeBarretenbergBackend,
    crs_g1_bytes: &[u8],
    crs_g2_bytes: &[u8],
    crs_mode: &PlatformCrsMode,
) -> Result<(), ZkError> {
    match crs_mode {
        PlatformCrsMode::VerifierOnly => {
            let crs = BarretenbergVerifierCrs::try_from_pinned_slices(crs_g1_bytes, crs_g2_bytes)?;
            backend.initialize_verifier_crs(crs)?;
        }
        PlatformCrsMode::FullProver => {
            let crs = BarretenbergProverCrs::try_from_pinned_slices(crs_g1_bytes, crs_g2_bytes)?;
            backend.initialize_prover_crs(crs)?;
        }
    }
    Ok(())
}

impl<'a> DispatchLease<'a> {
    fn try_acquire(active: &'a AtomicBool) -> Result<Self, ZkError> {
        match active.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => Ok(Self { active }),
            Err(_) => Err(ZkError::new(ZkErrorReason::BackendUnavailable)),
        }
    }
}

impl Drop for DispatchLease<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

pub(crate) fn coordinates_for_circuit_ref(
    circuit_ref: ZkCircuitRef,
) -> Result<(ZkClaimProofBundleKind, ZkClaimProofBundleStage), ZkError> {
    for bundle_kind in ZkClaimProofBundleKind::ALL {
        for stage in ZkClaimProofBundleStage::ALL {
            if bundle_kind.source_ref(circuit_ref.credential_hash_algorithm, *stage) == circuit_ref
            {
                return Ok((*bundle_kind, *stage));
            }
        }
    }
    Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
}

fn path_from_platform_bytes(bytes: &[u8]) -> Result<PathBuf, ZkError> {
    if bytes.is_empty() || bytes.len() > MAX_PLATFORM_PATH_BYTES {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let text =
        core::str::from_utf8(bytes).map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(path)
}

fn read_manifest_bytes(artifact_root: &Path, path: &Path) -> Result<Vec<u8>, ZkError> {
    let relative_path = path
        .strip_prefix(artifact_root)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let root = secure_open::open_root_directory(artifact_root).map_err(map_filesystem_error)?;
    let file = secure_open::open_relative_regular_file(&root, relative_path)
        .map_err(map_filesystem_error)?;
    let metadata = file
        .metadata()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if !metadata.is_file() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let len = usize::try_from(metadata.len())
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if len == 0 || len > MAX_ZK_ARTIFACT_MANIFEST_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut reader: Take<File> = file.take(
        u64::try_from(MAX_ZK_ARTIFACT_MANIFEST_BYTES)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?,
    );
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if after.len() != metadata.len() || bytes.len() != len {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(bytes)
}

fn read_exact_regular_file(
    path: &Path,
    expected_len: usize,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if expected_len == 0 {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let file = secure_open::open_absolute_regular_file(path).map_err(map_filesystem_error)?;
    let metadata = file
        .metadata()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if !metadata.is_file() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let len = usize::try_from(metadata.len())
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if len != expected_len {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let read_limit = u64::try_from(expected_len)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
        .checked_add(1)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut reader: Take<File> = file.take(read_limit);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if after.len() != metadata.len() || bytes.len() != expected_len {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
#[path = "context/tests.rs"]
mod tests;

fn map_filesystem_error(error: std::io::Error) -> ZkError {
    let path_rejected = matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    ) || rejected_path_component(&error);
    if path_rejected {
        ZkError::new(ZkErrorReason::ArtifactMismatch)
    } else {
        ZkError::new(ZkErrorReason::BackendFailure)
    }
}

#[cfg(unix)]
fn rejected_path_component(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::ENOTDIR)
    )
}

#[cfg(not(unix))]
const fn rejected_path_component(_error: &std::io::Error) -> bool {
    false
}

#[allow(unsafe_code)]
mod secure_open;
