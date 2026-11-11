// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fs, io::Read, path::Path};

use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    common_credential_root_source_closure_from_lock, ArtifactDigests, ArtifactKind,
    ArtifactManifestPin, ArtifactPackageLayout, ArtifactToolchain,
    CommonCredentialRootArtifactLayout, Digest32, ProductionArtifactManifest,
    ProductionBundleManifest, VerifiedArtifactBytes,
};
use reallyme_zk_backend_bb::{
    BarretenbergArtifactResolver, BarretenbergCommonCredentialRootArtifactResolver,
    BbExactCircuitArtifacts, BbStageArtifacts, BbStageVerificationArtifacts,
};
use reallyme_zk_proto_codec::{
    artifact::decode_artifact_manifest,
    release::{decode_release_index, ReleaseArtifactPin, ReleaseCommonCredentialRootArtifactPin},
};

use crate::error::HarnessError;
use crate::modern_all30::{load_circuit_evidence, CircuitEvidence};

const MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_MANIFEST_BYTES: usize = 1024 * 1024;

struct StageMaterial {
    evidence: CircuitEvidence,
    manifest: ProductionArtifactManifest,
}

pub(crate) struct StageResolver {
    bundle: ProductionBundleManifest,
    stages: Vec<StageMaterial>,
    common_credential_root_artifact_root: Option<std::path::PathBuf>,
    production_pins: Vec<ReleaseArtifactPin>,
    common_credential_root_pins: Vec<ReleaseCommonCredentialRootArtifactPin>,
}

pub(crate) fn load_private_persona_stages(
    root: &Path,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<Vec<CircuitEvidence>, HarnessError> {
    load_production_stages(
        root,
        credential_hash_algorithm,
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
    )
}

pub(crate) fn load_production_stages(
    root: &Path,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    profile: ZkClaimProofBundleKind,
) -> Result<Vec<CircuitEvidence>, HarnessError> {
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| HarnessError::InvalidLength)?;
    for stage in ZkClaimProofBundleStage::ALL {
        stages.push(load_circuit_evidence(
            root,
            profile.source_ref(credential_hash_algorithm, *stage),
        )?);
    }
    Ok(stages)
}

impl StageResolver {
    pub(crate) fn try_new(
        profile: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        evidence: Vec<CircuitEvidence>,
    ) -> Result<Self, HarnessError> {
        let mut stages = Vec::new();
        stages
            .try_reserve_exact(evidence.len())
            .map_err(|_| HarnessError::InvalidLength)?;
        let mut manifests = Vec::new();
        manifests
            .try_reserve_exact(evidence.len())
            .map_err(|_| HarnessError::InvalidLength)?;
        for item in evidence {
            let manifest = manifest_for(profile, &item)?;
            manifests.push(manifest.clone());
            stages.push(StageMaterial {
                evidence: item,
                manifest,
            });
        }
        let bundle = ProductionBundleManifest::try_from_stage_manifests(
            profile,
            credential_hash_algorithm,
            manifests,
        )?;
        Ok(Self {
            bundle,
            stages,
            common_credential_root_artifact_root: None,
            production_pins: Vec::new(),
            common_credential_root_pins: Vec::new(),
        })
    }

    pub(crate) fn with_common_credential_root_release(
        mut self,
        artifact_root: &Path,
        release_index: &[u8],
    ) -> Result<Self, HarnessError> {
        let release_index = decode_release_index(release_index)?;
        self.production_pins = release_index.artifact_manifests().to_vec();
        self.common_credential_root_pins =
            release_index.common_credential_root_artifacts().to_vec();
        self.common_credential_root_artifact_root = Some(artifact_root.to_path_buf());
        Ok(self)
    }

    fn material(
        &self,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<&StageMaterial, ZkError> {
        let material = self
            .stages
            .iter()
            .find(|candidate| candidate.manifest.stage() == stage)
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        if material.evidence.circuit_ref != circuit_ref
            || material.manifest.proof_suite() != proof_suite
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(material)
    }
}

impl BarretenbergArtifactResolver for StageResolver {
    fn resolve_stage_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError> {
        if self.bundle.bundle_kind() != profile || self.bundle.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let material = self.material(stage, circuit_ref, proof_suite)?;
        BbStageArtifacts::try_new(
            material.manifest.clone(),
            material.evidence.artifacts.bytecode().clone(),
            material.evidence.artifacts.verification_key().clone(),
        )
    }

    fn resolve_stage_verification_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageVerificationArtifacts, ZkError> {
        if self.bundle.bundle_kind() != profile || self.bundle.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let material = self.material(stage, circuit_ref, proof_suite)?;
        BbStageVerificationArtifacts::try_new(
            material.manifest.clone(),
            material.evidence.artifacts.verification_key().clone(),
        )
    }
}

impl BarretenbergCommonCredentialRootArtifactResolver for StageResolver {
    fn resolve_common_credential_root_artifacts(
        &self,
        profile: reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode,
        slot: reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        proof_suite.require_production()?;
        if profile.source_ref(circuit_ref.credential_hash_algorithm, slot) != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        match circuit_ref.family {
            ZkCircuitFamily::PrivatePersonaClaimV1 => {
                let stage = production_stage(circuit_ref.stage)?;
                let artifact_root = self
                    .common_credential_root_artifact_root
                    .as_deref()
                    .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
                self.release_exact_artifacts(
                    artifact_root,
                    profile,
                    stage,
                    circuit_ref,
                    proof_suite,
                )
            }
            ZkCircuitFamily::CommonCredentialRootV1 => {
                let artifact_root = self
                    .common_credential_root_artifact_root
                    .as_deref()
                    .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
                let pin = self
                    .common_credential_root_pins
                    .iter()
                    .copied()
                    .find(|candidate| candidate.circuit_ref() == circuit_ref)
                    .ok_or(ZkError::new(ZkErrorReason::UnsupportedCircuit))?;
                common_credential_root_release_artifacts(artifact_root, pin, proof_suite)
            }
            _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        }
    }
}

impl StageResolver {
    fn release_exact_artifacts(
        &self,
        artifact_root: &Path,
        profile: reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        proof_suite.require_production()?;
        let bundle_kind = match profile {
            reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode::PrivatePersona => {
                ZkClaimProofBundleKind::PrivatePersonaClaimV1
            }
            _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        };
        let pin = self
            .production_pins
            .iter()
            .copied()
            .find(|pin| {
                pin.bundle_kind() == bundle_kind
                    && pin.stage() == stage
                    && pin.circuit_ref() == circuit_ref
            })
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let layout = ArtifactPackageLayout::try_new(
            artifact_root,
            circuit_ref.credential_hash_algorithm,
            bundle_kind,
            stage,
            pin.manifest_sha256(),
        )?;
        ensure_descendant_regular_path(artifact_root, &layout.manifest())?;
        ensure_descendant_regular_path(artifact_root, &layout.program())?;
        ensure_descendant_regular_path(artifact_root, &layout.verification_key())?;
        let manifest_bytes =
            read_bounded_regular_file_with_limit(&layout.manifest(), MAX_ARTIFACT_MANIFEST_BYTES)?;
        if Digest32::sha256(manifest_bytes.as_slice()).as_bytes()
            != pin.manifest_sha256().as_bytes()
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let manifest = decode_artifact_manifest(manifest_bytes.as_slice())?;
        if manifest.bundle_kind() != bundle_kind
            || manifest.stage() != stage
            || manifest.circuit_ref() != circuit_ref
            || manifest.proof_suite() != proof_suite
            || manifest.manifest_sha256() != pin.manifest_sha256()
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let program = read_bounded_regular_file(&layout.program(), ArtifactKind::AcirBytecode)?;
        let verification_key =
            read_bounded_regular_file(&layout.verification_key(), ArtifactKind::VerificationKey)?;
        let bytecode = VerifiedArtifactBytes::try_from_bytes(
            ArtifactKind::AcirBytecode,
            program,
            manifest.digests().bytecode_sha256,
        )?;
        let key = VerifiedArtifactBytes::try_from_bytes(
            ArtifactKind::VerificationKey,
            verification_key,
            manifest.digests().verification_key_sha256,
        )?;
        BbExactCircuitArtifacts::try_new(circuit_ref, pin.manifest_sha256(), bytecode, key)
    }
}

fn common_credential_root_release_artifacts(
    artifact_root: &Path,
    pin: ReleaseCommonCredentialRootArtifactPin,
    proof_suite: ZkProofSuite,
) -> Result<BbExactCircuitArtifacts, ZkError> {
    proof_suite.require_production()?;
    ensure_directory_not_symlink(artifact_root)?;
    let layout = CommonCredentialRootArtifactLayout::try_new(artifact_root, pin.circuit_ref())?;
    ensure_descendant_regular_path(artifact_root, &layout.source_lock())?;
    ensure_descendant_regular_path(artifact_root, &layout.program())?;
    ensure_descendant_regular_path(artifact_root, &layout.verification_key())?;
    let source_lock = read_bounded_regular_file_with_limit(
        &layout.source_lock(),
        MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
    )?;
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

fn ensure_directory_not_symlink(path: &Path) -> Result<(), ZkError> {
    let metadata = fs::symlink_metadata(path).map_err(map_filesystem_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}

fn ensure_descendant_regular_path(artifact_root: &Path, path: &Path) -> Result<(), ZkError> {
    let relative = path
        .strip_prefix(artifact_root)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let mut current = artifact_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).map_err(map_filesystem_error)?;
        if metadata.file_type().is_symlink() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, kind: ArtifactKind) -> Result<Vec<u8>, ZkError> {
    read_bounded_regular_file_with_limit(path, kind.max_bytes())
}

fn read_bounded_regular_file_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ZkError> {
    if max_bytes == 0 {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let metadata = fs::symlink_metadata(path).map_err(map_filesystem_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
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
    let file = fs::File::open(path).map_err(map_filesystem_error)?;
    let mut reader = file.take(read_limit);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    reader
        .read_to_end(&mut bytes)
        .map_err(map_filesystem_error)?;
    let after = fs::symlink_metadata(path).map_err(map_filesystem_error)?;
    if after.len() != metadata.len()
        || after.file_type().is_symlink()
        || bytes.len() != declared_len
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(bytes)
}

fn map_filesystem_error(error: std::io::Error) -> ZkError {
    let path_rejected = matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    );
    if path_rejected {
        ZkError::new(ZkErrorReason::ArtifactMismatch)
    } else {
        ZkError::new(ZkErrorReason::BackendFailure)
    }
}

fn manifest_for(
    profile: ZkClaimProofBundleKind,
    evidence: &CircuitEvidence,
) -> Result<ProductionArtifactManifest, ZkError> {
    let stage = production_stage(evidence.circuit_ref.stage)?;
    ProductionArtifactManifest::try_new(
        profile,
        stage,
        evidence.circuit_ref,
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, evidence.artifact_identity)?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(evidence.circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: evidence.source_closure_sha256,
            bytecode_sha256: evidence.artifacts.bytecode().digest(),
            verification_key_sha256: evidence.artifacts.verification_key().digest(),
            capability_registry_sha256: capability_registry_digest(evidence.circuit_ref),
            vector_set_sha256: vec![Digest32::sha256(evidence.proof.proof_bytes())],
        },
    )
}

fn production_stage(stage: ZkCircuitStage) -> Result<ZkClaimProofBundleStage, ZkError> {
    match stage {
        ZkCircuitStage::Session => Ok(ZkClaimProofBundleStage::Session),
        ZkCircuitStage::CredentialEnvelope => Ok(ZkClaimProofBundleStage::CredentialEnvelope),
        ZkCircuitStage::CredentialRoot => Ok(ZkClaimProofBundleStage::CredentialRoot),
        ZkCircuitStage::Claim => Ok(ZkClaimProofBundleStage::Claim),
        ZkCircuitStage::ClaimBundle4 => Err(ZkError::new(ZkErrorReason::StageMismatch)),
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn capability_registry_digest(circuit_ref: ZkCircuitRef) -> Digest32 {
    Digest32::sha256(circuit_ref_capability_bytes(circuit_ref).as_bytes())
}

fn circuit_ref_capability_bytes(circuit_ref: ZkCircuitRef) -> String {
    [
        circuit_ref.credential_hash_algorithm.as_str(),
        "/",
        circuit_ref.family.as_str(),
        "/",
        circuit_ref.stage.as_str(),
        "/",
        "v1",
    ]
    .concat()
}
