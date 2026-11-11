// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resumable assembly of real ZK proving vectors and stage artifact packages.
//!
//! This release-only crate never proves. It regenerates serialized witness
//! stacks, reverifies retained production proofs with the pinned backend, and
//! constructs canonical vectors plus packages in a caller-provided empty root.

use std::path::{Path, PathBuf};

use crate::source_tree::{validate_directory, validate_empty_directory, SourceTree};
use crate::{ReleaseAssemblyError, ReleaseAssemblyErrorReason};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleStage,
        ZkClaimProofBundleStageProof, ZkClaimProofBundleWitness,
    },
    proofs::{ZkDecodedPublicInputs, ZkSessionBinding},
};
use reallyme_zk_artifact_package::{
    assemble_release_index, ArtifactPackage, ArtifactPackageCoordinates, ArtifactPackageInput,
    ArtifactPackageMaterial, CanonicalBundleVectorFile, ReleaseArtifactManifestFile,
    ReleasePackageLayout, ReleaseVerificationVectorFile,
};
use reallyme_zk_artifacts::{ArtifactVersion, Digest32};
use reallyme_zk_proto_codec::{
    capability_registry::build_capability_registry,
    release::ReleaseArtifactPin,
    vector::{BundleProvingVectorInput, StageProvingVectorInput},
    verification_vector::{
        encode_claim_proof_bundle_verification_vector_set, ClaimProofBundleVerificationVectorInput,
    },
};
use reallyme_zk_release_process::{
    CompletedReleaseProofMaterial, ExistingReleaseProofPaths, PinnedReleaseProcess,
    ReleaseProcessRunner, ReleaseWitnessMaterialPaths,
};

const CIRCUITS_DIRECTORY: &str = "circuits";
const FAMILIES_DIRECTORY: &str = "families";
const TARGET_DIRECTORY: &str = "target";
const PROOF_DIRECTORY: &str = "proof";
const PROOF_FILE: &str = "proof";
const PUBLIC_INPUTS_FILE: &str = "public_inputs";
const VERIFICATION_KEY_DIRECTORY: &str = "verification_key";
const VERIFICATION_KEY_FILE: &str = "vk";
const COMPILED_PROGRAM_EXTENSION: &str = "json";
const PROVING_VECTOR_PATH: &str = "proving-spec/bundle.pb";
const EXPECTED_PACKAGE_COUNT: usize = ZkCredentialHashAlgorithm::ALL.len()
    * ZkClaimProofBundleKind::ALL.len()
    * ZkClaimProofBundleStage::ALL.len();
const EXPECTED_VECTOR_SET_COUNT: usize =
    ZkCredentialHashAlgorithm::ALL.len() * ZkClaimProofBundleKind::ALL.len();

/// Validated roots for one resumable production assembly.
///
/// This type omits `Debug` so local build-host paths do not enter diagnostics.
pub struct ProductionAssemblyPaths<'a> {
    workspace_root: &'a Path,
    proof_matrix_root: &'a Path,
    crs_directory: &'a Path,
    output_root: &'a Path,
    release_version: ArtifactVersion,
}

impl<'a> ProductionAssemblyPaths<'a> {
    /// Requires absolute existing inputs and an existing empty output root.
    pub fn try_new(
        workspace_root: &'a Path,
        proof_matrix_root: &'a Path,
        crs_directory: &'a Path,
        output_root: &'a Path,
        release_version: ArtifactVersion,
    ) -> Result<Self, ReleaseAssemblyError> {
        validate_directory(workspace_root)?;
        validate_directory(proof_matrix_root)?;
        validate_directory(crs_directory)?;
        validate_empty_directory(output_root)?;
        let _ = ReleasePackageLayout::try_new(output_root, release_version)?;
        Ok(Self {
            workspace_root,
            proof_matrix_root,
            crs_directory,
            output_root,
            release_version,
        })
    }
}

/// Counts produced by a complete production assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionAssemblySummary {
    /// Number of persisted stage packages.
    pub package_count: u32,
    /// Number of distinct bundle_kind/hash vector sets.
    pub vector_set_count: u32,
    /// SHA-256 identity of the canonical release index.
    pub release_index_sha256: Digest32,
}

/// Regenerates witnesses, reverifies retained proofs, and persists all packages.
pub fn assemble_production_packages<R: ReleaseProcessRunner>(
    process: &PinnedReleaseProcess<R>,
    paths: ProductionAssemblyPaths<'_>,
) -> Result<ProductionAssemblySummary, ReleaseAssemblyError> {
    let registry = build_capability_registry()?;
    let mut artifact_files = Vec::new();
    artifact_files
        .try_reserve_exact(EXPECTED_PACKAGE_COUNT)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    let mut verification_vector_files = Vec::new();
    verification_vector_files
        .try_reserve_exact(EXPECTED_VECTOR_SET_COUNT)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    let mut package_count = 0_usize;
    let mut vector_set_count = 0_usize;
    for credential_hash_algorithm in [
        ZkCredentialHashAlgorithm::Sha256,
        ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            let mut stage_material = Vec::new();
            stage_material
                .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
                .map_err(|_| {
                    ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow)
                })?;
            for stage in ZkClaimProofBundleStage::ALL {
                stage_material.push(load_stage_material(
                    process,
                    &paths,
                    *bundle_kind,
                    credential_hash_algorithm,
                    *stage,
                )?);
            }

            let mut proof_material = Vec::new();
            let mut witnesses = Vec::new();
            proof_material
                .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
                .map_err(|_| {
                    ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow)
                })?;
            witnesses
                .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
                .map_err(|_| {
                    ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow)
                })?;
            for material in stage_material {
                let (proof, witness) = material.into_parts();
                proof_material.push(proof);
                witnesses.push(witness);
            }
            let witness_bundle = ZkClaimProofBundleWitness::try_from_stage_witnesses(
                *bundle_kind,
                credential_hash_algorithm,
                witnesses,
            )?;
            let binding = session_binding_from_material(proof_material.first().ok_or(
                ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow),
            )?)?;
            let stage_inputs = stage_vector_inputs(
                *bundle_kind,
                credential_hash_algorithm,
                binding,
                &proof_material,
            )?;
            let vector_input = BundleProvingVectorInput::try_new(
                *bundle_kind,
                credential_hash_algorithm,
                &witness_bundle,
                binding,
                stage_inputs,
            )?;
            let vector_owner = CanonicalBundleVectorFile::try_from_input(
                Path::new(PROVING_VECTOR_PATH),
                vector_input,
            )?;
            vector_set_count = vector_set_count
                .checked_add(1)
                .ok_or(ReleaseAssemblyError::new(
                    ReleaseAssemblyErrorReason::LengthOverflow,
                ))?;

            let mut manifest_pins = Vec::new();
            let mut manifests = Vec::new();
            manifest_pins
                .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
                .map_err(|_| {
                    ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow)
                })?;
            manifests
                .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
                .map_err(|_| {
                    ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow)
                })?;
            for stage in ZkClaimProofBundleStage::ALL {
                let index = usize::from(stage.index());
                let material = proof_material.get(index).ok_or(ReleaseAssemblyError::new(
                    ReleaseAssemblyErrorReason::LengthOverflow,
                ))?;
                let output = build_stage_package(StagePackageInput {
                    process,
                    paths: &paths,
                    registry: &registry,
                    vector_owner: &vector_owner,
                    bundle_kind: *bundle_kind,
                    credential_hash_algorithm,
                    stage: *stage,
                    proof_material: material,
                })?;
                artifact_files.push(output.manifest_file);
                manifest_pins.push(output.manifest_pin);
                manifests.push(output.manifest);
                package_count = package_count
                    .checked_add(1)
                    .ok_or(ReleaseAssemblyError::new(
                        ReleaseAssemblyErrorReason::LengthOverflow,
                    ))?;
            }

            let manifest_pins: [ReleaseArtifactPin; 4] =
                manifest_pins.try_into().map_err(|_| {
                    ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow)
                })?;
            let claim_proof_bundle =
                build_claim_proof_bundle(*bundle_kind, binding, proof_material, &manifests)?;
            let verification_vector = encode_claim_proof_bundle_verification_vector_set(
                ClaimProofBundleVerificationVectorInput::try_new(
                    *bundle_kind,
                    credential_hash_algorithm,
                    &claim_proof_bundle,
                    manifest_pins,
                )?,
            )?;
            verification_vector_files.push(ReleaseVerificationVectorFile::try_new(
                &verification_vector,
            )?);
        }
    }
    if package_count != EXPECTED_PACKAGE_COUNT || vector_set_count != EXPECTED_VECTOR_SET_COUNT {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::LengthOverflow,
        ));
    }
    let release_version = core::str::from_utf8(paths.release_version.as_bytes())
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::InvalidArguments))?;
    let release =
        assemble_release_index(release_version, artifact_files, verification_vector_files)?;
    release.write_new(paths.output_root)?;
    release.check(paths.output_root)?;
    Ok(ProductionAssemblySummary {
        package_count: u32::try_from(package_count)
            .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?,
        vector_set_count: u32::try_from(vector_set_count)
            .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?,
        release_index_sha256: release.sha256(),
    })
}

fn build_claim_proof_bundle(
    bundle_kind: ZkClaimProofBundleKind,
    binding: ZkSessionBinding,
    proof_material: Vec<CompletedReleaseProofMaterial>,
    manifests: &[reallyme_zk_artifacts::ProductionArtifactManifest],
) -> Result<ZkClaimProofBundle, ReleaseAssemblyError> {
    let mut stage_proofs = Vec::new();
    stage_proofs
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    if manifests.len() != ZkClaimProofBundleStage::ALL.len() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::LengthOverflow,
        ));
    }
    for ((stage, material), manifest) in ZkClaimProofBundleStage::ALL
        .iter()
        .zip(proof_material)
        .zip(manifests)
    {
        if manifest.bundle_kind() != bundle_kind || manifest.stage() != *stage {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::Domain(
                    reallyme_zk_api::errors::ZkErrorReason::StageMismatch,
                ),
            ));
        }
        let proof = material.into_manifest_bound_proof(manifest)?;
        stage_proofs.push(ZkClaimProofBundleStageProof::try_from_parts(
            bundle_kind,
            *stage,
            proof,
        )?);
    }
    Ok(ZkClaimProofBundle::try_from_stage_proofs(
        bundle_kind,
        binding,
        stage_proofs,
    )?)
}

fn load_stage_material<R: ReleaseProcessRunner>(
    process: &PinnedReleaseProcess<R>,
    paths: &ProductionAssemblyPaths<'_>,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
) -> Result<reallyme_zk_release_process::CompletedReleaseProvingMaterial, ReleaseAssemblyError> {
    let circuit_directory = circuit_directory(
        paths.workspace_root,
        bundle_kind,
        credential_hash_algorithm,
        stage,
    );
    let package_name = ArtifactVersion::try_from_token(bundle_kind.nargo_package_name(stage))?;
    let compiled_program = circuit_directory
        .join(TARGET_DIRECTORY)
        .join(bundle_kind.nargo_package_name(stage))
        .with_extension(COMPILED_PROGRAM_EXTENSION);
    let output_directory = paths
        .proof_matrix_root
        .join(credential_hash_algorithm.as_str())
        .join(bundle_kind.as_str())
        .join(stage.as_str());
    let verification_key = output_directory
        .join(VERIFICATION_KEY_DIRECTORY)
        .join(VERIFICATION_KEY_FILE);
    let proof = output_directory.join(PROOF_DIRECTORY).join(PROOF_FILE);
    let public_inputs = output_directory
        .join(PROOF_DIRECTORY)
        .join(PUBLIC_INPUTS_FILE);
    let proof_paths = ExistingReleaseProofPaths::try_new(
        bundle_kind.source_ref(credential_hash_algorithm, stage),
        paths.crs_directory,
        &compiled_program,
        &verification_key,
        &proof,
        &public_inputs,
    )?;
    let material_paths =
        ReleaseWitnessMaterialPaths::try_new(&circuit_directory, package_name, proof_paths)?;
    Ok(process.regenerate_witness_and_load_material(material_paths)?)
}

fn session_binding_from_material(
    material: &CompletedReleaseProofMaterial,
) -> Result<ZkSessionBinding, ReleaseAssemblyError> {
    let decoded =
        ZkDecodedPublicInputs::try_decode(material.circuit_ref(), material.public_inputs())?;
    Ok(ZkSessionBinding {
        nonce_hash: decoded.challenge(),
        audience_hash: decoded.audience_hash(),
        transaction_data_hash: decoded.transaction_data_hash(),
    })
}

fn stage_vector_inputs<'a>(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    binding: ZkSessionBinding,
    material: &'a [CompletedReleaseProofMaterial],
) -> Result<[StageProvingVectorInput<'a>; 4], ReleaseAssemblyError> {
    Ok([
        stage_vector_input(
            bundle_kind,
            credential_hash_algorithm,
            binding,
            material,
            ZkClaimProofBundleStage::Session,
        )?,
        stage_vector_input(
            bundle_kind,
            credential_hash_algorithm,
            binding,
            material,
            ZkClaimProofBundleStage::CredentialEnvelope,
        )?,
        stage_vector_input(
            bundle_kind,
            credential_hash_algorithm,
            binding,
            material,
            ZkClaimProofBundleStage::CredentialRoot,
        )?,
        stage_vector_input(
            bundle_kind,
            credential_hash_algorithm,
            binding,
            material,
            ZkClaimProofBundleStage::Claim,
        )?,
    ])
}

fn stage_vector_input<'a>(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    binding: ZkSessionBinding,
    material: &'a [CompletedReleaseProofMaterial],
    stage: ZkClaimProofBundleStage,
) -> Result<StageProvingVectorInput<'a>, ReleaseAssemblyError> {
    let material = material
        .get(usize::from(stage.index()))
        .ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::LengthOverflow,
        ))?;
    if material.circuit_ref() != bundle_kind.source_ref(credential_hash_algorithm, stage) {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::Domain(
                reallyme_zk_api::errors::ZkErrorReason::StageMismatch,
            ),
        ));
    }
    Ok(StageProvingVectorInput::try_new(
        bundle_kind,
        credential_hash_algorithm,
        stage,
        *Digest32::sha256(material.verification_key().as_bytes()).as_bytes(),
        material.public_inputs(),
        binding,
    )?)
}

struct StagePackageInput<'a, R: ReleaseProcessRunner> {
    process: &'a PinnedReleaseProcess<R>,
    paths: &'a ProductionAssemblyPaths<'a>,
    registry: &'a reallyme_zk_proto_codec::capability_registry::CanonicalCapabilityRegistry,
    vector_owner: &'a CanonicalBundleVectorFile,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
    proof_material: &'a CompletedReleaseProofMaterial,
}

struct StagePackageOutput {
    manifest_file: ReleaseArtifactManifestFile,
    manifest_pin: ReleaseArtifactPin,
    manifest: reallyme_zk_artifacts::ProductionArtifactManifest,
}

fn build_stage_package<R: ReleaseProcessRunner>(
    input: StagePackageInput<'_, R>,
) -> Result<StagePackageOutput, ReleaseAssemblyError> {
    let circuit_directory = circuit_directory(
        input.paths.workspace_root,
        input.bundle_kind,
        input.credential_hash_algorithm,
        input.stage,
    );
    let source_tree = SourceTree::load(input.paths.workspace_root, &circuit_directory)?;
    let source_files = source_tree.borrowed_files()?;
    let vectors = [input.vector_owner.as_artifact_vector_file()?];
    let package_material = ArtifactPackageMaterial::try_new(
        &source_files,
        input.proof_material.compiled_program().as_bytes(),
        input.proof_material.verification_key().as_bytes(),
        input.registry,
        &vectors,
    )?;
    let coordinates = ArtifactPackageCoordinates::new(
        input.bundle_kind,
        input.stage,
        input.credential_hash_algorithm,
        input.process.toolchain(),
    );
    let package = ArtifactPackage::build(ArtifactPackageInput::new(coordinates, package_material))?;
    let manifest = package.manifest().clone();
    let manifest_pin = ReleaseArtifactPin::try_new(
        input.bundle_kind,
        input.stage,
        manifest.circuit_ref(),
        manifest.manifest_sha256(),
    )?;
    let manifest_file = ReleaseArtifactManifestFile::try_new(package.manifest_bytes())?;
    package.write_new(input.paths.output_root)?;
    package.check(input.paths.output_root)?;
    Ok(StagePackageOutput {
        manifest_file,
        manifest_pin,
        manifest,
    })
}

pub(crate) fn circuit_directory(
    workspace_root: &Path,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
) -> PathBuf {
    workspace_root
        .join(CIRCUITS_DIRECTORY)
        .join(credential_hash_algorithm.as_str())
        .join(FAMILIES_DIRECTORY)
        .join(bundle_kind.as_str())
        .join(stage.as_str())
}
