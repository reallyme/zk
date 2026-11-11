// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical package assembly, create-new persistence, and verification.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use buffa::Message;
use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    ArtifactBytes, ArtifactDigests, ArtifactKind, ArtifactPackageLayout, ArtifactToolchain,
    Digest32, ProductionArtifactManifest, ProductionArtifactManifestDraft,
    ARTIFACT_MANIFEST_FILE_NAME, ARTIFACT_PROGRAM_FILE_NAME, ARTIFACT_VERIFICATION_KEY_FILE_NAME,
    MAX_ACIR_BYTECODE_BYTES, MAX_VECTOR_SET_DIGESTS, MAX_VERIFICATION_KEY_BYTES,
};
use reallyme_zk_proto_codec::artifact::seal_artifact_manifest;
use reallyme_zk_proto_codec::capability_registry::CanonicalCapabilityRegistry;
use reallyme_zk_proto_codec::release::ReleaseArtifactPin;
use reallyme_zk_proto_codec::vector::decode_proving_vector_set;
use reallyme_zk_proto_codec::vector::{encode_bundle_proving_vector_set, BundleProvingVectorInput};
use zeroize::Zeroizing;

use crate::{
    hash::{hash_named_files, validate_relative_path, NamedFile},
    ArtifactPackageError, ArtifactPackageErrorReason,
};

const SOURCE_TREE_HASH_DOMAIN: &[u8] = b"reallyme-zk-noir-source-tree-v1\0";
const VECTOR_FILE_HASH_DOMAIN: &[u8] = b"reallyme-zk-vector-file-v1\0";
const MANIFEST_MAX_BYTES: usize = 64 * 1024;

mod limits;
pub use limits::{
    MAX_CAPABILITY_REGISTRY_BYTES, MAX_NOIR_SOURCE_BYTES, MAX_NOIR_SOURCE_FILES,
    MAX_VECTOR_FILE_BYTES,
};

/// Hashes a full dependency-closed, repository-relative Noir source tree.
pub fn noir_source_tree_sha256(
    source_files: &[ArtifactSourceFile<'_>],
) -> Result<Digest32, ArtifactPackageError> {
    validate_file_count(source_files.len(), MAX_NOIR_SOURCE_FILES)?;
    validate_aggregate_source_bytes(source_files)?;
    validate_file_order(source_files, SOURCE_TREE_HASH_DOMAIN)?;
    hash_named_files(SOURCE_TREE_HASH_DOMAIN, source_files)
}

/// One normalized source file used in the source-tree identity.
#[derive(Debug, Clone, Copy)]
pub struct ArtifactSourceFile<'a> {
    relative_path: &'a Path,
    contents: &'a [u8],
}

impl<'a> ArtifactSourceFile<'a> {
    /// Validates a non-empty package-relative source path and content.
    pub fn try_new(
        relative_path: &'a Path,
        contents: &'a [u8],
    ) -> Result<Self, ArtifactPackageError> {
        validate_relative_path(relative_path)?;
        validate_nonempty_bounded(contents, MAX_NOIR_SOURCE_BYTES)?;
        Ok(Self {
            relative_path,
            contents,
        })
    }
}

impl NamedFile for ArtifactSourceFile<'_> {
    fn relative_path(&self) -> &Path {
        self.relative_path
    }

    fn contents(&self) -> &[u8] {
        self.contents
    }
}

/// One canonical vector-set protobuf file.
#[derive(Clone, Copy)]
pub struct ArtifactVectorFile<'a> {
    relative_path: &'a Path,
    contents: &'a [u8],
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
}

impl<'a> ArtifactVectorFile<'a> {
    /// Validates a non-empty package-relative protobuf vector file.
    pub fn try_new(
        relative_path: &'a Path,
        contents: &'a [u8],
    ) -> Result<Self, ArtifactPackageError> {
        validate_relative_path(relative_path)?;
        if relative_path.extension() != Some(OsStr::new("pb")) {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ));
        }
        validate_nonempty_bounded(contents, MAX_VECTOR_FILE_BYTES)?;
        let validated = decode_proving_vector_set(contents)?;
        Ok(Self {
            relative_path,
            contents,
            bundle_kind: validated.bundle_kind(),
            credential_hash_algorithm: validated.credential_hash_algorithm(),
            proof_suite: validated.proof_suite(),
        })
    }
}

/// Owned canonical bundle-vector bytes ready for artifact-package admission.
///
/// This owner intentionally implements neither `Debug` nor `Clone`: its binary
/// protobuf transitively contains synthetic witness stacks. Callers borrow an
/// `ArtifactVectorFile` only for the duration of package construction.
pub struct CanonicalBundleVectorFile {
    relative_path: PathBuf,
    contents: Zeroizing<Vec<u8>>,
}

impl CanonicalBundleVectorFile {
    /// Encodes and validates a real-material bundle vector under a safe package
    /// relative path.
    pub fn try_from_input(
        relative_path: &Path,
        input: BundleProvingVectorInput<'_>,
    ) -> Result<Self, ArtifactPackageError> {
        validate_relative_path(relative_path)?;
        if relative_path.extension() != Some(OsStr::new("pb")) {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ));
        }
        let contents = encode_bundle_proving_vector_set(input)?;
        let _validated = ArtifactVectorFile::try_new(relative_path, &contents)?;
        Ok(Self {
            relative_path: relative_path.to_path_buf(),
            contents,
        })
    }

    /// Borrows this zeroizing owner for package construction.
    pub fn as_artifact_vector_file(&self) -> Result<ArtifactVectorFile<'_>, ArtifactPackageError> {
        ArtifactVectorFile::try_new(&self.relative_path, &self.contents)
    }
}

impl NamedFile for ArtifactVectorFile<'_> {
    fn relative_path(&self) -> &Path {
        self.relative_path
    }

    fn contents(&self) -> &[u8] {
        self.contents
    }
}

/// Typed coordinates and compiler/backend versions for one package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactPackageCoordinates {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    toolchain: ArtifactToolchain,
}

impl ArtifactPackageCoordinates {
    /// Creates coordinates from closed protocol enums and validated versions.
    #[must_use]
    pub const fn new(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        toolchain: ArtifactToolchain,
    ) -> Self {
        Self::new_for_suite(
            bundle_kind,
            stage,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            toolchain,
        )
    }

    /// Creates coordinates for one exact proof suite.
    #[must_use]
    pub const fn new_for_suite(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        toolchain: ArtifactToolchain,
    ) -> Self {
        Self {
            bundle_kind,
            stage,
            credential_hash_algorithm,
            proof_suite,
            toolchain,
        }
    }

    /// Exact proof suite bound into the package manifest.
    #[must_use]
    pub const fn proof_suite(self) -> ZkProofSuite {
        self.proof_suite
    }
}

/// Borrowed artifact material used to construct one package.
#[derive(Clone, Copy)]
pub struct ArtifactPackageMaterial<'a> {
    source_digest: Digest32,
    compiled_program: &'a [u8],
    verification_key: &'a [u8],
    capability_registry: &'a CanonicalCapabilityRegistry,
    vectors: &'a [ArtifactVectorFile<'a>],
}

impl<'a> ArtifactPackageMaterial<'a> {
    /// Validates aggregate counts and byte bounds before package allocation.
    pub fn try_new(
        source_files: &'a [ArtifactSourceFile<'a>],
        compiled_program: &'a [u8],
        verification_key: &'a [u8],
        capability_registry: &'a CanonicalCapabilityRegistry,
        vectors: &'a [ArtifactVectorFile<'a>],
    ) -> Result<Self, ArtifactPackageError> {
        validate_file_count(vectors.len(), MAX_VECTOR_SET_DIGESTS)?;
        validate_nonempty_bounded(compiled_program, MAX_ACIR_BYTECODE_BYTES)?;
        validate_nonempty_bounded(verification_key, MAX_VERIFICATION_KEY_BYTES)?;
        let source_digest = noir_source_tree_sha256(source_files)?;
        validate_file_order(vectors, VECTOR_FILE_HASH_DOMAIN)?;
        Ok(Self {
            source_digest,
            compiled_program,
            verification_key,
            capability_registry,
            vectors,
        })
    }
}

/// Complete validated input for one deterministic package.
#[derive(Clone, Copy)]
pub struct ArtifactPackageInput<'a> {
    coordinates: ArtifactPackageCoordinates,
    material: ArtifactPackageMaterial<'a>,
}

impl<'a> ArtifactPackageInput<'a> {
    /// Combines typed package coordinates and bounded artifact material.
    #[must_use]
    pub const fn new(
        coordinates: ArtifactPackageCoordinates,
        material: ArtifactPackageMaterial<'a>,
    ) -> Self {
        Self {
            coordinates,
            material,
        }
    }
}

struct OwnedVectorFile {
    relative_path: PathBuf,
    contents: Zeroizing<Vec<u8>>,
}

struct PersistedVectorFile<'a> {
    relative_path: &'a Path,
    contents: &'a [u8],
}

impl NamedFile for PersistedVectorFile<'_> {
    fn relative_path(&self) -> &Path {
        self.relative_path
    }

    fn contents(&self) -> &[u8] {
        self.contents
    }
}

/// Fully built package whose manifest identity covers every retained input.
pub struct ArtifactPackage {
    coordinates: ArtifactPackageCoordinates,
    manifest: ProductionArtifactManifest,
    manifest_bytes: Vec<u8>,
    compiled_program: ArtifactBytes,
    verification_key: ArtifactBytes,
    vectors: Vec<OwnedVectorFile>,
}

mod sealed;
pub(crate) use sealed::copy_sealed_package_new;
pub use sealed::SealedArtifactPackage;

impl ArtifactPackage {
    /// Builds and seals a deterministic package entirely in memory.
    pub fn build(input: ArtifactPackageInput<'_>) -> Result<Self, ArtifactPackageError> {
        let coordinates = input.coordinates;
        let material = input.material;
        for vector in material.vectors {
            if vector.bundle_kind != coordinates.bundle_kind
                || vector.credential_hash_algorithm != coordinates.credential_hash_algorithm
                || vector.proof_suite != coordinates.proof_suite
            {
                return Err(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::PackageMismatch,
                ));
            }
        }
        let source_digest = material.source_digest;
        let vector_digests = material
            .vectors
            .iter()
            .map(|vector| hash_named_files(VECTOR_FILE_HASH_DOMAIN, core::slice::from_ref(vector)))
            .collect::<Result<Vec<_>, _>>()?;
        let circuit_ref = coordinates
            .bundle_kind
            .source_ref(coordinates.credential_hash_algorithm, coordinates.stage);
        let capabilities = circuit_ref_capabilities(circuit_ref)?;
        let digests = ArtifactDigests {
            noir_source_sha256: source_digest,
            bytecode_sha256: Digest32::sha256(material.compiled_program),
            verification_key_sha256: Digest32::sha256(material.verification_key),
            capability_registry_sha256: material.capability_registry.sha256(),
            vector_set_sha256: vector_digests,
        };
        let draft = ProductionArtifactManifestDraft::try_new(
            coordinates.bundle_kind,
            coordinates.stage,
            circuit_ref,
            coordinates.proof_suite,
            coordinates.toolchain,
            capabilities,
            digests,
        )?;
        let sealed = seal_artifact_manifest(draft)?;
        let (manifest, protobuf) = sealed.into_parts();
        let manifest_bytes = protobuf.encode_to_vec();
        validate_nonempty_bounded(&manifest_bytes, MANIFEST_MAX_BYTES)?;
        let compiled_program = ArtifactBytes::try_copy_from_slice(
            ArtifactKind::AcirBytecode,
            material.compiled_program,
        )?;
        let verification_key = ArtifactBytes::try_copy_from_slice(
            ArtifactKind::VerificationKey,
            material.verification_key,
        )?;
        let vectors = copy_vectors(material.vectors)?;

        Ok(Self {
            coordinates,
            manifest,
            manifest_bytes,
            compiled_program,
            verification_key,
            vectors,
        })
    }

    /// Returns the final runtime manifest and canonical package identity.
    #[must_use]
    pub const fn manifest(&self) -> &ProductionArtifactManifest {
        &self.manifest
    }

    /// Returns the canonical deterministic protobuf manifest bytes.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Derives this package's strict location beneath an artifact root.
    pub fn layout(
        &self,
        artifact_root: &Path,
    ) -> Result<ArtifactPackageLayout, ArtifactPackageError> {
        Ok(ArtifactPackageLayout::try_new(
            artifact_root,
            self.coordinates.credential_hash_algorithm,
            self.coordinates.bundle_kind,
            self.coordinates.stage,
            self.manifest.manifest_sha256(),
        )?)
    }

    /// Persists a new package without overwriting an existing directory.
    ///
    /// Payload files link into final paths with create-new semantics before
    /// `manifest.pb` becomes the consumer-visible readiness marker.
    pub fn write_new(&self, artifact_root: &Path) -> Result<(), ArtifactPackageError> {
        let layout = self.layout(artifact_root)?;
        if layout.directory().try_exists()? {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageAlreadyExists,
            ));
        }
        let parent = layout
            .directory()
            .parent()
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
        ensure_directory_chain(artifact_root, parent)?;
        fs::create_dir(layout.directory()).map_err(map_create_directory_error)?;
        fs::create_dir(layout.vectors())?;

        write_atomic_file(
            parent,
            layout.directory(),
            OsStr::new(ARTIFACT_PROGRAM_FILE_NAME),
            self.compiled_program.as_bytes(),
        )?;
        write_atomic_file(
            parent,
            layout.directory(),
            OsStr::new(ARTIFACT_VERIFICATION_KEY_FILE_NAME),
            self.verification_key.as_bytes(),
        )?;
        for vector in &self.vectors {
            let destination = layout.vectors().join(&vector.relative_path);
            let directory = destination.parent().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            ensure_directory_chain(&layout.vectors(), directory)?;
            let file_name = destination.file_name().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            write_atomic_file(parent, directory, file_name, &vector.contents)?;
        }
        sync_directory(&layout.vectors())?;
        write_atomic_file(
            parent,
            layout.directory(),
            OsStr::new(ARTIFACT_MANIFEST_FILE_NAME),
            &self.manifest_bytes,
        )?;
        sync_directory(layout.directory())?;
        Ok(())
    }

    /// Verifies one persisted package against the complete expected package.
    pub fn check(&self, artifact_root: &Path) -> Result<(), ArtifactPackageError> {
        let layout = self.layout(artifact_root)?;
        if !layout.directory().try_exists()? {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMissing,
            ));
        }
        validate_derived_directories(artifact_root, layout.directory())?;
        validate_top_level_entries(&layout)?;
        compare_file(&layout.manifest(), &self.manifest_bytes, MANIFEST_MAX_BYTES)?;
        compare_file(
            &layout.program(),
            self.compiled_program.as_bytes(),
            MAX_ACIR_BYTECODE_BYTES,
        )?;
        compare_file(
            &layout.verification_key(),
            self.verification_key.as_bytes(),
            MAX_VERIFICATION_KEY_BYTES,
        )?;
        validate_vector_tree(&layout.vectors(), &self.vectors)?;
        Ok(())
    }
}

mod io;

use io::validate_vector_tree;
pub(crate) use io::{
    collect_vector_paths, compare_file, copy_bounded_file_new, ensure_directory_chain,
    map_create_directory_error, read_bounded_file, sync_directory, write_atomic_file,
};
use io::{copy_vectors, package_mismatch_error, validate_aggregate_source_bytes};
use io::{validate_derived_directories, validate_file_count, validate_file_order};
use io::{validate_nonempty_bounded, validate_persisted_vectors, validate_top_level_entries};
