// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    collect_vector_paths, copy_bounded_file_new, ensure_directory_chain, fs,
    map_create_directory_error, package_mismatch_error, read_bounded_file, sync_directory,
    validate_derived_directories, validate_persisted_vectors, validate_top_level_entries,
    ArtifactPackageError, ArtifactPackageErrorReason, ArtifactPackageLayout, Digest32, OsStr, Path,
    ProductionArtifactManifest, ReleaseArtifactPin, ARTIFACT_MANIFEST_FILE_NAME,
    ARTIFACT_PROGRAM_FILE_NAME, ARTIFACT_VERIFICATION_KEY_FILE_NAME, MANIFEST_MAX_BYTES,
    MAX_ACIR_BYTECODE_BYTES, MAX_VECTOR_FILE_BYTES, MAX_VECTOR_SET_DIGESTS,
    MAX_VERIFICATION_KEY_BYTES,
};

/// One persisted package admitted from its release-index manifest pin.
///
/// The loader retains only the validated public manifest. Artifact payloads
/// are bounded, hashed, and dropped through zeroizing owners before this value
/// is returned.
pub struct SealedArtifactPackage {
    manifest: ProductionArtifactManifest,
}

impl SealedArtifactPackage {
    /// Opens and validates one immutable package selected by an exact release
    /// pin. No path component comes from an untyped caller string.
    pub fn load_and_check(
        artifact_root: &Path,
        pin: ReleaseArtifactPin,
    ) -> Result<Self, ArtifactPackageError> {
        let circuit_ref = pin.circuit_ref();
        let layout = ArtifactPackageLayout::try_new(
            artifact_root,
            circuit_ref.credential_hash_algorithm,
            pin.bundle_kind(),
            pin.stage(),
            pin.manifest_sha256(),
        )?;
        validate_derived_directories(artifact_root, layout.directory())?;
        validate_top_level_entries(&layout)?;

        let manifest_bytes = read_bounded_file(&layout.manifest(), MANIFEST_MAX_BYTES)?;
        let manifest_digest = Digest32::sha256(&manifest_bytes);
        if manifest_digest.as_bytes() != pin.manifest_sha256().as_bytes() {
            return package_mismatch_error();
        }
        let manifest =
            reallyme_zk_proto_codec::artifact::decode_artifact_manifest(&manifest_bytes)?;
        if manifest.bundle_kind() != pin.bundle_kind()
            || manifest.stage() != pin.stage()
            || manifest.circuit_ref() != circuit_ref
            || manifest.manifest_sha256() != pin.manifest_sha256()
        {
            return package_mismatch_error();
        }

        let program = read_bounded_file(&layout.program(), MAX_ACIR_BYTECODE_BYTES)?;
        if !manifest.digests().bytecode_sha256.matches_sha256(&program) {
            return package_mismatch_error();
        }
        let verification_key =
            read_bounded_file(&layout.verification_key(), MAX_VERIFICATION_KEY_BYTES)?;
        if !manifest
            .digests()
            .verification_key_sha256
            .matches_sha256(&verification_key)
        {
            return package_mismatch_error();
        }
        validate_persisted_vectors(&layout, &manifest)?;
        Ok(Self { manifest })
    }

    /// Validated canonical manifest loaded from the package commit marker.
    #[must_use]
    pub const fn manifest(&self) -> &ProductionArtifactManifest {
        &self.manifest
    }
}

pub(crate) fn copy_sealed_package_new(
    source_root: &Path,
    destination_root: &Path,
    pin: ReleaseArtifactPin,
) -> Result<bool, ArtifactPackageError> {
    let _source = SealedArtifactPackage::load_and_check(source_root, pin)?;
    let circuit_ref = pin.circuit_ref();
    let source = ArtifactPackageLayout::try_new(
        source_root,
        circuit_ref.credential_hash_algorithm,
        pin.bundle_kind(),
        pin.stage(),
        pin.manifest_sha256(),
    )?;
    let destination = ArtifactPackageLayout::try_new(
        destination_root,
        circuit_ref.credential_hash_algorithm,
        pin.bundle_kind(),
        pin.stage(),
        pin.manifest_sha256(),
    )?;
    if destination.directory().try_exists()? {
        let _existing = SealedArtifactPackage::load_and_check(destination_root, pin)?;
        return Ok(false);
    }
    let parent = destination
        .directory()
        .parent()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
    ensure_directory_chain(destination_root, parent)?;
    fs::create_dir(destination.directory()).map_err(map_create_directory_error)?;
    let copy_result = (|| {
        fs::create_dir(destination.vectors()).map_err(map_create_directory_error)?;

        copy_bounded_file_new(
            parent,
            &source.program(),
            destination.directory(),
            OsStr::new(ARTIFACT_PROGRAM_FILE_NAME),
            MAX_ACIR_BYTECODE_BYTES,
        )?;
        copy_bounded_file_new(
            parent,
            &source.verification_key(),
            destination.directory(),
            OsStr::new(ARTIFACT_VERIFICATION_KEY_FILE_NAME),
            MAX_VERIFICATION_KEY_BYTES,
        )?;
        let mut vector_paths = Vec::new();
        vector_paths
            .try_reserve_exact(MAX_VECTOR_SET_DIGESTS)
            .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
        collect_vector_paths(&source.vectors(), &source.vectors(), &mut vector_paths)?;
        vector_paths.sort();
        for relative_path in vector_paths {
            let target = destination.vectors().join(&relative_path);
            let target_directory = target.parent().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            ensure_directory_chain(&destination.vectors(), target_directory)?;
            let file_name = target.file_name().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            copy_bounded_file_new(
                parent,
                &source.vectors().join(relative_path),
                target_directory,
                file_name,
                MAX_VECTOR_FILE_BYTES,
            )?;
        }
        sync_directory(&destination.vectors())?;
        copy_bounded_file_new(
            parent,
            &source.manifest(),
            destination.directory(),
            OsStr::new(ARTIFACT_MANIFEST_FILE_NAME),
            MANIFEST_MAX_BYTES,
        )?;
        sync_directory(destination.directory())?;
        let _copied = SealedArtifactPackage::load_and_check(destination_root, pin)?;
        Ok(())
    })();
    if let Err(error) = copy_result {
        fs::remove_dir_all(destination.directory())?;
        return Err(error);
    }
    Ok(true)
}
