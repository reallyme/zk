// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use reallyme_zk_artifacts::{ArtifactPackageLayout, ProductionArtifactManifest};
use zeroize::Zeroizing;

use crate::{
    hash::{hash_named_files, NamedFile},
    ArtifactPackageError, ArtifactPackageErrorReason,
};

const TEMPORARY_FILE_RETRY_LIMIT: u64 = 1024;
const STABILITY_READ_CHUNK_BYTES: usize = 64 * 1024;

static TEMPORARY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

use super::{
    ArtifactSourceFile, ArtifactVectorFile, OwnedVectorFile, PersistedVectorFile,
    MAX_NOIR_SOURCE_BYTES, MAX_VECTOR_FILE_BYTES, VECTOR_FILE_HASH_DOMAIN,
};

pub(crate) use tree::collect_vector_paths;
pub(super) use tree::{validate_top_level_entries, validate_vector_tree};

pub(super) fn validate_persisted_vectors(
    layout: &ArtifactPackageLayout,
    manifest: &ProductionArtifactManifest,
) -> Result<(), ArtifactPackageError> {
    let mut paths = Vec::new();
    paths
        .try_reserve_exact(manifest.digests().vector_set_sha256.len())
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
    collect_vector_paths(&layout.vectors(), &layout.vectors(), &mut paths)?;
    paths.sort();
    if paths.len() != manifest.digests().vector_set_sha256.len() {
        return package_mismatch_error();
    }
    for (path, expected_digest) in paths.iter().zip(&manifest.digests().vector_set_sha256) {
        let contents = read_bounded_file(&layout.vectors().join(path), MAX_VECTOR_FILE_BYTES)?;
        let persisted = PersistedVectorFile {
            relative_path: path,
            contents: &contents,
        };
        let actual_digest =
            hash_named_files(VECTOR_FILE_HASH_DOMAIN, core::slice::from_ref(&persisted))?;
        if actual_digest != *expected_digest {
            return package_mismatch_error();
        }
        let vector = ArtifactVectorFile::try_new(path, &contents)?;
        if vector.bundle_kind != manifest.bundle_kind()
            || vector.credential_hash_algorithm != manifest.circuit_ref().credential_hash_algorithm
            || vector.proof_suite != manifest.proof_suite()
        {
            return package_mismatch_error();
        }
    }
    Ok(())
}

pub(super) fn validate_derived_directories(
    root: &Path,
    directory: &Path,
) -> Result<(), ArtifactPackageError> {
    validate_directory(root)?;
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return package_mismatch_error();
        };
        current.push(component);
        validate_directory(&current)?;
    }
    Ok(())
}

fn validate_directory(path: &Path) -> Result<(), ArtifactPackageError> {
    let metadata = fs::symlink_metadata(path).map_err(map_missing_file_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return package_mismatch_error();
    }
    Ok(())
}

pub(super) fn package_mismatch_error<T>() -> Result<T, ArtifactPackageError> {
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))
}

pub(super) fn validate_file_count(
    count: usize,
    maximum: usize,
) -> Result<(), ArtifactPackageError> {
    if count == 0 {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::EmptyInput,
        ));
    }
    if count > maximum {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InputTooLarge,
        ));
    }
    Ok(())
}

pub(super) fn validate_nonempty_bounded(
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ArtifactPackageError> {
    if bytes.is_empty() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::EmptyInput,
        ));
    }
    if bytes.len() > maximum {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InputTooLarge,
        ));
    }
    Ok(())
}

pub(super) fn validate_aggregate_source_bytes(
    source_files: &[ArtifactSourceFile<'_>],
) -> Result<(), ArtifactPackageError> {
    let total = source_files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(file.contents.len())
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))
    })?;
    if total > MAX_NOIR_SOURCE_BYTES {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InputTooLarge,
        ));
    }
    Ok(())
}

pub(super) fn validate_file_order<T: NamedFile>(
    files: &[T],
    domain: &[u8],
) -> Result<(), ArtifactPackageError> {
    let _ = hash_named_files(domain, files)?;
    Ok(())
}

pub(super) fn copy_vectors(
    vectors: &[ArtifactVectorFile<'_>],
) -> Result<Vec<OwnedVectorFile>, ArtifactPackageError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(vectors.len())
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
    for vector in vectors {
        let mut contents = Zeroizing::new(Vec::new());
        contents
            .try_reserve_exact(vector.contents.len())
            .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
        contents.extend_from_slice(vector.contents);
        owned.push(OwnedVectorFile {
            relative_path: vector.relative_path.to_path_buf(),
            contents,
        });
    }
    Ok(owned)
}

pub(crate) fn map_create_directory_error(error: std::io::Error) -> ArtifactPackageError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        ArtifactPackageError::new(ArtifactPackageErrorReason::PackageAlreadyExists)
    } else {
        ArtifactPackageError::from(error)
    }
}

pub(crate) fn write_atomic_file(
    temporary_parent: &Path,
    directory: &Path,
    file_name: &OsStr,
    bytes: &[u8],
) -> Result<(), ArtifactPackageError> {
    validate_directory(temporary_parent)?;
    validate_directory(directory)?;
    let final_path = directory.join(file_name);
    for _ in 0..TEMPORARY_FILE_RETRY_LIMIT {
        let temporary_path = next_temporary_path(temporary_parent, file_name)?;
        match create_and_link_atomic_file(&temporary_path, &final_path, bytes) {
            Ok(()) => {
                sync_directory(directory)?;
                sync_directory(temporary_parent)?;
                return Ok(());
            }
            Err(AtomicWriteError::TemporaryNameCollision) => continue,
            Err(AtomicWriteError::Package(error)) => return Err(error),
        }
    }
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::Filesystem(std::io::ErrorKind::AlreadyExists),
    ))
}

pub(crate) fn copy_bounded_file_new(
    temporary_parent: &Path,
    source: &Path,
    destination_directory: &Path,
    destination_name: &OsStr,
    maximum: usize,
) -> Result<(), ArtifactPackageError> {
    let bytes = read_bounded_file(source, maximum)?;
    write_atomic_file(
        temporary_parent,
        destination_directory,
        destination_name,
        &bytes,
    )
}

enum AtomicWriteError {
    TemporaryNameCollision,
    Package(ArtifactPackageError),
}

fn create_and_link_atomic_file(
    temporary_path: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), AtomicWriteError> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AtomicWriteError::TemporaryNameCollision);
        }
        Err(error) => return Err(AtomicWriteError::Package(ArtifactPackageError::from(error))),
    };
    let write_result = (|| -> Result<(), ArtifactPackageError> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(temporary_path, final_path).map_err(map_create_file_error)?;
        fs::remove_file(temporary_path)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _cleanup_result = fs::remove_file(temporary_path);
        return Err(AtomicWriteError::Package(error));
    }
    Ok(())
}

fn next_temporary_path(
    temporary_parent: &Path,
    file_name: &OsStr,
) -> Result<PathBuf, ArtifactPackageError> {
    let counter = TEMPORARY_FILE_COUNTER
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;
    let mut name = OsString::from(".reallyme-zk-artifact-package.");
    name.push(file_name);
    name.push(".");
    name.push(std::process::id().to_string());
    name.push(".");
    name.push(counter.to_string());
    name.push(".partial");
    Ok(temporary_parent.join(name))
}

fn map_create_file_error(error: std::io::Error) -> ArtifactPackageError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        ArtifactPackageError::new(ArtifactPackageErrorReason::PackageAlreadyExists)
    } else {
        ArtifactPackageError::from(error)
    }
}

pub(crate) fn ensure_directory_chain(
    root: &Path,
    directory: &Path,
) -> Result<(), ArtifactPackageError> {
    validate_directory(root)?;
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InvalidRelativePath))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ));
        };
        let parent = current.clone();
        current.push(component);
        if current.try_exists()? {
            validate_directory(&current)?;
        } else {
            match fs::create_dir(&current) {
                Ok(()) => sync_directory(&parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    validate_directory(&current)?;
                }
                Err(error) => return Err(ArtifactPackageError::from(error)),
            }
        }
    }
    Ok(())
}

pub(crate) fn sync_directory(directory: &Path) -> Result<(), ArtifactPackageError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

pub(crate) fn compare_file(
    path: &Path,
    expected: &[u8],
    maximum: usize,
) -> Result<(), ArtifactPackageError> {
    let actual = read_bounded_file(path, maximum)?;
    if actual.as_slice() != expected {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(())
}

pub(crate) fn read_bounded_file(
    path: &Path,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, ArtifactPackageError> {
    let path_metadata = fs::symlink_metadata(path).map_err(map_missing_file_error)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    let mut file = open_read_only_no_follow(path).map_err(map_missing_file_error)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || !same_file(&path_metadata, &metadata) {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    let reported_length = usize::try_from(metadata.len())
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;
    if reported_length == 0 || reported_length > maximum {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    let bytes = read_bounded_file_snapshot(&mut file, reported_length)?;
    file.seek(SeekFrom::Start(0))?;
    verify_file_matches_snapshot(&mut file, &bytes)?;
    let final_metadata = file.metadata()?;
    if !final_metadata.is_file()
        || !same_file(&path_metadata, &final_metadata)
        || final_metadata.len() != metadata.len()
    {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(bytes)
}

fn read_bounded_file_snapshot(
    file: &mut File,
    reported_length: usize,
) -> Result<Zeroizing<Vec<u8>>, ArtifactPackageError> {
    // Package verification can read synthetic witness-bearing vector sets.
    // Zeroizing every bounded payload avoids a separate sensitive-file path
    // whose classification could drift as the package format evolves.
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(reported_length)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
    bytes.resize(reported_length, 0);
    file.read_exact(&mut bytes).map_err(map_read_exact_error)?;
    if read_excess_byte(file)? {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(bytes)
}

fn verify_file_matches_snapshot(
    file: &mut File,
    expected: &[u8],
) -> Result<(), ArtifactPackageError> {
    let mut scratch = Zeroizing::new(Vec::new());
    scratch
        .try_reserve_exact(STABILITY_READ_CHUNK_BYTES)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
    let mut offset = 0_usize;
    while offset < expected.len() {
        let remaining = expected
            .len()
            .checked_sub(offset)
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
        let chunk_length = remaining.min(STABILITY_READ_CHUNK_BYTES);
        scratch.resize(chunk_length, 0);
        file.read_exact(&mut scratch)
            .map_err(map_read_exact_error)?;
        let end = offset
            .checked_add(chunk_length)
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
        if &expected[offset..end] != scratch.as_slice() {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMismatch,
            ));
        }
        scratch.as_mut_slice().fill(0);
        offset = end;
    }
    if read_excess_byte(file)? {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(())
}

fn read_excess_byte(file: &mut File) -> Result<bool, ArtifactPackageError> {
    let mut extra = [0_u8; 1];
    let read_result = file.read(&mut extra);
    extra.fill(0);
    let count = read_result?;
    Ok(count != 0)
}

fn map_read_exact_error(error: std::io::Error) -> ArtifactPackageError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch)
    } else {
        ArtifactPackageError::from(error)
    }
}

fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(unix)]
fn same_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(_before: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    // A metadata-only comparison cannot establish object identity here.
    // Keep the path admission closed until a platform-specific handle check exists.
    false
}

fn map_missing_file_error(error: std::io::Error) -> ArtifactPackageError {
    if error.kind() == std::io::ErrorKind::NotFound {
        ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMissing)
    } else {
        ArtifactPackageError::from(error)
    }
}

mod tree;

#[cfg(test)]
mod tests;
