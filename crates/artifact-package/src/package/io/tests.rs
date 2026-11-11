// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    ffi::OsStr,
    fs,
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use crate::{ArtifactPackageError, ArtifactPackageErrorReason};

use super::{
    collect_vector_paths, map_missing_file_error, open_read_only_no_follow, read_bounded_file,
    read_bounded_file_snapshot, same_file, tree::MAX_VECTOR_DIRECTORY_DEPTH,
    verify_file_matches_snapshot, write_atomic_file,
};

fn temporary_root(label: &str) -> Result<PathBuf, ArtifactPackageError> {
    let counter = super::TEMPORARY_FILE_COUNTER
        .try_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |value| value.checked_add(1),
        )
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-artifact-package-{label}-{}-{counter}",
        std::process::id()
    ));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ArtifactPackageError::from(error)),
    }
    fs::create_dir(&root)?;
    Ok(root)
}

fn entry_names(directory: &Path) -> Result<Vec<String>, ArtifactPackageError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn read_bounded_file_with_after_first_read<F>(
    path: &Path,
    maximum: usize,
    after_first_read: F,
) -> Result<(), ArtifactPackageError>
where
    F: FnOnce() -> Result<(), ArtifactPackageError>,
{
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
    after_first_read()?;
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
    Ok(())
}

#[test]
fn read_bounded_file_returns_stable_snapshot() -> Result<(), ArtifactPackageError> {
    let root = temporary_root("stable-read")?;
    let payload = root.join("payload");
    fs::write(&payload, b"artifact bytes")?;

    let actual = read_bounded_file(&payload, 64)?;

    assert_eq!(actual.as_slice(), b"artifact bytes");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn read_bounded_file_rejects_in_place_mutation_between_reads() -> Result<(), ArtifactPackageError> {
    let root = temporary_root("mutated-read")?;
    let payload = root.join("payload");
    fs::write(&payload, b"artifact bytes")?;

    let result = read_bounded_file_with_after_first_read(&payload, 64, || {
        fs::write(&payload, b"tampered bytes")?;
        Ok(())
    });

    assert_eq!(
        result.map_err(|error| error.reason()),
        Err(ArtifactPackageErrorReason::PackageMismatch)
    );
    assert_eq!(fs::read(&payload)?, b"tampered bytes");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn read_bounded_file_rejects_in_place_extension_between_reads() -> Result<(), ArtifactPackageError>
{
    let root = temporary_root("extended-read")?;
    let payload = root.join("payload");
    fs::write(&payload, b"artifact bytes")?;

    let result = read_bounded_file_with_after_first_read(&payload, 64, || {
        fs::write(&payload, b"artifact bytes extended")?;
        Ok(())
    });

    assert_eq!(
        result.map_err(|error| error.reason()),
        Err(ArtifactPackageErrorReason::PackageMismatch)
    );
    assert_eq!(fs::read(&payload)?, b"artifact bytes extended");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn atomic_write_does_not_remove_foreign_deterministic_partial() -> Result<(), ArtifactPackageError>
{
    let root = temporary_root("foreign-partial")?;
    let destination = root.join("package");
    fs::create_dir(&destination)?;
    let foreign_partial = destination.join("payload.partial");
    fs::write(&foreign_partial, b"foreign")?;

    write_atomic_file(&root, &destination, OsStr::new("payload"), b"owned")?;

    assert_eq!(fs::read(destination.join("payload"))?, b"owned");
    assert_eq!(fs::read(foreign_partial)?, b"foreign");
    assert_eq!(
        entry_names(&destination)?,
        vec!["payload".to_owned(), "payload.partial".to_owned()]
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn concurrent_atomic_writes_preserve_create_new_final_semantics() -> Result<(), ArtifactPackageError>
{
    let root = temporary_root("concurrent")?;
    let destination = root.join("package");
    fs::create_dir(&destination)?;
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for bytes in [b"first".as_slice(), b"second".as_slice()] {
        let root = root.clone();
        let destination = destination.clone();
        let barrier = Arc::clone(&barrier);
        let owned_bytes = bytes.to_vec();
        handles.push(thread::spawn(move || {
            barrier.wait();
            write_atomic_file(&root, &destination, OsStr::new("payload"), &owned_bytes)
                .map_err(|error| error.reason())
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.join().map_err(|_| {
            ArtifactPackageError::new(ArtifactPackageErrorReason::Filesystem(
                std::io::ErrorKind::Other,
            ))
        })?);
    }
    results.sort_by_key(|result| match result {
        Ok(()) => 0_u8,
        Err(reason) if *reason == ArtifactPackageErrorReason::PackageAlreadyExists => 1_u8,
        Err(_) => 2_u8,
    });

    assert_eq!(results[0], Ok(()));
    assert_eq!(
        results[1],
        Err(ArtifactPackageErrorReason::PackageAlreadyExists)
    );
    assert_eq!(entry_names(&destination)?, vec!["payload".to_owned()]);
    assert!(matches!(
        fs::read(destination.join("payload"))?.as_slice(),
        b"first" | b"second"
    ));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn interrupted_out_of_tree_temporary_file_does_not_pollute_destination(
) -> Result<(), ArtifactPackageError> {
    let root = temporary_root("interrupted")?;
    let destination = root.join("package");
    fs::create_dir(&destination)?;

    write_atomic_file(&root, &destination, OsStr::new("payload"), b"owned")?;
    fs::write(
        root.join(".reallyme-zk-artifact-package.payload.interrupted.partial"),
        b"orphan",
    )?;

    assert_eq!(entry_names(&destination)?, vec!["payload".to_owned()]);
    assert_eq!(fs::read(destination.join("payload"))?, b"owned");
    fs::remove_dir_all(root)?;
    Ok(())
}

fn nested_vector_tree(root: &Path, directories: usize) -> Result<(), ArtifactPackageError> {
    let mut directory = root.to_path_buf();
    for _ in 0..directories {
        directory.push("d");
    }
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("vector.pb"), b"vector")?;
    Ok(())
}

#[test]
fn vector_tree_at_maximum_directory_depth_is_collected() -> Result<(), ArtifactPackageError> {
    let root = temporary_root("vector-depth-maximum")?;
    nested_vector_tree(&root, MAX_VECTOR_DIRECTORY_DEPTH)?;

    let mut paths = Vec::new();
    collect_vector_paths(&root, &root, &mut paths)?;

    assert_eq!(paths.len(), 1);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn vector_tree_beyond_maximum_directory_depth_is_rejected() -> Result<(), ArtifactPackageError> {
    let root = temporary_root("vector-depth-exceeded")?;
    let directories =
        MAX_VECTOR_DIRECTORY_DEPTH
            .checked_add(1)
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
    nested_vector_tree(&root, directories)?;

    let mut paths = Vec::new();
    let result = collect_vector_paths(&root, &root, &mut paths);

    assert_eq!(
        result.map_err(|error| error.reason()),
        Err(ArtifactPackageErrorReason::PackageMismatch)
    );
    assert!(paths.is_empty());
    fs::remove_dir_all(root)?;
    Ok(())
}
