// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{collections::BTreeSet, fs, path::PathBuf};

use super::{
    expected_directories, validate_candidate_directory, ArtifactPackageError,
    ArtifactPackageErrorReason,
};

fn temporary_root() -> Result<PathBuf, ArtifactPackageError> {
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-exact-candidate-tree-{}",
        std::process::id()
    ));
    if root.try_exists()? {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir(&root)?;
    Ok(root)
}

#[test]
fn exact_candidate_tree_rejects_extra_files_and_empty_directories(
) -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let expected_path = PathBuf::from("v1/release/index.pb");
    let expected_absolute = root.join(&expected_path);
    let expected_parent = expected_absolute.parent().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidRelativePath,
    ))?;
    fs::create_dir_all(expected_parent)?;
    fs::write(&expected_absolute, b"index")?;
    let expected_files = BTreeSet::from([expected_path]);
    let expected_directories = expected_directories(&root, &expected_files)?;
    let mut observed = 0;
    validate_candidate_directory(
        &root,
        &root,
        &expected_files,
        &expected_directories,
        &mut observed,
    )?;

    fs::write(root.join("unexpected.bin"), b"unexpected")?;
    let mut observed = 0;
    let file_reason = validate_candidate_directory(
        &root,
        &root,
        &expected_files,
        &expected_directories,
        &mut observed,
    )
    .err()
    .map(|error| error.reason());
    assert_eq!(
        file_reason,
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::remove_file(root.join("unexpected.bin"))?;

    fs::create_dir(root.join("unexpected-directory"))?;
    let mut observed = 0;
    let directory_reason = validate_candidate_directory(
        &root,
        &root,
        &expected_files,
        &expected_directories,
        &mut observed,
    )
    .err()
    .map(|error| error.reason());
    assert_eq!(
        directory_reason,
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
