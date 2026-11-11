// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

use super::copy_or_verify_bounded_file;
use crate::{ArtifactPackageError, ArtifactPackageErrorReason};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn shared_common_credential_root_file_requires_exact_bytes() -> Result<(), ArtifactPackageError> {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-promotion-reuse-{}-{sequence}",
        std::process::id()
    ));
    let source_directory = root.join("source");
    let destination_root = root.join("destination");
    let destination_directory = destination_root.join("common-credential-root-v1");
    fs::create_dir(&root)?;
    fs::create_dir(&source_directory)?;
    fs::create_dir(&destination_root)?;
    let source = source_directory.join("program.json");
    let destination = destination_directory.join("program.json");
    fs::write(&source, b"pinned program")?;

    copy_or_verify_bounded_file(&destination_root, &source, &destination, 64)?;
    copy_or_verify_bounded_file(&destination_root, &source, &destination, 64)?;
    fs::write(&destination, b"different program")?;
    let reason = copy_or_verify_bounded_file(&destination_root, &source, &destination, 64)
        .err()
        .map(|error| error.reason());
    assert_eq!(reason, Some(ArtifactPackageErrorReason::PackageMismatch));

    fs::remove_dir_all(root)?;
    Ok(())
}
