// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Check a public mobile artifact pack without requiring private test vectors.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifact_package::{
    validate_mobile_public_runtime, ArtifactPackageError, ArtifactPackageErrorReason,
};
use reallyme_zk_artifacts::ArtifactVersion;

fn main() -> Result<(), ArtifactPackageError> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    let root = PathBuf::from(next_argument(&mut arguments)?);
    let version = next_argument(&mut arguments)?;
    let version = version.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    if arguments.next().is_some() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ));
    }
    validate_mobile_public_runtime(&root, ArtifactVersion::try_from_token(version)?)
}

fn next_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, ArtifactPackageError> {
    arguments.next().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))
}
