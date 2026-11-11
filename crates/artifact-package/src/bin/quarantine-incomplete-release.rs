// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Move one incomplete promoted release into recoverable quarantine.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifact_package::{
    quarantine_incomplete_release, ArtifactPackageError, ArtifactPackageErrorReason,
};
use reallyme_zk_artifacts::ArtifactVersion;

fn main() -> Result<(), ArtifactPackageError> {
    let arguments = parse_arguments(std::env::args_os())?;
    let _summary =
        quarantine_incomplete_release(&arguments.artifact_root, arguments.release_version)?;
    Ok(())
}

struct Arguments {
    artifact_root: PathBuf,
    release_version: ArtifactVersion,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, ArtifactPackageError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let artifact_root = next_argument(&mut arguments)?;
    let release_version = next_argument(&mut arguments)?;
    if arguments.next().is_some() {
        return invalid_arguments();
    }
    let release_version = release_version.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    Ok(Arguments {
        artifact_root: PathBuf::from(artifact_root),
        release_version: ArtifactVersion::try_from_token(release_version)?,
    })
}

fn next_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, ArtifactPackageError> {
    arguments.next().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))
}

fn invalid_arguments<T>() -> Result<T, ArtifactPackageError> {
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))
}

#[cfg(test)]
#[path = "quarantine-incomplete-release/tests.rs"]
mod tests;
