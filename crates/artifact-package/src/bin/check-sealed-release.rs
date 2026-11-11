// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate a complete sealed release without proving or mutating it.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifact_package::{
    ArtifactPackageError, ArtifactPackageErrorReason, SealedRelease,
};
use reallyme_zk_artifacts::ArtifactVersion;

const REQUIRED_ARGUMENT_COUNT: usize = 2;

fn main() -> Result<(), ArtifactPackageError> {
    let arguments = parse_arguments(std::env::args_os())?;
    let _release = SealedRelease::load_and_check(&arguments.root, arguments.release_version)?;
    Ok(())
}

struct Arguments {
    root: PathBuf,
    release_version: ArtifactVersion,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, ArtifactPackageError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let mut values = Vec::new();
    values
        .try_reserve_exact(REQUIRED_ARGUMENT_COUNT)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;
    for _ in 0..REQUIRED_ARGUMENT_COUNT {
        values.push(next_argument(&mut arguments)?);
    }
    if arguments.next().is_some() {
        return invalid_arguments();
    }
    let mut values = values.into_iter();
    let root = PathBuf::from(next_argument(&mut values)?);
    let release_version = next_argument(&mut values)?;
    let release_version = release_version.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    Ok(Arguments {
        root,
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
#[path = "check-sealed-release/tests.rs"]
mod tests;
