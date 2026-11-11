// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Check that a sealed release candidate matches the checked-out source tree.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifacts::ArtifactVersion;
use reallyme_zk_release_assembly::{
    validate_release_source_attestation, ReleaseAssemblyError, ReleaseAssemblyErrorReason,
};

const ARGUMENT_COUNT: usize = 3;

fn main() -> Result<(), ReleaseAssemblyError> {
    let arguments = parse_arguments(std::env::args_os())?;
    validate_release_source_attestation(
        &arguments.workspace_root,
        &arguments.release_root,
        arguments.release_version,
    )
}

struct Arguments {
    workspace_root: PathBuf,
    release_root: PathBuf,
    release_version: ArtifactVersion,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, ReleaseAssemblyError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let mut values = Vec::new();
    values
        .try_reserve_exact(ARGUMENT_COUNT)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    for argument in arguments {
        if values.len() >= ARGUMENT_COUNT {
            return invalid_arguments();
        }
        values.push(argument);
    }
    if values.len() != ARGUMENT_COUNT {
        return invalid_arguments();
    }

    let mut values = values.into_iter();
    let workspace_root = PathBuf::from(next_argument(&mut values)?);
    let release_root = PathBuf::from(next_argument(&mut values)?);
    let release_version = next_argument(&mut values)?;
    let release_version = release_version.to_str().ok_or(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidArguments,
    ))?;

    Ok(Arguments {
        workspace_root,
        release_root,
        release_version: ArtifactVersion::try_from_token(release_version)?,
    })
}

fn next_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, ReleaseAssemblyError> {
    arguments.next().ok_or(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidArguments,
    ))
}

fn invalid_arguments<T>() -> Result<T, ReleaseAssemblyError> {
    Err(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidArguments,
    ))
}

#[cfg(test)]
#[path = "check-release-source-attestation/tests.rs"]
mod tests;
