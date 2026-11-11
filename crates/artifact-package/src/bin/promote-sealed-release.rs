// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Promote one checked release into an existing artifact root.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifact_package::{
    promote_sealed_release_new, ArtifactPackageError, ArtifactPackageErrorReason,
};
use reallyme_zk_artifacts::{ArtifactVersion, Digest32};

const REQUIRED_ARGUMENT_COUNT: usize = 4;
const SHA256_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = SHA256_BYTES * 2;

fn main() -> Result<(), ArtifactPackageError> {
    let arguments = parse_arguments(std::env::args_os())?;
    let _summary = promote_sealed_release_new(
        &arguments.staging_root,
        &arguments.artifact_root,
        arguments.release_version,
        arguments.expected_index_sha256,
    )?;
    Ok(())
}

struct Arguments {
    staging_root: PathBuf,
    artifact_root: PathBuf,
    release_version: ArtifactVersion,
    expected_index_sha256: Digest32,
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
    let staging_root = PathBuf::from(next_argument(&mut values)?);
    let artifact_root = PathBuf::from(next_argument(&mut values)?);
    let release_version = next_argument(&mut values)?;
    let release_version = release_version.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    let expected_index_sha256 = next_argument(&mut values)?;
    let expected_index_sha256 = expected_index_sha256
        .to_str()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ))?;
    Ok(Arguments {
        staging_root,
        artifact_root,
        release_version: ArtifactVersion::try_from_token(release_version)?,
        expected_index_sha256: parse_sha256(expected_index_sha256)?,
    })
}

fn parse_sha256(value: &str) -> Result<Digest32, ArtifactPackageError> {
    if value.len() != SHA256_HEX_BYTES {
        return invalid_arguments();
    }
    let decoded = reallyme_codec::hex::lower_hex_to_bytes(value)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InvalidArguments))?;
    let decoded = <[u8; SHA256_BYTES]>::try_from(decoded)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InvalidArguments))?;
    Ok(Digest32::from_bytes(decoded))
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
#[path = "promote-sealed-release/tests.rs"]
mod tests;
