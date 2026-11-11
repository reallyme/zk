// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admit a sealed release and require one reviewed canonical index digest.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifact_package::{
    ArtifactPackageError, ArtifactPackageErrorReason, SealedRelease,
};
use reallyme_zk_artifacts::{ArtifactVersion, Digest32};
use reallyme_zk_proto_codec::{
    capability_registry::build_capability_registry, release::ReleaseIndex,
};

const SHA256_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = SHA256_BYTES * 2;
const ATTESTED_NARGO_VERSION: &[u8] = b"1.0.0";
const ATTESTED_BARRETENBERG_VERSION: &[u8] = b"6.0.0";

fn main() -> Result<(), ArtifactPackageError> {
    let arguments = parse_arguments(std::env::args_os())?;
    // Attestation covers every byte shipped in the candidate, including files
    // outside the index graph. The runtime loader is intentionally less strict.
    let release = SealedRelease::load_candidate_and_check(
        &arguments.artifact_root,
        arguments.release_version,
    )?;
    if release.index_sha256() != arguments.expected_index_sha256 {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    validate_attested_release_index(release.index())?;
    Ok(())
}

struct Arguments {
    artifact_root: PathBuf,
    release_version: ArtifactVersion,
    expected_index_sha256: Digest32,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, ArtifactPackageError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let artifact_root = next_argument(&mut arguments)?;
    let release_version = next_argument(&mut arguments)?;
    let expected_index_sha256 = next_argument(&mut arguments)?;
    if arguments.next().is_some() {
        return invalid_arguments();
    }

    let artifact_root = PathBuf::from(artifact_root);
    let release_version = release_version.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    let expected_index_sha256 = expected_index_sha256
        .to_str()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ))?;

    Ok(Arguments {
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

fn validate_attested_release_index(index: &ReleaseIndex) -> Result<(), ArtifactPackageError> {
    let toolchain = index.toolchain();
    if toolchain.nargo_version().as_bytes() != ATTESTED_NARGO_VERSION
        || toolchain.barretenberg_version().as_bytes() != ATTESTED_BARRETENBERG_VERSION
    {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }

    let registry = build_capability_registry()?;
    if index.capability_registry_sha256() != registry.sha256() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "check-release-index-attestation/tests.rs"]
mod tests;
