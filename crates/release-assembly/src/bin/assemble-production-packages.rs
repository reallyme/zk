// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Assemble all production packages from retained proof outputs.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifacts::ArtifactVersion;
use reallyme_zk_release_assembly::{
    assemble_production_packages, ProductionAssemblyPaths, ReleaseAssemblyError,
    ReleaseAssemblyErrorReason,
};
use reallyme_zk_release_process::{
    PinnedReleaseProcess, ReleaseToolDigests, ReleaseToolPaths, ReleaseToolchainProfile,
    SystemReleaseProcessRunner,
};

const REQUIRED_ARGUMENT_COUNT: usize = 9;
const OPTIONAL_PROFILE_ARGUMENT_COUNT: usize = 10;
const MODERN_CANDIDATE_FLAG: &str = "--modern-candidate";

fn main() -> Result<(), ReleaseAssemblyError> {
    let arguments = parse_arguments(std::env::args_os())?;
    let tools = ReleaseToolPaths::try_new(
        &arguments.nargo,
        &arguments.barretenberg,
        arguments.tool_digests,
    )
    .map_err(ReleaseAssemblyError::from)?;
    let process = PinnedReleaseProcess::try_new_for_profile(
        SystemReleaseProcessRunner,
        tools,
        arguments.profile,
    )
    .map_err(ReleaseAssemblyError::from)?;
    let paths = ProductionAssemblyPaths::try_new(
        &arguments.workspace_root,
        &arguments.proof_matrix_root,
        &arguments.crs,
        &arguments.output_root,
        arguments.release_version,
    )?;
    let _summary = assemble_production_packages(&process, paths)?;
    Ok(())
}

struct Arguments {
    nargo: PathBuf,
    barretenberg: PathBuf,
    crs: PathBuf,
    workspace_root: PathBuf,
    proof_matrix_root: PathBuf,
    output_root: PathBuf,
    release_version: ArtifactVersion,
    profile: ReleaseToolchainProfile,
    tool_digests: ReleaseToolDigests,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, ReleaseAssemblyError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let mut values = Vec::new();
    values
        .try_reserve_exact(OPTIONAL_PROFILE_ARGUMENT_COUNT)
        .map_err(|_| ReleaseAssemblyError::new(ReleaseAssemblyErrorReason::LengthOverflow))?;
    for argument in arguments {
        if values.len() >= OPTIONAL_PROFILE_ARGUMENT_COUNT {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidArguments,
            ));
        }
        values.push(argument);
    }
    if values.len() != REQUIRED_ARGUMENT_COUNT && values.len() != OPTIONAL_PROFILE_ARGUMENT_COUNT {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidArguments,
        ));
    }
    let mut values = values.into_iter();
    let nargo = PathBuf::from(next_argument(&mut values)?);
    let nargo_sha256 = parse_sha256(next_argument(&mut values)?)?;
    let barretenberg = PathBuf::from(next_argument(&mut values)?);
    let barretenberg_sha256 = parse_sha256(next_argument(&mut values)?)?;
    let crs = PathBuf::from(next_argument(&mut values)?);
    let workspace_root = PathBuf::from(next_argument(&mut values)?);
    let proof_matrix_root = PathBuf::from(next_argument(&mut values)?);
    let output_root = PathBuf::from(next_argument(&mut values)?);
    let release_version = next_argument(&mut values)?;
    let release_version = release_version.to_str().ok_or(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidArguments,
    ))?;
    let profile = match values.next() {
        Some(flag) if flag.to_str() == Some(MODERN_CANDIDATE_FLAG) => {
            ReleaseToolchainProfile::ModernCandidate
        }
        Some(_) => {
            return Err(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidArguments,
            ));
        }
        None => ReleaseToolchainProfile::ModernCandidate,
    };
    Ok(Arguments {
        nargo,
        barretenberg,
        crs,
        workspace_root,
        proof_matrix_root,
        output_root,
        profile,
        release_version: ArtifactVersion::try_from_token(release_version)
            .map_err(ReleaseAssemblyError::from)?,
        tool_digests: ReleaseToolDigests::new(nargo_sha256, barretenberg_sha256),
    })
}

fn parse_sha256(value: OsString) -> Result<[u8; 32], ReleaseAssemblyError> {
    let value = value.to_str().ok_or(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidArguments,
    ))?;
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidArguments,
        ));
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidArguments,
        ));
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        digest[index] = high
            .checked_mul(16)
            .and_then(|value| value.checked_add(low))
            .ok_or(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidArguments,
            ))?;
    }
    Ok(digest)
}

fn decode_hex_nibble(value: u8) -> Result<u8, ReleaseAssemblyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidArguments,
        )),
    }
}

fn next_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, ReleaseAssemblyError> {
    arguments.next().ok_or(ReleaseAssemblyError::new(
        ReleaseAssemblyErrorReason::InvalidArguments,
    ))
}

#[cfg(test)]
#[path = "assemble-production-packages/tests.rs"]
mod tests;
