// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seal or refresh a reviewed local release candidate with persona-credential-evidence pins.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_artifact_package::{
    seal_persona_credential_evidence_candidate, ArtifactPackageError, ArtifactPackageErrorReason,
};
use reallyme_zk_artifacts::{ArtifactVersion, Digest32};

fn main() -> Result<(), ArtifactPackageError> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    let root = PathBuf::from(next_argument(&mut arguments)?);
    let version = next_argument(&mut arguments)?;
    let version = version.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    let base_index_sha256 = parse_sha256(next_argument(&mut arguments)?)?;
    let source_lock_sha256 = parse_sha256(next_argument(&mut arguments)?)?;
    if arguments.next().is_some() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ));
    }
    let release_version = ArtifactVersion::try_from_token(version)?;
    let _digest = seal_persona_credential_evidence_candidate(
        &root,
        release_version,
        base_index_sha256,
        source_lock_sha256,
    )?;
    Ok(())
}

fn next_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, ArtifactPackageError> {
    arguments.next().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))
}

fn parse_sha256(value: OsString) -> Result<Digest32, ArtifactPackageError> {
    let value = value.to_str().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidArguments,
    ))?;
    if value.len() != 64 {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ));
    }
    let mut bytes = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ));
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        *bytes.get_mut(index).ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ))? = (high << 4) | low;
    }
    Ok(Digest32::from_bytes(bytes))
}

fn nibble(value: u8) -> Result<u8, ArtifactPackageError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        )),
    }
}
