// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit a host-independent representation of one pinned modern Noir program.

use std::io::{self, Read, Write};

use reallyme_zk_release_process::{
    normalize_modern_compiled_program_artifact, ReleaseProcessError, ReleaseProcessErrorReason,
    MAX_COMPILED_PROGRAM_ARTIFACT_BYTES,
};

fn main() -> Result<(), ReleaseProcessError> {
    if std::env::args_os().count() != 1 {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        ));
    }
    let maximum = u64::try_from(MAX_COMPILED_PROGRAM_ARTIFACT_BYTES).map_err(|_| {
        ReleaseProcessError::new(ReleaseProcessErrorReason::MalformedCompiledArtifact)
    })?;
    let limit = maximum.checked_add(1).ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::MalformedCompiledArtifact,
    ))?;
    let mut bytes = Vec::new();
    io::stdin().take(limit).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_COMPILED_PROGRAM_ARTIFACT_BYTES {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::MalformedCompiledArtifact,
        ));
    }
    let normalized = normalize_modern_compiled_program_artifact(&bytes)?;
    io::stdout().write_all(&normalized)?;
    Ok(())
}
