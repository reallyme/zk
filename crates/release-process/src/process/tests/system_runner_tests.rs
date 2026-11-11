// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    artifact_version, fs, Fixture, PinnedReleaseProcess, RecordingRunner, ReleaseProcessError,
    ReleaseProcessErrorReason, ReleaseTool, ReleaseToolPaths, SystemReleaseProcessRunner,
};

#[test]
fn version_mismatch_fails_closed_with_no_tool_output() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let reason = PinnedReleaseProcess::try_new(
        RecordingRunner::mismatching(ReleaseTool::Barretenberg),
        fixture.paths()?,
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ReleaseProcessErrorReason::VersionMismatch(
            ReleaseTool::Barretenberg
        ))
    );
    fixture.cleanup()
}

#[test]
fn release_commands_reject_relative_paths() -> Result<(), ReleaseProcessError> {
    let fixture = Fixture::create()?;
    let process = PinnedReleaseProcess::try_new(RecordingRunner::matching(), fixture.paths()?)?;

    let reason = process
        .compile_command(
            std::path::Path::new("relative-circuit"),
            artifact_version("circuit_name")?,
        )
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ReleaseProcessErrorReason::InvalidPath));
    fixture.cleanup()
}

#[cfg(unix)]
#[test]
fn symlinked_tool_path_is_rejected_before_attestation() -> Result<(), ReleaseProcessError> {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::create()?;
    let symlinked = fixture.root.join("nargo-link");
    symlink(&fixture.nargo, &symlinked)?;
    let reason =
        ReleaseToolPaths::try_new(&symlinked, &fixture.barretenberg, fixture.tool_digests()?)
            .err()
            .map(|error| error.reason());

    assert_eq!(reason, Some(ReleaseProcessErrorReason::InvalidPath));
    fixture.cleanup()
}

#[cfg(unix)]
#[test]
fn system_runner_attests_bounded_tool_output() -> Result<(), ReleaseProcessError> {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::create()?;
    fs::write(
        &fixture.nargo,
        b"#!/bin/sh\nprintf 'nargo version = 1.0.0\\nnoirc version = 1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c\\n'\n",
    )?;
    fs::write(&fixture.barretenberg, b"#!/bin/sh\nprintf '6.0.0\\n'\n")?;
    fs::set_permissions(&fixture.nargo, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&fixture.barretenberg, fs::Permissions::from_mode(0o700))?;

    let process = PinnedReleaseProcess::try_new(SystemReleaseProcessRunner, fixture.paths()?)?;
    assert_eq!(
        process.toolchain().barretenberg_version().as_bytes(),
        b"6.0.0"
    );
    fixture.cleanup()
}
