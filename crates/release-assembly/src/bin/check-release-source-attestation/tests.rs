// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_arguments, ReleaseAssemblyError, ReleaseAssemblyErrorReason};
use std::ffi::OsString;

#[test]
fn parser_requires_exact_argument_count() {
    let missing = [OsString::from("binary")];
    let extra = vec![
        OsString::from("binary"),
        OsString::from("workspace"),
        OsString::from("release"),
        OsString::from("0.1.0"),
        OsString::from("extra"),
    ];

    assert_eq!(
        parse_arguments(missing).err().map(|error| error.reason()),
        Some(ReleaseAssemblyErrorReason::InvalidArguments)
    );
    assert_eq!(
        parse_arguments(extra).err().map(|error| error.reason()),
        Some(ReleaseAssemblyErrorReason::InvalidArguments)
    );
}

#[test]
fn parser_rejects_malformed_release_version() {
    let arguments = vec![
        OsString::from("binary"),
        OsString::from("workspace"),
        OsString::from("release"),
        OsString::from("../0.1.0"),
    ];

    assert_eq!(
        parse_arguments(arguments).err().map(|error| error.reason()),
        Some(ReleaseAssemblyErrorReason::Domain(
            reallyme_zk_api::errors::ZkErrorReason::ArtifactMismatch,
        ))
    );
}

#[test]
fn parser_accepts_canonical_arguments() -> Result<(), ReleaseAssemblyError> {
    let arguments = vec![
        OsString::from("binary"),
        OsString::from("workspace"),
        OsString::from("release"),
        OsString::from("0.1.0"),
    ];

    let parsed = parse_arguments(arguments)?;
    assert_eq!(parsed.workspace_root, std::path::Path::new("workspace"));
    assert_eq!(parsed.release_root, std::path::Path::new("release"));
    assert_eq!(parsed.release_version.as_bytes(), b"0.1.0");
    Ok(())
}
