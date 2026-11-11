// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    compiled_artifact, normalize_compiled_program_artifact, ReleaseProcessError,
    ReleaseProcessErrorReason,
};

#[test]
fn compiled_artifact_normalization_removes_build_root_identity() -> Result<(), ReleaseProcessError>
{
    let first = compiled_artifact(32, "acir", 1);
    let second = String::from_utf8(first.clone())
        .map_err(|_| {
            ReleaseProcessError::new(ReleaseProcessErrorReason::MalformedCompiledArtifact)
        })?
        .replace("/tmp/build-1", "/another/checkout/root")
        .into_bytes();
    let first = normalize_compiled_program_artifact(&first)?;
    let second = normalize_compiled_program_artifact(&second)?;

    assert_eq!(first, second);
    let normalized_path = br#""path":"source/1.nr""#;
    assert!(first
        .windows(normalized_path.len())
        .any(|window| window == normalized_path));
    Ok(())
}
