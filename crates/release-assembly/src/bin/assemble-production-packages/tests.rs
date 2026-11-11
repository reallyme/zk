// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_arguments, OsString, ReleaseAssemblyErrorReason};
use reallyme_zk_release_process::ReleaseToolchainProfile;

#[test]
fn parser_requires_exact_argument_count() {
    let missing = [OsString::from("binary")];
    let extra = [
        "binary",
        "nargo",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "bb",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "crs",
        "workspace",
        "proofs",
        "output",
        "0.1.0",
        "extra",
    ]
    .map(OsString::from);

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
fn parser_defaults_to_modern_profile(
) -> Result<(), reallyme_zk_release_assembly::ReleaseAssemblyError> {
    let parsed = parse_arguments(valid_arguments([]))?;

    assert_eq!(parsed.profile, ReleaseToolchainProfile::ModernCandidate);
    Ok(())
}

#[test]
fn parser_accepts_explicit_modern_candidate_profile(
) -> Result<(), reallyme_zk_release_assembly::ReleaseAssemblyError> {
    let parsed = parse_arguments(valid_arguments(["--modern-candidate"]))?;

    assert_eq!(parsed.profile, ReleaseToolchainProfile::ModernCandidate);
    Ok(())
}

#[test]
fn parser_rejects_unknown_profile_flag() {
    let parsed = parse_arguments(valid_arguments(["--candidate"]));

    assert_eq!(
        parsed.err().map(|error| error.reason()),
        Some(ReleaseAssemblyErrorReason::InvalidArguments)
    );
}

fn valid_arguments<const N: usize>(extra: [&str; N]) -> Vec<OsString> {
    [
        "binary",
        "/tmp/nargo",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "/tmp/bb",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "/tmp/crs",
        "/tmp/workspace",
        "/tmp/proofs",
        "/tmp/output",
        "0.1.0",
    ]
    .into_iter()
    .chain(extra)
    .map(OsString::from)
    .collect()
}
