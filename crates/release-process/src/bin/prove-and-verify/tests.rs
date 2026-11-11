// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_arguments, OsString, PathBuf, ReleaseProcessError, ReleaseProcessErrorReason};

#[test]
fn parser_requires_exact_opaque_path_arguments() {
    let missing = [OsString::from("binary")];
    let extra = [
        "binary",
        "nargo",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "bb",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "crs",
        "bytecode",
        "witness",
        "output",
        "sha256:credential_subject_claim_v1:session:v1",
        "suite",
        "extra",
    ]
    .map(OsString::from);

    assert_eq!(
        parse_arguments(missing).err().map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::InvalidArguments)
    );
    assert_eq!(
        parse_arguments(extra).err().map(|error| error.reason()),
        Some(ReleaseProcessErrorReason::InvalidArguments)
    );
}

#[test]
fn parser_preserves_non_utf8_agnostic_path_values() -> Result<(), ReleaseProcessError> {
    let arguments = [
        "binary",
        "nargo",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "bb",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "crs",
        "bytecode",
        "witness",
        "output",
        "sha256:credential_subject_claim_v1:session:v1",
    ]
    .map(OsString::from);

    let parsed = parse_arguments(arguments)?;

    assert_eq!(parsed.nargo, PathBuf::from("nargo"));
    assert_eq!(parsed.output, PathBuf::from("output"));
    assert_eq!(
        parsed.proof_suite,
        reallyme_zk_api::proofs::ZkProofSuite::PRODUCTION
    );
    Ok(())
}
