// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_arguments, OsString, PathBuf, ReleaseProcessError, ReleaseProcessErrorReason};

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
        "circuit",
        "package",
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
fn parser_keeps_package_identity_separate_from_paths() -> Result<(), ReleaseProcessError> {
    let arguments = [
        "binary",
        "nargo",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "bb",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "crs",
        "circuit",
        "package",
        "output",
        "sha256:credential_subject_claim_v1:session:v1",
    ]
    .map(OsString::from);

    let parsed = parse_arguments(arguments)?;

    assert_eq!(parsed.package_name, OsString::from("package"));
    assert_eq!(parsed.circuit, PathBuf::from("circuit"));
    assert_eq!(
        parsed.proof_suite,
        reallyme_zk_api::proofs::ZkProofSuite::PRODUCTION
    );
    Ok(())
}

#[test]
fn parser_accepts_an_explicit_suite() -> Result<(), ReleaseProcessError> {
    let arguments = [
        "binary",
        "nargo",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "bb",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "crs",
        "circuit",
        "package",
        "output",
        "sha256:credential_subject_claim_v1:session:v1",
        "barretenberg_ultra_honk_poseidon2_unmasked_no_ipa",
    ]
    .map(OsString::from);

    let parsed = parse_arguments(arguments)?;
    assert_eq!(
        parsed.proof_suite,
        reallyme_zk_api::proofs::ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa
    );
    Ok(())
}
