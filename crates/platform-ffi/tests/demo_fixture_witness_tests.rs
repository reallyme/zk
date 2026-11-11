// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, unsafe_code)]
#![cfg(feature = "native")]

#[path = "support/demo_fixture_witness.rs"]
mod demo_fixture_witness;

#[test]
fn demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider(
) -> Result<(), demo_fixture_witness::TestError> {
    demo_fixture_witness::run_demo_stage_fixtures_dispatch_witness_release_prove_and_verify_through_platform_provider()
}

#[test]
#[ignore = "requires staged mobile artifacts, common-credential-root vectors, linked Barretenberg, and full prover CRS"]
fn mobile_package_verifies_both_hashes_and_persona_modes(
) -> Result<(), demo_fixture_witness::TestError> {
    demo_fixture_witness::run_mobile_package_verifies_both_hashes_and_persona_modes()
}

#[test]
#[ignore = "requires staged mobile artifacts, common-credential-root stage vectors, linked Barretenberg, and full prover CRS"]
fn mobile_package_proves_every_common_credential_root_stage(
) -> Result<(), demo_fixture_witness::TestError> {
    demo_fixture_witness::run_mobile_package_proves_every_common_credential_root_stage()
}
