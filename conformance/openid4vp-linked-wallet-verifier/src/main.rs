// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used,
    clippy::wildcard_imports
)]

#[path = "../../../crates/backend-bb/tests/support/modern_all30.rs"]
mod modern_all30;

mod artifacts;
mod binding_rejection;
mod common_credential_root_direct_post;
mod common_credential_root_issuance;
mod common_credential_root_stage_builder;
mod constants;
mod credential_subject_claim;
mod direct_post;
mod error;
mod fixture;
mod openid;
mod runtime;
mod sd_jwt_roundtrip;
mod status_qualified;
mod witness;

use std::sync::Arc;

use artifacts::{load_private_persona_stages, StageResolver};
use binding_rejection::verify_negative_bindings;
use common_credential_root_direct_post::{
    common_credential_root_release_paths, expect_common_credential_root_direct_post_accepts_once,
    write_active_binding,
};
use constants::{
    COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT_ENV, DIRECT_POST_FIXTURE_ROOT_ENV, FIXTURE_ROOT_ENV,
    QUERY_A, QUERY_B, SECOND_COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT_ENV,
};
use credential_subject_claim::verify_credential_subject_claim_status;
use direct_post::{
    direct_post_session_binding, direct_post_status_qualified_wallet_values,
    expect_direct_post_accepts_once, status_floor_store,
};
use error::{HarnessError, HarnessPhase};
use fixture::{
    trusted_issuers_from_fixtures, validate_fixture_relationships, verification_time_for_fixtures,
    CredentialFixture,
};
use modern_all30::{
    read_g2, read_prover_g1_prefix, required_path, G1_PATH_ENV, G2_PATH_ENV, ROOT_ENV,
};
use openid::status_qualified_wallet_value;
use openid::{
    dc_api_invocation, expect_direct_post_rejects_dc_api_bound_presentation, expect_zk_reason,
    openid_session_binding, verify_response, zk_claim_pair,
};
use reallyme_openid4vp_types::PresentationValue;
use reallyme_openid4vp_verifier::{
    HolderBindingVerifier, ZkHolderBindingVerifier, ZkVerificationRequirements,
};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver,
        ZkPresentationBoundClaimBundleVerifier, ZkPresentationBoundClaimBundleVerifyRequest,
        ZkStatusQualifiedClaimProofBundle,
    },
    errors::ZkErrorReason,
    issuer_status::ZkIssuerStatusPurpose,
    proofs::ZkProofSuite,
};
use reallyme_zk_backend_bb::{
    BarretenbergBundleProvider, BarretenbergProverCrs, NativeBarretenbergBackend,
};
use runtime::OwnedZkHolderBindingVerifier;
use status_qualified::{
    expect_live_status_rejections, prove_issuer_credential_status, signed_status_list,
    status_source, FixtureStatusSignatureVerifier, StatusRejectionContext,
};
use witness::witness_bundle_from_tomls;

fn main() -> Result<(), HarnessError> {
    run()
}

fn run() -> Result<(), HarnessError> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 2 && args.get(1).map(String::as_str) == Some("--sd-jwt-only") {
        return sd_jwt_roundtrip::run_sd_jwt_roundtrip();
    }
    let root = required_path(ROOT_ENV)?;
    let fixture_root = required_path(FIXTURE_ROOT_ENV)?;
    let direct_post_fixture_root = required_path(DIRECT_POST_FIXTURE_ROOT_ENV)?;
    let common_credential_root_stage_request_root =
        required_path(COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT_ENV)?;
    let second_common_credential_root_stage_request_root =
        required_path(SECOND_COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT_ENV)?;
    if args.len() == 3
        && matches!(
            args.get(1).map(String::as_str),
            Some(
                "--write-common-credential-root-binding"
                    | "--write-second-common-credential-root-binding"
            )
        )
    {
        let first_fixture = CredentialFixture::try_new(&direct_post_fixture_root, QUERY_A)?;
        let second_fixture = CredentialFixture::try_new(&direct_post_fixture_root, QUERY_B)?;
        let verification_time_unix =
            verification_time_for_fixtures([&first_fixture, &second_fixture])?;
        let output = args.get(2).ok_or(HarnessError::MissingField)?;
        let second = args.get(1).map(String::as_str)
            == Some("--write-second-common-credential-root-binding");
        return write_active_binding(std::path::Path::new(output), verification_time_unix, second);
    }
    sd_jwt_roundtrip::run_sd_jwt_roundtrip()?;
    let g1 = read_prover_g1_prefix(&required_path(G1_PATH_ENV)?)?;
    let g2 = read_g2(&required_path(G2_PATH_ENV)?)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1.as_slice(), &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(crs)?;

    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stages = load_private_persona_stages(&root, credential_hash_algorithm)?;
    let first_fixture = CredentialFixture::try_new(&fixture_root, QUERY_A)?;
    let second_fixture = CredentialFixture::try_new(&fixture_root, QUERY_B)?;
    let wrong_fixture = CredentialFixture::try_new(&fixture_root.join("wrong-persona"), QUERY_A)?;
    validate_fixture_relationships(&first_fixture, &second_fixture, &wrong_fixture)?;
    let first_direct_post_fixture = CredentialFixture::try_new(&direct_post_fixture_root, QUERY_A)?;
    let second_direct_post_fixture =
        CredentialFixture::try_new(&direct_post_fixture_root, QUERY_B)?;
    let wrong_direct_post_fixture =
        CredentialFixture::try_new(&direct_post_fixture_root.join("wrong-persona"), QUERY_A)?;
    validate_fixture_relationships(
        &first_direct_post_fixture,
        &second_direct_post_fixture,
        &wrong_direct_post_fixture,
    )?;

    let session_binding = openid_session_binding();
    let first_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &first_fixture,
        session_binding,
    )?;
    let second_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &second_fixture,
        session_binding,
    )?;
    let wrong_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &wrong_fixture,
        session_binding,
    )?;
    let direct_post_binding = direct_post_session_binding();
    let first_direct_post_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &first_direct_post_fixture,
        direct_post_binding,
    )?;
    let second_direct_post_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &second_direct_post_fixture,
        direct_post_binding,
    )?;
    let (common_credential_root_artifact_root, common_credential_root_release_index) =
        common_credential_root_release_paths()?;
    let resolver = StageResolver::try_new(bundle_kind, credential_hash_algorithm, stages)
        .map_err(|_| HarnessError::Phase(HarnessPhase::PrivatePersonaResolver))?
        .with_common_credential_root_release(
            &common_credential_root_artifact_root,
            common_credential_root_release_index.as_slice(),
        )
        .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootResolver))?;
    let provider = Arc::new(BarretenbergBundleProvider::new(backend, resolver));

    let first_bundle = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &first_witness,
            session_binding,
        )?)
        .map_err(|_| HarnessError::Phase(HarnessPhase::FirstBundleProof))?;
    let second_bundle = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &second_witness,
            session_binding,
        )?)
        .map_err(|_| HarnessError::Phase(HarnessPhase::SecondBundleProof))?;
    let wrong_bundle = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &wrong_witness,
            session_binding,
        )?)
        .map_err(|_| HarnessError::Phase(HarnessPhase::WrongPersonaBundleProof))?;
    let first_direct_post_bundle = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &first_direct_post_witness,
            direct_post_binding,
        )?)
        .map_err(|_| HarnessError::Phase(HarnessPhase::FirstDirectPostBundleProof))?;
    let second_direct_post_bundle = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &second_direct_post_witness,
            direct_post_binding,
        )?)
        .map_err(|_| HarnessError::Phase(HarnessPhase::SecondDirectPostBundleProof))?;

    let trusted_issuers =
        trusted_issuers_from_fixtures([&first_fixture, &second_fixture, &wrong_fixture])?;
    let verification_time_unix =
        verification_time_for_fixtures([&first_fixture, &second_fixture, &wrong_fixture])?;
    let first_qualified = ZkStatusQualifiedClaimProofBundle::try_from_parts(
        first_bundle,
        prove_issuer_credential_status(
            provider.as_ref(),
            &first_fixture,
            credential_hash_algorithm,
            session_binding,
        )?,
    )?;
    let second_qualified = ZkStatusQualifiedClaimProofBundle::try_from_parts(
        second_bundle,
        prove_issuer_credential_status(
            provider.as_ref(),
            &second_fixture,
            credential_hash_algorithm,
            session_binding,
        )?,
    )?;
    let wrong_qualified = ZkStatusQualifiedClaimProofBundle::try_from_parts(
        wrong_bundle,
        prove_issuer_credential_status(
            provider.as_ref(),
            &wrong_fixture,
            credential_hash_algorithm,
            session_binding,
        )?,
    )?;
    let first_direct_post_qualified = ZkStatusQualifiedClaimProofBundle::try_from_parts(
        first_direct_post_bundle,
        prove_issuer_credential_status(
            provider.as_ref(),
            &first_direct_post_fixture,
            credential_hash_algorithm,
            direct_post_binding,
        )?,
    )?;
    let second_direct_post_qualified = ZkStatusQualifiedClaimProofBundle::try_from_parts(
        second_direct_post_bundle,
        prove_issuer_credential_status(
            provider.as_ref(),
            &second_direct_post_fixture,
            credential_hash_algorithm,
            direct_post_binding,
        )?,
    )?;
    let signer_verifier = FixtureStatusSignatureVerifier::new()?;
    let first_status_list = signed_status_list(&first_fixture)?;
    let second_status_list = signed_status_list(&second_fixture)?;
    let status_sources = [
        status_source(
            &first_status_list,
            &signer_verifier,
            first_fixture.issuer_key,
        ),
        status_source(
            &second_status_list,
            &signer_verifier,
            second_fixture.issuer_key,
        ),
    ];
    let (status_store, _status_store_directory) = status_floor_store()?;
    let status_authority =
        reallyme_identity_openid4vp_product_store::ZkPersonaCredentialEvidenceSignedStatusAuthority::new(
            status_store.as_ref(),
            &status_sources,
        );
    let verifier = ZkHolderBindingVerifier::new(
        provider.as_ref(),
        trusted_issuers.as_slice(),
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: true,
        },
    )
    .with_issuer_credential_status(
        provider.as_ref(),
        &status_authority,
        ZkIssuerStatusPurpose::Revocation,
    );
    let invocation = dc_api_invocation()?;
    let first_value = status_qualified_wallet_value(&first_qualified, QUERY_A, &invocation)?;
    let second_value = status_qualified_wallet_value(&second_qualified, QUERY_B, &invocation)?;
    let direct_post_values = direct_post_status_qualified_wallet_values(
        &first_direct_post_qualified,
        &second_direct_post_qualified,
        verification_time_unix,
    )?;

    verify_same_persona_accepts(
        &verifier,
        [
            first_qualified.claim_proof_bundle(),
            second_qualified.claim_proof_bundle(),
        ],
        [first_value.clone(), second_value.clone()],
        verification_time_unix,
    )?;
    verify_negative_bindings(
        &verifier,
        [
            first_qualified.claim_proof_bundle(),
            second_qualified.claim_proof_bundle(),
        ],
        [first_value.clone(), second_value.clone()],
        verification_time_unix,
    )?;
    verify_wrong_persona_rejects_composition(
        &verifier,
        [
            first_qualified.claim_proof_bundle(),
            wrong_qualified.claim_proof_bundle(),
        ],
        [
            first_value.clone(),
            status_qualified_wallet_value(&wrong_qualified, QUERY_B, &invocation)?,
        ],
        verification_time_unix,
    )?;
    verify_direct_zk_binding_rejects(
        provider.as_ref(),
        first_qualified.claim_proof_bundle(),
        session_binding,
        trusted_issuers.as_slice(),
        verification_time_unix,
    )?;
    expect_live_status_rejections(StatusRejectionContext {
        provider: provider.as_ref(),
        first: &first_qualified,
        second: &second_qualified,
        first_fixture: &first_fixture,
        signer_verifier: &signer_verifier,
        trusted_issuers: trusted_issuers.as_slice(),
        current_authority: &status_authority,
        session_binding,
        verification_time_unix,
    })?;

    verify_credential_subject_claim_status(
        &root,
        &fixture_root,
        &common_credential_root_artifact_root,
        common_credential_root_release_index.as_slice(),
    )?;

    expect_common_credential_root_direct_post_accepts_once(
        provider.clone(),
        &common_credential_root_stage_request_root,
        &second_common_credential_root_stage_request_root,
        verification_time_unix,
        trusted_issuers.as_slice(),
    )?;

    let runtime_verifier: Arc<dyn HolderBindingVerifier> = Arc::new(OwnedZkHolderBindingVerifier {
        provider: provider.clone(),
        trusted_issuers,
        requirements: ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: true,
        },
        status_store,
        status_lists: [first_status_list, second_status_list],
        status_issuer_keys: [first_fixture.issuer_key, second_fixture.issuer_key],
        status_signer: signer_verifier,
    });
    expect_direct_post_accepts_once(
        runtime_verifier.clone(),
        first_direct_post_qualified.claim_proof_bundle(),
        second_direct_post_qualified.claim_proof_bundle(),
        direct_post_values,
        verification_time_unix,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::DirectPostRuntime))?;
    expect_direct_post_rejects_dc_api_bound_presentation(
        runtime_verifier,
        [
            (first_qualified.claim_proof_bundle(), QUERY_A),
            (second_qualified.claim_proof_bundle(), QUERY_B),
        ],
        [(QUERY_A, first_value), (QUERY_B, second_value)],
        verification_time_unix,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::DcApiBoundPresentationRejection))
}

fn verify_same_persona_accepts(
    verifier: &ZkHolderBindingVerifier<'_>,
    bundles: [&reallyme_zk_api::claim_bundle::ZkClaimProofBundle; 2],
    values: [PresentationValue; 2],
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    let accepted = verify_response(
        verifier,
        [(bundles[0], QUERY_A), (bundles[1], QUERY_B)],
        [(QUERY_A, values[0].clone()), (QUERY_B, values[1].clone())],
        verification_time_unix,
    )?;
    let accepted_claims = zk_claim_pair(&accepted)?;
    if accepted_claims
        .0
        .same_presenting_key_in_session(accepted_claims.1)
    {
        Ok(())
    } else {
        Err(HarnessError::WrongPersonaAccepted)
    }
}

fn verify_wrong_persona_rejects_composition(
    verifier: &ZkHolderBindingVerifier<'_>,
    bundles: [&reallyme_zk_api::claim_bundle::ZkClaimProofBundle; 2],
    values: [PresentationValue; 2],
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    let rejected = verify_response(
        verifier,
        [(bundles[0], QUERY_A), (bundles[1], QUERY_B)],
        [(QUERY_A, values[0].clone()), (QUERY_B, values[1].clone())],
        verification_time_unix,
    )?;
    let rejected_claims = zk_claim_pair(&rejected)?;
    if rejected_claims
        .0
        .same_presenting_key_in_session(rejected_claims.1)
    {
        Err(HarnessError::WrongPersonaAccepted)
    } else {
        Ok(())
    }
}

fn verify_direct_zk_binding_rejects(
    provider: &impl ZkPresentationBoundClaimBundleVerifier,
    bundle: &reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
    mut binding: reallyme_zk_api::proofs::ZkSessionBinding,
    trusted_issuers: &[reallyme_zk_api::keys::ZkIssuerPublicKey],
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    binding.nonce_hash[0] ^= 1;
    expect_zk_reason(
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            trusted_issuers,
            verification_time_unix,
        )
        .and_then(|request| provider.verify_presentation_bound_claim_bundle_evidence(request)),
        ZkErrorReason::BindingMismatch,
    )
}
