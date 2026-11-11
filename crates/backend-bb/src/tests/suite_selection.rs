// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver,
        ZkCompatibilitySuiteAcknowledgement, ZkPresentationBoundClaimBundleVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};

use super::{
    binding, bundle_with_hashes, claim_proof_bundle_witness, provider, trusted_issuer,
    AcceptingBackend, BarretenbergBundleProvider, StaticArtifactResolver,
};

#[test]
fn prove_claim_proof_bundle_preserves_each_explicit_suite() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Poseidon2;
    let witness_bundle = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;

    for suite in ZkProofSuite::ALL {
        let request = if *suite == ZkProofSuite::PRODUCTION {
            ZkClaimProofBundleProveRequest::try_new(
                bundle_kind,
                credential_hash_algorithm,
                *suite,
                &witness_bundle,
                binding(2),
            )?
        } else {
            ZkClaimProofBundleProveRequest::try_new_compatibility(
                bundle_kind,
                credential_hash_algorithm,
                *suite,
                &witness_bundle,
                binding(2),
                ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
            )?
        };
        let bundle = provider().prove_claim_proof_bundle(request)?;
        assert_eq!(bundle.proof_suite(), *suite);
        assert!(bundle
            .stage_proofs()
            .iter()
            .all(|stage| stage.proof().proof_suite() == *suite));
    }
    Ok(())
}

#[test]
fn verify_claim_proof_bundle_rejects_a_suite_not_selected_by_policy() -> Result<(), ZkError> {
    let bundle = bundle_with_hashes(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        &[Some(ZkCredentialHashAlgorithm::Sha256); 4],
    )?;
    let error = ZkPresentationBoundClaimBundleVerifyRequest::try_new_compatibility(
        &bundle,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
        binding(7),
        &[trusted_issuer()],
        41,
        ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::UnsupportedProofSuite));
    Ok(())
}

#[test]
fn prove_claim_proof_bundle_fails_closed_when_backend_lacks_requested_suite() -> Result<(), ZkError>
{
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let witness_bundle = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;
    let provider = BarretenbergBundleProvider::new(
        AcceptingBackend::only(ZkProofSuite::PRODUCTION),
        StaticArtifactResolver::matching(),
    );
    let error = provider
        .prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new_compatibility(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
            &witness_bundle,
            binding(2),
            ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )?)
        .err()
        .map(|error| error.reason());

    assert_eq!(error, Some(ZkErrorReason::UnsupportedProofSuite));
    Ok(())
}
