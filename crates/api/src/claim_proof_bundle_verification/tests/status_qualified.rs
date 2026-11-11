// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::sync::atomic::{AtomicU32, Ordering};

use super::{
    binding, bundle_issuer, bundle_with_expiry, issuer, manifest_digest, private_persona_bundle,
    AcceptingBundleVerifier,
};
use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{
        prove_status_qualified_claim_proof_bundle_with,
        verify_status_qualified_claim_proof_bundle_with, ZkClaimProofBundleKind,
        ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver, ZkClaimProofBundleStage,
        ZkClaimProofBundleWitness, ZkPresentationBoundClaimBundleVerifyRequest,
        ZkStatusQualifiedClaimProofBundleVerifyRequest,
    },
    common_root::ZkCommonCredentialRootRawPublicInputs,
    errors::{ZkError, ZkErrorReason},
    issuer_status::{
        ZkIssuerCredentialStatusProof, ZkIssuerCredentialStatusProver,
        ZkIssuerCredentialStatusVerifier, ZkIssuerStatusAuthority, ZkIssuerStatusFeed,
        ZkIssuerStatusListPointer,
    },
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding, ZkWitness},
};

const STATUS_FIELD_BYTES: usize = 32;
const STATUS_FIELD_COUNT: usize = 292;
const STATUS_TEST_EXPIRY: u64 = 1_060;
const STATUS_TEST_NOW: u64 = 1_000;

fn set_status_bytes(fields: &mut [u8], start_field: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        fields[(start_field + offset) * STATUS_FIELD_BYTES + STATUS_FIELD_BYTES - 1] = *byte;
    }
}

fn set_status_u64(fields: &mut [u8], field: usize, value: u64) {
    let start = field * STATUS_FIELD_BYTES + STATUS_FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn signed_status_fields(
    session: ZkSessionBinding,
    issuer: ZkIssuerPublicKey,
    credential_binding: [u8; 32],
) -> Vec<u8> {
    let mut fields = vec![0_u8; STATUS_FIELD_COUNT * STATUS_FIELD_BYTES];
    set_status_bytes(&mut fields, 0, &session.nonce_hash);
    set_status_bytes(&mut fields, 32, &session.audience_hash);
    set_status_bytes(&mut fields, 64, &session.transaction_data_public_input());
    set_status_bytes(&mut fields, 96, &issuer.x);
    set_status_bytes(&mut fields, 128, &issuer.y);
    set_status_u64(&mut fields, 160, STATUS_TEST_EXPIRY);
    set_status_bytes(&mut fields, 161, &credential_binding);
    set_status_bytes(&mut fields, 193, &[0x41; 32]);
    set_status_u64(&mut fields, 225, 256);
    set_status_bytes(&mut fields, 226, &[0x42; 32]);
    set_status_bytes(&mut fields, 258, &[0x43; 32]);
    set_status_bytes(&mut fields, 290, &[1]);
    set_status_u64(&mut fields, 291, STATUS_TEST_NOW);
    fields
}

fn signed_status_proof(
    lane: ZkCredentialHashAlgorithm,
    fields: Vec<u8>,
) -> Result<ZkIssuerCredentialStatusProof, ZkError> {
    let circuit_ref = ZkCircuitRef::new(
        lane,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::IssuerCredentialStatus,
    );
    ZkIssuerCredentialStatusProof::try_from_parts(
        ZkProofSuite::PRODUCTION,
        crate::artifacts::ZkArtifactSetIdentity::from_bytes(*(manifest_digest()).as_bytes()),
        ZkProofBytes::try_from_bytes(vec![0x51])?,
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, fields)?,
    )
}

struct AcceptingStatusVerifier;

impl ZkIssuerCredentialStatusVerifier for AcceptingStatusVerifier {
    fn verify_issuer_credential_status(
        &self,
        proof: &ZkIssuerCredentialStatusProof,
    ) -> Result<(), ZkError> {
        if proof.proof_bytes().as_bytes() != [0x51] {
            return Err(ZkError::new(ZkErrorReason::InvalidProof));
        }
        Ok(())
    }
}

struct FixedStatusAuthority {
    root: [u8; 32],
}

struct CountingStatusAuthority(std::sync::atomic::AtomicUsize);

impl ZkIssuerStatusAuthority for CountingStatusAuthority {
    fn current_feed_for_issuer(
        &self,
        _issuer_key: &ZkIssuerPublicKey,
        _pointer: &ZkIssuerStatusListPointer,
        _verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(ZkError::new(ZkErrorReason::UntrustedIssuer))
    }
}

impl ZkIssuerStatusAuthority for FixedStatusAuthority {
    fn current_feed_for_issuer(
        &self,
        issuer_key: &ZkIssuerPublicKey,
        pointer: &ZkIssuerStatusListPointer,
        verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError> {
        if *issuer_key != bundle_issuer()
            || verification_time_unix != STATUS_TEST_NOW
            || pointer.list_id != [0x42; 32]
            || pointer.url_hash != [0x43; 32]
            || pointer.purpose != crate::issuer_status::ZkIssuerStatusPurpose::Revocation
        {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        Ok(ZkIssuerStatusFeed {
            root: self.root,
            length: 256,
            list_id: pointer.list_id,
            url_hash: pointer.url_hash,
            purpose: pointer.purpose,
        })
    }
}

fn verify_status_fixture(fields: Vec<u8>, authority_root: [u8; 32]) -> Result<(), ZkError> {
    let bundle = bundle_with_expiry(STATUS_TEST_EXPIRY)?;
    verify_status_fixture_with_bundle(&bundle, fields, authority_root)
}

fn verify_status_fixture_with_bundle(
    bundle: &crate::claim_bundle::ZkClaimProofBundle,
    fields: Vec<u8>,
    authority_root: [u8; 32],
) -> Result<(), ZkError> {
    let status_proof = signed_status_proof(ZkCredentialHashAlgorithm::Sha256, fields)?;
    let authority = FixedStatusAuthority {
        root: authority_root,
    };
    let trusted_issuers = [bundle_issuer()];
    let bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        bundle,
        ZkProofSuite::PRODUCTION,
        binding(11),
        &trusted_issuers,
        STATUS_TEST_NOW,
    )?;
    let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        bundle_request,
        &status_proof,
        &authority,
        crate::issuer_status::ZkIssuerStatusPurpose::Revocation,
    )?;
    let verified = verify_status_qualified_claim_proof_bundle_with(
        &AcceptingBundleVerifier::new(),
        &AcceptingStatusVerifier,
        request,
    )?;
    let statement: &crate::claim_bundle::ZkVerifiedClaimStatement = verified.statement();
    if statement.credential_binding() != [14; 32] {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

#[test]
fn status_qualified_credential_subject_claim_requires_matching_current_feed() -> Result<(), ZkError>
{
    let fields = signed_status_fields(binding(11), bundle_issuer(), [14; 32]);
    verify_status_fixture(fields, [0x41; 32])
}

#[test]
fn status_qualified_private_persona_requires_matching_current_feed() -> Result<(), ZkError> {
    let bundle = private_persona_bundle(
        binding(11),
        bundle_issuer(),
        issuer(7),
        [0x55; 32],
        STATUS_TEST_EXPIRY,
    )?;
    let fields = signed_status_fields(binding(11), bundle_issuer(), [14; 32]);
    verify_status_fixture_with_bundle(&bundle, fields, [0x41; 32])?;

    // The private claim's hidden persona does not change the credential join:
    // substituting the issuer's current root must still fail closed.
    let fields = signed_status_fields(binding(11), bundle_issuer(), [14; 32]);
    let error = verify_status_fixture_with_bundle(&bundle, fields, [0x77; 32])
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn status_qualified_credential_subject_claim_rejects_substitution_and_stale_feed(
) -> Result<(), ZkError> {
    for changed_field in [96, 161, 193, 225, 226, 258, 290, 291] {
        let mut fields = signed_status_fields(binding(11), bundle_issuer(), [14; 32]);
        if changed_field == 225 {
            set_status_u64(&mut fields, changed_field, 257);
        } else if changed_field == 291 {
            set_status_u64(&mut fields, changed_field, STATUS_TEST_NOW + 1);
        } else {
            set_status_bytes(&mut fields, changed_field, &[0x99]);
        }
        let result = verify_status_fixture(fields, [0x41; 32]);
        assert!(
            result.is_err(),
            "changed field {changed_field} was accepted"
        );
    }
    let fields = signed_status_fields(binding(11), bundle_issuer(), [14; 32]);
    let error = verify_status_fixture(fields, [0x77; 32])
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn mismatched_status_proof_does_not_consult_status_authority() -> Result<(), ZkError> {
    let bundle = bundle_with_expiry(STATUS_TEST_EXPIRY)?;
    let fields = signed_status_fields(binding(11), bundle_issuer(), [0x99; 32]);
    let status_proof = signed_status_proof(ZkCredentialHashAlgorithm::Sha256, fields)?;
    let authority = CountingStatusAuthority(std::sync::atomic::AtomicUsize::new(0));
    let issuers = [bundle_issuer()];
    let bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        ZkProofSuite::PRODUCTION,
        binding(11),
        &issuers,
        STATUS_TEST_NOW,
    )?;
    let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        bundle_request,
        &status_proof,
        &authority,
        crate::issuer_status::ZkIssuerStatusPurpose::Revocation,
    )?;
    let result = verify_status_qualified_claim_proof_bundle_with(
        &AcceptingBundleVerifier::new(),
        &AcceptingStatusVerifier,
        request,
    );
    let error = result
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    assert_eq!(authority.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    Ok(())
}

struct CountingProver(AtomicU32);

impl ZkClaimProofBundleProver for CountingProver {
    fn prove_claim_proof_bundle(
        &self,
        _request: ZkClaimProofBundleProveRequest<'_>,
    ) -> Result<crate::claim_bundle::ZkClaimProofBundle, ZkError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    }
}

impl ZkIssuerCredentialStatusProver for CountingProver {
    fn prove_issuer_credential_status(
        &self,
        _credential_hash_algorithm: ZkCredentialHashAlgorithm,
        _witness: &ZkWitness,
        _session_binding: ZkSessionBinding,
    ) -> Result<ZkIssuerCredentialStatusProof, ZkError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    }
}

#[test]
fn status_qualified_prover_rejects_wrong_source_before_backend() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let mut witnesses = Vec::new();
    for stage in ZkClaimProofBundleStage::ALL {
        witnesses.push(ZkWitness::try_from_noir_witness_stack_v1(
            bundle_kind.source_ref(credential_hash_algorithm, *stage),
            vec![1],
        )?);
    }
    let claim_proof_bundle_witness = ZkClaimProofBundleWitness::try_from_stage_witnesses(
        bundle_kind,
        credential_hash_algorithm,
        witnesses,
    )?;
    let wrong_status_witness = ZkWitness::try_from_noir_witness_stack_v1(
        bundle_kind.source_ref(credential_hash_algorithm, ZkClaimProofBundleStage::Claim),
        vec![1],
    )?;
    let prover = CountingProver(AtomicU32::new(0));
    let result = prove_status_qualified_claim_proof_bundle_with(
        &prover,
        &prover,
        bundle_kind,
        credential_hash_algorithm,
        &claim_proof_bundle_witness,
        &wrong_status_witness,
        binding(11),
    );
    let error = result
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    assert_eq!(prover.0.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn status_qualified_acceptance_rejects_backend_failure_before_status_authority(
) -> Result<(), ZkError> {
    struct RejectingStatusVerifier;
    impl ZkIssuerCredentialStatusVerifier for RejectingStatusVerifier {
        fn verify_issuer_credential_status(
            &self,
            _proof: &ZkIssuerCredentialStatusProof,
        ) -> Result<(), ZkError> {
            Err(ZkError::new(ZkErrorReason::InvalidProof))
        }
    }
    let bundle = bundle_with_expiry(STATUS_TEST_EXPIRY)?;
    let status = signed_status_proof(
        ZkCredentialHashAlgorithm::Sha256,
        signed_status_fields(binding(11), bundle_issuer(), [14; 32]),
    )?;
    let authority = CountingStatusAuthority(std::sync::atomic::AtomicUsize::new(0));
    let issuers = [bundle_issuer()];
    let bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        ZkProofSuite::PRODUCTION,
        binding(11),
        &issuers,
        STATUS_TEST_NOW,
    )?;
    let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        bundle_request,
        &status,
        &authority,
        crate::issuer_status::ZkIssuerStatusPurpose::Revocation,
    )?;
    let error = verify_status_qualified_claim_proof_bundle_with(
        &AcceptingBundleVerifier::new(),
        &RejectingStatusVerifier,
        request,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::InvalidProof);
    assert_eq!(authority.0.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn status_qualified_acceptance_requires_authenticated_current_status() -> Result<(), ZkError> {
    let bundle = bundle_with_expiry(STATUS_TEST_EXPIRY)?;
    let status = signed_status_proof(
        ZkCredentialHashAlgorithm::Sha256,
        signed_status_fields(binding(11), bundle_issuer(), [14; 32]),
    )?;
    let authority = CountingStatusAuthority(std::sync::atomic::AtomicUsize::new(0));
    let issuers = [bundle_issuer()];
    let bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        ZkProofSuite::PRODUCTION,
        binding(11),
        &issuers,
        STATUS_TEST_NOW,
    )?;
    let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        bundle_request,
        &status,
        &authority,
        crate::issuer_status::ZkIssuerStatusPurpose::Revocation,
    )?;
    let error = verify_status_qualified_claim_proof_bundle_with(
        &AcceptingBundleVerifier::new(),
        &AcceptingStatusVerifier,
        request,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::UntrustedIssuer);
    assert_eq!(authority.0.load(Ordering::Relaxed), 1);
    Ok(())
}
