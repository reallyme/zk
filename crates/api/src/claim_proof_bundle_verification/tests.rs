// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::sync::atomic::{AtomicU32, Ordering};

use super::{
    ZkClaimedStatement, ZkPresentationBoundClaimBundleVerifyRequest,
    ZkPresentationBoundClaimStatement,
};
use crate::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkClaimProofBundle, ZkClaimProofBundleKind,
        ZkClaimProofBundleStage, ZkPresentationBoundClaimBundleVerifier,
        MAX_PRESENTATION_LIFETIME_SECONDS,
    },
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding,
    },
};

mod status_qualified;

fn issuer(byte: u8) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [byte; 32],
        y: [byte.saturating_add(1); 32],
    }
}

fn claimed_statement(
    issuer: ZkIssuerPublicKey,
    persona: Option<crate::keys::ZkPersonaPublicKey>,
) -> Result<ZkClaimedStatement, ZkError> {
    let mut value = [0_u8; 64];
    value[0] = 9;
    ZkClaimedStatement::try_from_parts(issuer, persona, [8; 32], [3; 32], value, 1, 42)
}

fn binding(byte: u8) -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [byte; 32],
        audience_hash: [byte.saturating_add(1); 32],
        transaction_data_hash: Some([byte.saturating_add(2); 32]),
    }
}

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([7_u8; 32])
}

fn bundle_issuer() -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [0_u8; 32],
        y: [0_u8; 32],
    }
}

fn bundle_with_expiry(expiry_unix: u64) -> Result<ZkClaimProofBundle, ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let session_binding = binding(11);
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for stage in ZkClaimProofBundleStage::ALL {
        let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, *stage);
        let public_inputs = public_inputs_for(circuit_ref, session_binding, expiry_unix)?;
        let proof = ZkProof::try_from_exact_parts(
            bundle_kind.circuit_id(),
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            manifest_digest(),
            vec![stage.index().saturating_add(1)],
            public_inputs,
        )?;
        proofs.push(
            crate::claim_bundle::ZkClaimProofBundleStageProof::try_from_parts(
                bundle_kind,
                *stage,
                proof,
            )?,
        );
    }
    ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, session_binding, proofs)
}

fn private_persona_bundle(
    session_binding: ZkSessionBinding,
    credential_issuer: ZkIssuerPublicKey,
    persona: ZkIssuerPublicKey,
    session_link_commitment: [u8; 32],
    expiry_unix: u64,
) -> Result<ZkClaimProofBundle, ZkError> {
    private_persona_bundle_with_credential_binding(
        session_binding,
        credential_issuer,
        persona,
        session_link_commitment,
        [14_u8; 32],
        expiry_unix,
    )
}

fn private_persona_bundle_with_credential_binding(
    session_binding: ZkSessionBinding,
    credential_issuer: ZkIssuerPublicKey,
    persona: ZkIssuerPublicKey,
    session_link_commitment: [u8; 32],
    credential_binding: [u8; 32],
    expiry_unix: u64,
) -> Result<ZkClaimProofBundle, ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for stage in ZkClaimProofBundleStage::ALL {
        let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, *stage);
        let public_inputs = private_persona_public_inputs_for(
            circuit_ref,
            session_binding,
            credential_issuer,
            persona,
            session_link_commitment,
            credential_binding,
            expiry_unix,
        )?;
        let proof = ZkProof::try_from_exact_parts(
            bundle_kind.circuit_id(),
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            manifest_digest(),
            vec![stage.index().saturating_add(1)],
            public_inputs,
        )?;
        proofs.push(
            crate::claim_bundle::ZkClaimProofBundleStageProof::try_from_parts(
                bundle_kind,
                *stage,
                proof,
            )?,
        );
    }
    ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, session_binding, proofs)
}

fn private_persona_public_inputs_for(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
    credential_issuer: ZkIssuerPublicKey,
    persona: ZkIssuerPublicKey,
    session_link_commitment: [u8; 32],
    credential_binding: [u8; 32],
    expiry_unix: u64,
) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::Challenge,
        &binding.nonce_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::AudienceHash,
        &binding.audience_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::TransactionDataHash,
        &binding.transaction_data_public_input(),
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &expiry_unix.to_be_bytes(),
    )?;
    for (name, value) in [
        (ZkPublicInputName::IssuerPublicKeyX, credential_issuer.x),
        (ZkPublicInputName::IssuerPublicKeyY, credential_issuer.y),
        (ZkPublicInputName::PersonaPublicKeyX, persona.x),
        (ZkPublicInputName::PersonaPublicKeyY, persona.y),
        (ZkPublicInputName::SessionBinding, session_link_commitment),
        (ZkPublicInputName::EnvelopeBinding, [13_u8; 32]),
        (ZkPublicInputName::CredentialBinding, credential_binding),
        (ZkPublicInputName::ClaimNameHash, [15_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::ValueLength,
            &1_u32.to_be_bytes(),
        )?;
        let mut claim_value = [0_u8; 64];
        claim_value[0] = 5;
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::Value,
            &claim_value,
        )?;
    }
    ZkPublicInputs::try_from_bytes(bytes)
}

fn public_inputs_for(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
    expiry_unix: u64,
) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::Challenge,
        &binding.nonce_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::AudienceHash,
        &binding.audience_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &expiry_unix.to_be_bytes(),
    )?;
    for (name, value) in [
        (
            ZkPublicInputName::TransactionDataHash,
            binding.transaction_data_public_input(),
        ),
        (ZkPublicInputName::SessionBinding, [12_u8; 32]),
        (ZkPublicInputName::EnvelopeBinding, [13_u8; 32]),
        (ZkPublicInputName::CredentialBinding, [14_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::ValueLength,
            &1_u32.to_be_bytes(),
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::Value)
    {
        let mut claim_value = [0_u8; 64];
        claim_value[0] = 5;
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::Value,
            &claim_value,
        )?;
    }
    ZkPublicInputs::try_from_bytes(bytes)
}

fn write_public_input(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

fn request_error_for(
    bundle: &ZkClaimProofBundle,
    expected_binding: ZkSessionBinding,
    trusted_issuers: &[ZkIssuerPublicKey],
    verification_time_unix: u64,
) -> Result<ZkErrorReason, ZkError> {
    ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        bundle,
        ZkProofSuite::PRODUCTION,
        expected_binding,
        trusted_issuers,
        verification_time_unix,
    )
    .err()
    .map(|error| error.reason())
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))
}

struct AcceptingBundleVerifier {
    calls: AtomicU32,
}

impl AcceptingBundleVerifier {
    const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl ZkPresentationBoundClaimBundleVerifier for AcceptingBundleVerifier {
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        let _previous = self.calls.fetch_add(1, Ordering::Relaxed);
        for stage_proof in request.bundle().stage_proofs() {
            let expected = [stage_proof.stage().index().saturating_add(1)];
            if stage_proof.proof().proof_bytes() != expected.as_slice() {
                return Err(ZkError::new(ZkErrorReason::InvalidProof));
            }
        }
        Ok(())
    }
}

#[test]
fn different_verified_session_links_fail_closed() -> Result<(), ZkError> {
    let left = ZkPresentationBoundClaimStatement::from_claimed(
        claimed_statement(issuer(1), None)?,
        [4; 32],
    );
    let right = ZkPresentationBoundClaimStatement::from_claimed(
        claimed_statement(issuer(1), None)?,
        [5; 32],
    );

    let error = left
        .require_same_session_link(&right)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn different_verified_credential_bindings_fail_closed() -> Result<(), ZkError> {
    let left = ZkPresentationBoundClaimStatement::from_claimed(
        claimed_statement(issuer(1), None)?,
        [4; 32],
    );
    let mut value = [0_u8; 64];
    value[0] = 9;
    let right_statement =
        ZkClaimedStatement::try_from_parts(issuer(1), None, [9; 32], [3; 32], value, 1, 42)?;
    let right = ZkPresentationBoundClaimStatement::from_claimed(right_statement, [4; 32]);

    let error = left
        .require_same_credential_binding(&right)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn verify_request_rejects_policy_failures_before_backend() -> Result<(), ZkError> {
    let bundle = bundle_with_expiry(1_060)?;
    let trusted_issuer = bundle_issuer();

    assert_eq!(
        request_error_for(&bundle, binding(12), &[trusted_issuer], 1_000)?,
        ZkErrorReason::BindingMismatch
    );
    let mut zero_nonce = binding(11);
    zero_nonce.nonce_hash = [0_u8; 32];
    assert_eq!(
        request_error_for(&bundle, zero_nonce, &[trusted_issuer], 1_000)?,
        ZkErrorReason::BindingMismatch
    );
    let mut wrong_transaction = binding(11);
    wrong_transaction.transaction_data_hash = Some([22_u8; 32]);
    assert_eq!(
        request_error_for(&bundle, wrong_transaction, &[trusted_issuer], 1_000)?,
        ZkErrorReason::BindingMismatch
    );
    let mut absent_transaction = binding(11);
    absent_transaction.transaction_data_hash = None;
    assert_eq!(
        request_error_for(&bundle, absent_transaction, &[trusted_issuer], 1_000)?,
        ZkErrorReason::BindingMismatch
    );
    let mut sentinel_transaction = binding(11);
    sentinel_transaction.transaction_data_hash = Some(crate::proofs::ABSENT_TRANSACTION_DATA_HASH);
    assert_eq!(
        request_error_for(&bundle, sentinel_transaction, &[trusted_issuer], 1_000)?,
        ZkErrorReason::BindingMismatch
    );
    assert_eq!(
        request_error_for(&bundle, binding(11), &[trusted_issuer], 0)?,
        ZkErrorReason::PresentationExpired
    );
    assert_eq!(
        request_error_for(&bundle, binding(11), &[issuer(7)], 1_000)?,
        ZkErrorReason::UntrustedIssuer
    );
    assert_eq!(
        request_error_for(&bundle, binding(11), &[trusted_issuer], 1_060)?,
        ZkErrorReason::PresentationExpired
    );

    let too_far = 1_000_u64
        .checked_add(MAX_PRESENTATION_LIFETIME_SECONDS)
        .and_then(|value| value.checked_add(1))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let too_far_bundle = bundle_with_expiry(too_far)?;
    assert_eq!(
        request_error_for(&too_far_bundle, binding(11), &[trusted_issuer], 1_000)?,
        ZkErrorReason::PresentationExpiryTooFar
    );
    let at_limit = 1_000_u64
        .checked_add(MAX_PRESENTATION_LIFETIME_SECONDS)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let at_limit_bundle = bundle_with_expiry(at_limit)?;
    ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &at_limit_bundle,
        ZkProofSuite::PRODUCTION,
        binding(11),
        &[trusted_issuer],
        1_000,
    )?;
    Ok(())
}

#[test]
fn same_persona_session_link_is_not_named_same_identity() -> Result<(), ZkError> {
    let persona = Some(crate::keys::ZkPersonaPublicKey::from(
        crate::keys::ZkP256PublicKey::from(issuer(30)),
    ));
    let left = ZkPresentationBoundClaimStatement::from_claimed(
        claimed_statement(issuer(10), persona)?,
        [6; 32],
    );
    let right = ZkPresentationBoundClaimStatement::from_claimed(
        claimed_statement(issuer(20), persona)?,
        [6; 32],
    );

    left.require_same_session_link(&right)?;
    assert_ne!(left.issuer(), right.issuer());
    assert_eq!(left.persona(), right.persona());
    assert_eq!(
        left.session_link_commitment(),
        right.session_link_commitment()
    );
    Ok(())
}

#[test]
fn complete_private_persona_bundles_can_require_same_verified_session_link() -> Result<(), ZkError>
{
    let session_binding = binding(31);
    let first_issuer = issuer(10);
    let second_issuer = issuer(20);
    let persona = issuer(80);
    let session_link = [90_u8; 32];
    let first_bundle =
        private_persona_bundle(session_binding, first_issuer, persona, session_link, 1_060)?;
    let second_bundle =
        private_persona_bundle(session_binding, second_issuer, persona, session_link, 1_060)?;
    let trusted_issuers = [first_issuer, second_issuer];
    let verifier = AcceptingBundleVerifier::new();

    let first = verify_presentation_bound_claim_bundle_with(
        &verifier,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &first_bundle,
            ZkProofSuite::PRODUCTION,
            session_binding,
            &trusted_issuers,
            1_000,
        )?,
    )?;
    let second = verify_presentation_bound_claim_bundle_with(
        &verifier,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &second_bundle,
            ZkProofSuite::PRODUCTION,
            session_binding,
            &trusted_issuers,
            1_000,
        )?,
    )?;

    first
        .statement()
        .require_same_session_link(second.statement())?;
    first
        .statement()
        .require_same_credential_binding(second.statement())?;
    assert_ne!(first.statement().issuer(), second.statement().issuer());
    assert_eq!(first.statement().persona(), None);
    assert_eq!(second.statement().persona(), None);
    assert_eq!(first.statement().session_link_commitment(), session_link);
    assert_eq!(second.statement().session_link_commitment(), session_link);
    assert_eq!(verifier.calls(), 2);
    Ok(())
}

#[test]
fn complete_private_persona_bundles_can_reject_changed_credential_binding() -> Result<(), ZkError> {
    let session_binding = binding(31);
    let first_issuer = issuer(10);
    let second_issuer = issuer(20);
    let persona = issuer(80);
    let trusted_issuers = [first_issuer, second_issuer];
    let first_bundle = private_persona_bundle_with_credential_binding(
        session_binding,
        first_issuer,
        persona,
        [90_u8; 32],
        [14_u8; 32],
        1_060,
    )?;
    let second_bundle = private_persona_bundle_with_credential_binding(
        session_binding,
        second_issuer,
        persona,
        [90_u8; 32],
        [15_u8; 32],
        1_060,
    )?;
    let verifier = AcceptingBundleVerifier::new();
    let first = verify_presentation_bound_claim_bundle_with(
        &verifier,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &first_bundle,
            ZkProofSuite::PRODUCTION,
            session_binding,
            &trusted_issuers,
            1_000,
        )?,
    )?;
    let second = verify_presentation_bound_claim_bundle_with(
        &verifier,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &second_bundle,
            ZkProofSuite::PRODUCTION,
            session_binding,
            &trusted_issuers,
            1_000,
        )?,
    )?;

    first
        .statement()
        .require_same_session_link(second.statement())?;
    let error = first
        .statement()
        .require_same_credential_binding(second.statement())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    assert_eq!(verifier.calls(), 2);
    Ok(())
}

#[test]
fn complete_private_persona_bundles_reject_changed_session_link() -> Result<(), ZkError> {
    let session_binding = binding(31);
    let first_issuer = issuer(10);
    let second_issuer = issuer(20);
    let persona = issuer(80);
    let trusted_issuers = [first_issuer, second_issuer];
    let first_bundle =
        private_persona_bundle(session_binding, first_issuer, persona, [90_u8; 32], 1_060)?;
    let second_bundle =
        private_persona_bundle(session_binding, second_issuer, persona, [91_u8; 32], 1_060)?;
    let verifier = AcceptingBundleVerifier::new();
    let first = verify_presentation_bound_claim_bundle_with(
        &verifier,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &first_bundle,
            ZkProofSuite::PRODUCTION,
            session_binding,
            &trusted_issuers,
            1_000,
        )?,
    )?;
    let second = verify_presentation_bound_claim_bundle_with(
        &verifier,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &second_bundle,
            ZkProofSuite::PRODUCTION,
            session_binding,
            &trusted_issuers,
            1_000,
        )?,
    )?;

    let error = first
        .statement()
        .require_same_session_link(second.statement())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    assert_eq!(verifier.calls(), 2);
    Ok(())
}

#[test]
fn complete_private_persona_bundle_rejects_changed_active_session_before_verifier(
) -> Result<(), ZkError> {
    let session_binding = binding(31);
    let credential_issuer = issuer(10);
    let persona = issuer(80);
    let bundle = private_persona_bundle(
        session_binding,
        credential_issuer,
        persona,
        [90_u8; 32],
        1_060,
    )?;
    let verifier = AcceptingBundleVerifier::new();

    let error = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        ZkProofSuite::PRODUCTION,
        binding(32),
        &[credential_issuer],
        1_000,
    )
    .err()
    .map(|error| error.reason())
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error, ZkErrorReason::BindingMismatch);
    assert_eq!(verifier.calls(), 0);
    Ok(())
}

#[test]
fn presentation_evidence_rejects_each_changed_request_binding() -> Result<(), ZkError> {
    let bundle = bundle_with_expiry(1_060)?;
    for expected in [
        ZkSessionBinding {
            nonce_hash: [91; 32],
            ..binding(11)
        },
        ZkSessionBinding {
            audience_hash: [92; 32],
            ..binding(11)
        },
        ZkSessionBinding {
            transaction_data_hash: Some([93; 32]),
            ..binding(11)
        },
    ] {
        assert_eq!(
            request_error_for(&bundle, expected, &[bundle_issuer()], 1_000)?,
            ZkErrorReason::BindingMismatch,
        );
    }
    Ok(())
}

#[test]
fn presentation_verification_is_stateless_within_the_same_session() -> Result<(), ZkError> {
    let bundle = bundle_with_expiry(1_060)?;
    let issuers = [bundle_issuer()];
    let request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        &bundle,
        ZkProofSuite::PRODUCTION,
        binding(11),
        &issuers,
        1_000,
    )?;
    let verifier = AcceptingBundleVerifier::new();
    // Proof verification cannot consume application sessions. The protocol
    // must reject the second acceptance using its atomic durable session store.
    let first = verify_presentation_bound_claim_bundle_with(&verifier, request)?;
    let second = verify_presentation_bound_claim_bundle_with(&verifier, request)?;
    assert_eq!(first, second);
    Ok(())
}
