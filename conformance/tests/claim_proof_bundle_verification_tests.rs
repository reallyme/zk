// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use core::sync::atomic::{AtomicU32, Ordering};

use buffa::Message;
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleStage,
        ZkClaimProofBundleStageProof, ZkPresentationBoundClaimBundleVerifier,
        ZkPresentationBoundClaimBundleVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_conformance::{
    run_claim_proof_bundle_verification_vectors, ConformanceErrorReason,
    VerificationConformanceSummary,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{self as pb, ZkVerificationVectorSet};
use reallyme_zk_proto_codec::{
    release::ReleaseArtifactPin,
    verification_vector::{
        encode_claim_proof_bundle_verification_vector_set, ClaimProofBundleVerificationVectorInput,
    },
};

const NONCE: [u8; 32] = [11; 32];
const AUDIENCE: [u8; 32] = [22; 32];

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: NONCE,
        audience_hash: AUDIENCE,
        transaction_data_hash: None,
    }
}

fn public_inputs(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
) -> Result<ZkPublicInputs, ZkError> {
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(descriptor.encoded_len()?)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    encoded.resize(descriptor.encoded_len()?, 0);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&NONCE);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&AUDIENCE);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    for (name, value) in [
        (ZkPublicInputName::IssuerPublicKeyX, [21; 32]),
        (ZkPublicInputName::IssuerPublicKeyY, [22; 32]),
        (ZkPublicInputName::ClaimNameHash, [25; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            encoded
                .get_mut(descriptor.field_range(name)?)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
                .copy_from_slice(&value);
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        encoded
            .get_mut(descriptor.field_range(ZkPublicInputName::ValueLength)?)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
            .copy_from_slice(&1_u32.to_be_bytes());
        let value = encoded
            .get_mut(descriptor.field_range(ZkPublicInputName::Value)?)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        value[0] = 26;
    }
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::ExpiryUnix)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&42_u64.to_be_bytes());
    ZkPublicInputs::try_from_bytes(encoded)
}

fn vector_bytes() -> Result<Vec<u8>, ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let mut stage_proofs = Vec::new();
    let mut manifest_pins = Vec::new();
    stage_proofs
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    manifest_pins
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;

    for stage in ZkClaimProofBundleStage::ALL {
        let marker = stage
            .index()
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let manifest_digest = ZkArtifactManifestDigest::from_bytes([marker; 32]);
        let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, *stage);
        let proof = ZkProof::try_from_exact_parts(
            bundle_kind.circuit_id(),
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            manifest_digest,
            vec![31, stage.index(), 33],
            public_inputs(bundle_kind, credential_hash_algorithm, *stage)?,
        )?;
        stage_proofs.push(ZkClaimProofBundleStageProof::try_from_parts(
            bundle_kind,
            *stage,
            proof,
        )?);
        manifest_pins.push(ReleaseArtifactPin::try_new(
            bundle_kind,
            *stage,
            circuit_ref,
            manifest_digest,
        )?);
    }

    let claim_proof_bundle =
        ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stage_proofs)?;
    let manifest_pins: [ReleaseArtifactPin; 4] = manifest_pins
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let input = ClaimProofBundleVerificationVectorInput::try_new(
        bundle_kind,
        credential_hash_algorithm,
        &claim_proof_bundle,
        manifest_pins,
    )?;
    Ok(encode_claim_proof_bundle_verification_vector_set(input)?.to_vec())
}

struct ExactVerifier {
    calls: AtomicU32,
}

struct AcceptAllVerifier {
    calls: AtomicU32,
}

impl ExactVerifier {
    const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
        }
    }
}

impl AcceptAllVerifier {
    const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
        }
    }
}

impl ZkPresentationBoundClaimBundleVerifier for ExactVerifier {
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        let _previous = self.calls.fetch_add(1, Ordering::Relaxed);
        for stage_proof in request.bundle().stage_proofs() {
            request.expected_binding().decode_and_validate(
                stage_proof.proof().circuit_ref(),
                stage_proof.proof().public_inputs(),
            )?;
            let expected_inputs = public_inputs(
                ZkClaimProofBundleKind::CredentialSubjectClaimV1,
                ZkCredentialHashAlgorithm::Sha256,
                stage_proof.stage(),
            )?;
            if stage_proof.proof().public_inputs().as_bytes() != expected_inputs.as_bytes() {
                return Err(ZkError::new(ZkErrorReason::BindingMismatch));
            }
            let marker = stage_proof
                .stage()
                .index()
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            if stage_proof.proof().artifact_identity()
                != reallyme_zk_api::artifacts::ZkArtifactIdentity::from(
                    ZkArtifactManifestDigest::from_bytes([marker; 32]),
                )
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            let expected_proof = [31, stage_proof.stage().index(), 33];
            if stage_proof.proof().proof_bytes() != expected_proof.as_slice() {
                return Err(ZkError::new(ZkErrorReason::InvalidProof));
            }
        }
        let statement = request.bundle().decode_claimed_statement()?;
        if !request.trusted_issuers().contains(&statement.issuer()) {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        Ok(())
    }
}

impl ZkPresentationBoundClaimBundleVerifier for AcceptAllVerifier {
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        _request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        let _previous = self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn every_bundle_case_matches_boundary_or_provider_result() -> Result<(), ZkError> {
    let bytes = vector_bytes()?;
    let verifier = ExactVerifier::new();
    let summary = run_claim_proof_bundle_verification_vectors(&bytes, &verifier)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(
        summary,
        VerificationConformanceSummary {
            total_cases: 18,
            provider_cases: 4,
            policy_rejections: 2,
            boundary_rejections: 12,
        }
    );
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 4);
    Ok(())
}

#[test]
fn malformed_vector_set_never_reaches_provider() {
    let verifier = ExactVerifier::new();
    let reason = run_claim_proof_bundle_verification_vectors(&[0xff], &verifier)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ConformanceErrorReason::InvalidVectorSet(
            ZkErrorReason::MalformedProtobuf
        ))
    );
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn provider_cannot_forge_verified_result_metadata() -> Result<(), ZkError> {
    let bytes = vector_bytes()?;
    let verifier = ExactVerifier::new();
    let summary = run_claim_proof_bundle_verification_vectors(&bytes, &verifier)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(summary.total_cases, 18);
    Ok(())
}

#[test]
fn expected_report_binds_session_link_and_credential_binding() -> Result<(), ZkError> {
    let bytes = vector_bytes()?;
    let mut decoded = ZkVerificationVectorSet::decode(&mut bytes.as_slice())
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let response = decoded
        .vectors
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
        .expected_response
        .get_or_insert_default();
    let Some(pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(result)) =
        response.outcome.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    };
    let Some(
        pb::__buffa::oneof::zk_provider_operation_result::Result::ClaimProofBundleVerification(
            verification,
        ),
    ) = result.result.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    };
    let statement = verification.statement.get_or_insert_default();
    statement.session_link_commitment[0] ^= 1;

    let verifier = ExactVerifier::new();
    let reason = run_claim_proof_bundle_verification_vectors(&decoded.encode_to_vec(), &verifier)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ConformanceErrorReason::VerificationMismatch));
    Ok(())
}

#[test]
fn accept_all_verifier_is_not_conformance_evidence_for_provider_reaching_negatives(
) -> Result<(), ZkError> {
    let bytes = vector_bytes()?;
    let verifier = AcceptAllVerifier::new();
    let reason = run_claim_proof_bundle_verification_vectors(&bytes, &verifier)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ConformanceErrorReason::UnexpectedSuccess));
    assert_ne!(verifier.calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn omitted_or_reordered_mutation_catalog_is_not_conformance_evidence() -> Result<(), ZkError> {
    let bytes = vector_bytes()?;
    let decoded = ZkVerificationVectorSet::decode(&mut bytes.as_slice())
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;

    let mut omitted = decoded.clone();
    let _removed = omitted.vectors.pop();
    let verifier = ExactVerifier::new();
    assert_eq!(
        run_claim_proof_bundle_verification_vectors(&omitted.encode_to_vec(), &verifier)
            .err()
            .map(|error| error.reason()),
        Some(ConformanceErrorReason::IncompleteVectorSet)
    );

    let mut reordered = decoded;
    reordered.vectors.swap(0, 1);
    assert_eq!(
        run_claim_proof_bundle_verification_vectors(&reordered.encode_to_vec(), &verifier)
            .err()
            .map(|error| error.reason()),
        Some(ConformanceErrorReason::InvalidVectorSet(
            ZkErrorReason::InvalidClaimProofBundle
        ))
    );
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
    Ok(())
}
