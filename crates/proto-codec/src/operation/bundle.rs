// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    claim_bundle::{ZkClaimProofBundleStage, ZkClaimProofBundleWitness, MAX_TRUSTED_ISSUERS},
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusFeed,
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::binding::session_binding_from_proto_message;
use crate::domain::{
    bundle_kind_from_proto, credential_hash_algorithm_from_proto, proof_suite_from_proto,
};
use crate::issuer_status::purpose_from_proto;
use crate::proof::claim_proof_bundle_from_proto;
use crate::status_qualified::status_qualified_claim_proof_bundle_from_proto;

use super::native_handle::ZkNativeStageWitnessHandle;
use super::secret_cleanup::{
    BundleProveOperationGuard, ClaimProofBundleWitnessGuard,
    RetainedClaimProofBundleProveOperationGuard, RetainedClaimProofBundleWitnessGuard,
    StageWitnessHandlesGuard, StageWitnessesGuard,
};
use super::{stage_witness_handle_from_proto, witness_from_proto, ZkProviderOperation};

pub(super) fn prove_retained_claim_proof_bundle_from_proto(
    operation: pb::ZkRetainedClaimProofBundleProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = RetainedClaimProofBundleProveOperationGuard::new(operation);
    let profile = bundle_kind_from_proto(operation.bundle_kind())?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(operation.credential_hash_algorithm())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    let witness_bundle = operation
        .take_witness_bundle()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let mut witness_bundle = RetainedClaimProofBundleWitnessGuard::new(witness_bundle);
    let witness_profile = bundle_kind_from_proto(witness_bundle.bundle_kind())?;
    let witness_credential_hash_algorithm =
        credential_hash_algorithm_from_proto(witness_bundle.credential_hash_algorithm())?;
    if witness_profile != profile || witness_credential_hash_algorithm != credential_hash_algorithm
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let mut witness_handles = Vec::new();
    witness_handles
        .try_reserve_exact(witness_bundle.stage_witness_handle_count())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut remaining_handles =
        StageWitnessHandlesGuard::new(witness_bundle.take_stage_witness_handles());
    let mut index = 0_usize;
    while !remaining_handles.is_empty() {
        let stage = ZkClaimProofBundleStage::ALL
            .get(index)
            .ok_or(ZkError::new(ZkErrorReason::DuplicateStage))?;
        let handle = remaining_handles
            .take_next()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        witness_handles.push(stage_witness_handle_from_proto(
            handle,
            profile.source_ref(credential_hash_algorithm, *stage),
        )?);
        index = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    if witness_handles.len() != ZkClaimProofBundleStage::ALL.len() {
        return Err(ZkError::new(ZkErrorReason::MissingStage));
    }
    validate_unique_witness_handle_ids(&witness_handles)?;
    let session_binding = session_binding_from_proto_message(operation.take_session_binding())?;

    for stage in ZkClaimProofBundleStage::ALL {
        session_binding
            .validate_for_circuit(profile.source_ref(credential_hash_algorithm, *stage))?;
    }

    Ok(ZkProviderOperation::ProveRetainedClaimProofBundle {
        bundle_kind: profile,
        credential_hash_algorithm,
        proof_suite,
        witness_handles,
        session_binding,
    })
}

fn validate_unique_witness_handle_ids(
    handles: &[ZkNativeStageWitnessHandle],
) -> Result<(), ZkError> {
    let mut index = 0_usize;
    while index < handles.len() {
        let mut comparison = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        while comparison < handles.len() {
            if handles[index].native_handle_id == handles[comparison].native_handle_id {
                return Err(ZkError::new(ZkErrorReason::DuplicateStage));
            }
            comparison = comparison
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
        index = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    Ok(())
}

pub(super) fn prove_claim_proof_bundle_from_proto(
    operation: pb::ZkClaimProofBundleProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = BundleProveOperationGuard::new(operation);
    let profile = bundle_kind_from_proto(operation.bundle_kind())?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(operation.credential_hash_algorithm())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    let witness_bundle = operation
        .take_witness_bundle()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let mut witness_bundle = ClaimProofBundleWitnessGuard::new(witness_bundle);
    let witness_profile = bundle_kind_from_proto(witness_bundle.bundle_kind())?;
    let witness_credential_hash_algorithm =
        credential_hash_algorithm_from_proto(witness_bundle.credential_hash_algorithm())?;
    if witness_profile != profile || witness_credential_hash_algorithm != credential_hash_algorithm
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let mut stage_witnesses = Vec::new();
    stage_witnesses
        .try_reserve_exact(witness_bundle.stage_witness_count())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut remaining_witnesses = StageWitnessesGuard::new(witness_bundle.take_stage_witnesses());
    let mut index = 0_usize;
    while !remaining_witnesses.is_empty() {
        let stage = ZkClaimProofBundleStage::ALL
            .get(index)
            .ok_or(ZkError::new(ZkErrorReason::DuplicateStage))?;
        let witness = remaining_witnesses
            .take_next()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        stage_witnesses.push(witness_from_proto(
            witness,
            profile.source_ref(credential_hash_algorithm, *stage),
        )?);
        index = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    let witness_bundle = ZkClaimProofBundleWitness::try_from_stage_witnesses(
        profile,
        credential_hash_algorithm,
        stage_witnesses,
    )?;
    let session_binding = session_binding_from_proto_message(operation.take_session_binding())?;

    for stage in ZkClaimProofBundleStage::ALL {
        session_binding
            .validate_for_circuit(profile.source_ref(credential_hash_algorithm, *stage))?;
    }

    Ok(ZkProviderOperation::ProveClaimProofBundle {
        bundle_kind: profile,
        credential_hash_algorithm,
        proof_suite,
        witness_bundle,
        session_binding,
    })
}

pub(super) fn verify_claim_proof_bundle_from_proto(
    mut operation: pb::ZkClaimProofBundleVerifyOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let claim_proof_bundle = operation
        .claim_proof_bundle
        .take()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
    let claim_proof_bundle = claim_proof_bundle_from_proto(claim_proof_bundle)?;
    let expected_proof_suite = proof_suite_from_proto(operation.expected_proof_suite)?;
    if claim_proof_bundle.proof_suite() != expected_proof_suite {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    let expected_binding = session_binding_from_proto_message(operation.expected_binding)?;
    if claim_proof_bundle.session_binding() != expected_binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let trusted_issuers = trusted_issuers_from_proto(operation.trusted_issuers)?;
    if operation.credential_status_checked_at_unix != 0 {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }

    Ok(ZkProviderOperation::VerifyClaimProofBundle {
        claim_proof_bundle,
        expected_proof_suite,
        expected_binding,
        trusted_issuers,
        verification_time_unix: operation.verification_time_unix,
    })
}

/// Largest issuer status list the status circuit admits.
const MAX_ISSUER_STATUS_LENGTH: u64 = 1_000_000;
const ISSUER_STATUS_FIELD_BYTES: usize = 32;

pub(super) fn verify_status_qualified_claim_proof_bundle_from_proto(
    mut operation: pb::ZkStatusQualifiedClaimProofBundleVerifyOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let bundle = operation
        .status_qualified_claim_proof_bundle
        .take()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
    let bundle = status_qualified_claim_proof_bundle_from_proto(bundle)?;
    let expected_proof_suite = proof_suite_from_proto(operation.expected_proof_suite)?;
    // The fifth proof exists only for the production suite; the joined bundle
    // has already required both parts to share one suite.
    expected_proof_suite.require_production()?;
    if bundle.claim_proof_bundle().proof_suite() != expected_proof_suite {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    let expected_binding = session_binding_from_proto_message(operation.expected_binding)?;
    if bundle.claim_proof_bundle().session_binding() != expected_binding {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let trusted_issuers = trusted_issuers_from_proto(operation.trusted_issuers)?;
    let current_issuer_status = issuer_status_feed_from_proto(
        operation
            .current_issuer_status
            .take()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
    )?;
    let expected_issuer = issuer_public_key_from_proto(
        operation
            .expected_issuer
            .take()
            .ok_or(ZkError::new(ZkErrorReason::UntrustedIssuer))?,
    )?;
    if !trusted_issuers.contains(&expected_issuer) {
        return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
    }
    if bundle
        .claim_proof_bundle()
        .decode_claimed_statement()?
        .issuer()
        != expected_issuer
    {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }

    Ok(ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle {
        status_qualified_claim_proof_bundle: Box::new(bundle),
        expected_proof_suite,
        expected_binding,
        trusted_issuers,
        verification_time_unix: operation.verification_time_unix,
        current_issuer_status,
        expected_issuer,
    })
}

/// Admits the verifier-supplied current issuer status list. Every field is
/// required: an absent or all-zero root, list identifier, or URL hash, an
/// empty or oversized list, and an unspecified purpose are rejected so a
/// default-valued message can never stand in for an authenticated list.
fn issuer_status_feed_from_proto(
    feed: pb::ZkCommonCredentialRootIssuerStatusExpectation,
) -> Result<ZkIssuerStatusFeed, ZkError> {
    let root = issuer_status_field(feed.root.as_slice())?;
    let list_id = issuer_status_field(feed.list_id.as_slice())?;
    let url_hash = issuer_status_field(feed.url_hash.as_slice())?;
    if feed.length == 0 || feed.length > MAX_ISSUER_STATUS_LENGTH {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let purpose = purpose_from_proto(feed.purpose)?;
    Ok(ZkIssuerStatusFeed {
        root,
        length: feed.length,
        list_id,
        url_hash,
        purpose,
    })
}

fn issuer_status_field(bytes: &[u8]) -> Result<[u8; ISSUER_STATUS_FIELD_BYTES], ZkError> {
    let field: [u8; ISSUER_STATUS_FIELD_BYTES] = bytes
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if field == [0_u8; ISSUER_STATUS_FIELD_BYTES] {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(field)
}

fn trusted_issuers_from_proto(
    issuers: Vec<pb::ZkP256PublicKey>,
) -> Result<Vec<ZkIssuerPublicKey>, ZkError> {
    validate_trusted_issuer_count(issuers.len())?;
    let mut trusted_issuers = Vec::new();
    trusted_issuers
        .try_reserve_exact(issuers.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for issuer in issuers {
        let issuer = issuer_public_key_from_proto(issuer)?;
        if trusted_issuers.contains(&issuer) {
            return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
        }
        trusted_issuers.push(issuer);
    }
    Ok(trusted_issuers)
}

pub(super) fn validate_trusted_issuer_count(count: usize) -> Result<(), ZkError> {
    if count == 0 {
        return Err(ZkError::new(ZkErrorReason::UntrustedIssuer));
    }
    if count > MAX_TRUSTED_ISSUERS {
        return Err(ZkError::new(ZkErrorReason::PublicKeyTooLarge));
    }
    Ok(())
}

fn issuer_public_key_from_proto(key: pb::ZkP256PublicKey) -> Result<ZkIssuerPublicKey, ZkError> {
    let x: [u8; 32] = key
        .x
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let y: [u8; 32] = key
        .y
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if x == [0_u8; 32] && y == [0_u8; 32] {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(ZkIssuerPublicKey { x, y })
}
