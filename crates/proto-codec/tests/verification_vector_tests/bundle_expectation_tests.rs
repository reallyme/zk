// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    decode_verification_vector_set, pb, success_response, vector_set, Message, Operation, Outcome,
    ProviderResult, ZkError, ZkErrorReason,
};

#[test]
fn positive_bundle_expectations_are_bound_to_nonce_issuer_and_claim() -> Result<(), ZkError> {
    let mutation = pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE;
    let mut wrong_issuer = success_response(true);
    let Some(Outcome::Result(result)) = wrong_issuer.outcome.as_mut() else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    let Some(ProviderResult::ClaimProofBundleVerification(verification)) = result.result.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    let statement = verification.statement.get_or_insert_default();
    statement.issuer.get_or_insert_default().x[0] ^= 1;
    let issuer_reason =
        decode_verification_vector_set(&vector_set(mutation, wrong_issuer, true)?.encode_to_vec())
            .err()
            .map(|error| error.reason());
    assert_eq!(issuer_reason, Some(ZkErrorReason::StageMismatch));

    let mut wrong_claim = success_response(true);
    let Some(Outcome::Result(result)) = wrong_claim.outcome.as_mut() else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    let Some(ProviderResult::ClaimProofBundleVerification(verification)) = result.result.as_mut()
    else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    verification.statement.get_or_insert_default().claim_value[0] ^= 1;
    let claim_reason =
        decode_verification_vector_set(&vector_set(mutation, wrong_claim, true)?.encode_to_vec())
            .err()
            .map(|error| error.reason());
    assert_eq!(claim_reason, Some(ZkErrorReason::StageMismatch));

    let mut wrong_nonce = vector_set(mutation, success_response(true), true)?;
    let operation = wrong_nonce
        .vectors
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
        .base_operation
        .get_or_insert_default();
    let Some(Operation::VerifyClaimProofBundle(bundle)) = operation.operation.as_mut() else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    bundle.expected_binding.get_or_insert_default().nonce_hash[0] ^= 1;
    let nonce_reason = decode_verification_vector_set(&wrong_nonce.encode_to_vec())
        .err()
        .map(|error| error.reason());
    assert_eq!(nonce_reason, Some(ZkErrorReason::BindingMismatch));
    Ok(())
}
