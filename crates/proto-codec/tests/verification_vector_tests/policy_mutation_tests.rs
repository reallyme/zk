// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    decode_verification_vector_set, error_response, pb, vector_set, Message, ZkError,
    ZkErrorReason, ZkProviderOperation,
};

#[test]
fn policy_mutations_remain_valid_bundle_operations() -> Result<(), ZkError> {
    let cases = [
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_UNTRUSTED_ISSUER,
            ZkErrorReason::UntrustedIssuer,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_PRESENTATION_EXPIRED,
            ZkErrorReason::PresentationExpired,
        ),
        (
            pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_WRONG_BUNDLE_SESSION_BINDING,
            ZkErrorReason::BindingMismatch,
        ),
    ];
    for (mutation, expected) in cases {
        let encoded = vector_set(mutation, error_response(expected), true)?.encode_to_vec();
        assert!(matches!(
            decode_verification_vector_set(&encoded)?
                .into_vectors()
                .pop()
                .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?
                .execute()?,
            ZkProviderOperation::VerifyClaimProofBundle { .. }
        ));
    }
    Ok(())
}
