// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkCommonCredentialRootClaimExpectation as ProtoCommonCredentialRootClaimExpectation;

use super::{canonical_admission::admit_join_policy, issuer, join_policy};

#[test]
fn common_credential_root_join_policy_admits_two_verifier_claims() -> Result<(), ZkError> {
    let owner = admit_join_policy(join_policy())?;
    let borrowed = owner.as_borrowed(
        reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode::PrivatePersona,
    );

    assert_eq!(borrowed.challenge, [1; 32]);
    assert_eq!(borrowed.status_validation_time_unix, 1);
    assert_eq!(borrowed.status_validation_max_age_seconds, 120);
    assert_eq!(borrowed.claims[0].value, &[51, 52]);
    assert_eq!(borrowed.claims[1].claim_name_hash, [71; 32]);
    Ok(())
}

#[test]
fn common_credential_root_join_policy_rejects_missing_status_validation_time() {
    let mut policy = join_policy();
    policy.status_validation_time_unix = 0;

    assert!(matches!(
        admit_join_policy(policy),
        Err(error) if error.reason() == ZkErrorReason::PresentationExpired
    ));
}

#[test]
fn common_credential_root_join_policy_rejects_holder_sized_claim_mismatch() {
    let mut policy = join_policy();
    policy.claims[0].claim_value_length = 64;

    assert!(matches!(
        admit_join_policy(policy),
        Err(error) if error.reason() == ZkErrorReason::ClaimPayloadTooLarge
    ));
}

#[test]
fn common_credential_root_join_policy_rejects_second_claim_length_mismatch() {
    let mut policy = join_policy();
    policy.claims[1].claim_value_length = 64;

    assert!(matches!(
        admit_join_policy(policy),
        Err(error) if error.reason() == ZkErrorReason::ClaimPayloadTooLarge
    ));
}

#[test]
fn common_credential_root_join_policy_rejects_extra_claim() {
    let mut policy = join_policy();
    policy
        .claims
        .push(ProtoCommonCredentialRootClaimExpectation {
            issuer: MessageField::some(issuer(91)),
            claim_name_hash: vec![92; 32],
            claim_value: vec![93],
            claim_value_length: 1,
            __buffa_unknown_fields: Default::default(),
        });

    assert!(matches!(
        admit_join_policy(policy),
        Err(error) if error.reason() == ZkErrorReason::InvalidClaimProofBundle
    ));
}
