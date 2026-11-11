// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};

use super::{pb, scrub_claim_proof_bundle_verification_response};

#[test]
fn claim_proof_bundle_verification_response_scrub_removes_claim_material() {
    let mut response = pb::ZkProviderOperationResponse {
        request_sha256: vec![1; 32],
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(Box::new(
                pb::ZkProviderOperationResult {
                    result: Some(
                        pb::__buffa::oneof::zk_provider_operation_result::Result::ClaimProofBundleVerification(
                            Box::new(pb::ZkPresentationBoundClaimBundleVerification {
                                bundle_kind: EnumValue::from(
                                    pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                                ),
                                verified_stage_count: 4,
                                proof_suite: EnumValue::from(
                                    pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                                ),
                                statement: MessageField::some(pb::ZkPresentationBoundClaimStatement {
                                    issuer: MessageField::some(pb::ZkP256PublicKey {
                                        x: vec![21; 32],
                                        y: vec![22; 32],
                                        __buffa_unknown_fields: Default::default(),
                                    }),
                                    persona: MessageField::none(),
                                    claim_name_hash: vec![25; 32],
                                    claim_value: vec![26; 64],
                                    claim_value_length: 64,
                                    presentation_expiry_unix: 42,
                                    session_link_commitment: vec![27; 32],
                                    credential_binding: vec![28; 32],
                                    __buffa_unknown_fields: Default::default(),
                                }),
                                __buffa_unknown_fields: Default::default(),
                            }),
                        ),
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };

    scrub_claim_proof_bundle_verification_response(&mut response);

    let outcome = response.outcome.as_ref();
    assert!(matches!(
        outcome,
        Some(pb::zk_provider_operation_response::Outcome::Result(_))
    ));
    let Some(pb::zk_provider_operation_response::Outcome::Result(result)) = outcome else {
        return;
    };
    let result_value = result.result.as_ref();
    assert!(matches!(
        result_value,
        Some(pb::zk_provider_operation_result::Result::ClaimProofBundleVerification(_))
    ));
    let Some(pb::zk_provider_operation_result::Result::ClaimProofBundleVerification(verification)) =
        result_value
    else {
        return;
    };
    let statement = verification.statement.as_option();
    assert!(statement.is_some());
    let Some(statement) = statement else {
        return;
    };
    assert_eq!(statement.claim_name_hash.len(), 32);
    assert_eq!(statement.claim_value.len(), 64);
    assert!(statement.claim_name_hash.iter().all(|byte| *byte == 0));
    assert!(statement.claim_value.iter().all(|byte| *byte == 0));
    assert!(statement
        .session_link_commitment
        .iter()
        .all(|byte| *byte == 0));
    assert!(statement.credential_binding.iter().all(|byte| *byte == 0));
    assert_eq!(statement.claim_value_length, 0);
}
