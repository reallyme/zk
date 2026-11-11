// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_types::{PresentationValue, TransactionDataHashAlgorithm};
use reallyme_openid4vp_verifier::{
    TransactionDataBinding, VerifierErrorReason, ZkHolderBindingVerifier,
};

use crate::constants::{QUERY_A, QUERY_B};
use crate::error::HarnessError;
use crate::openid::{
    expect_verifier_reason, tamper_first_stage_proof, verify_response, verify_response_with_session,
};

pub(crate) fn verify_negative_bindings(
    verifier: &ZkHolderBindingVerifier<'_>,
    bundles: [&reallyme_zk_api::claim_bundle::ZkClaimProofBundle; 2],
    values: [PresentationValue; 2],
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    expect_verifier_reason(
        verify_response_with_session(
            verifier,
            [(bundles[0], QUERY_A), (bundles[1], QUERY_B)],
            [(QUERY_A, values[0].clone()), (QUERY_B, values[1].clone())],
            verification_time_unix,
            "wrong-linked-private-persona-openid4vp-nonce-v1",
            crate::constants::VERIFIER_ORIGIN,
            Vec::new(),
        ),
        VerifierErrorReason::InvalidZkPresentation,
    )?;
    expect_verifier_reason(
        verify_response_with_session(
            verifier,
            [(bundles[0], QUERY_A), (bundles[1], QUERY_B)],
            [(QUERY_A, values[0].clone()), (QUERY_B, values[1].clone())],
            verification_time_unix,
            crate::constants::REQUEST_NONCE,
            "https://attacker.example",
            Vec::new(),
        ),
        VerifierErrorReason::InvalidZkPresentation,
    )?;
    expect_verifier_reason(
        verify_response_with_session(
            verifier,
            [(bundles[0], QUERY_A), (bundles[1], QUERY_B)],
            [(QUERY_A, values[0].clone()), (QUERY_B, values[1].clone())],
            verification_time_unix,
            crate::constants::REQUEST_NONCE,
            crate::constants::VERIFIER_ORIGIN,
            vec![TransactionDataBinding {
                query_id: QueryId::parse(QUERY_A)?,
                algorithm: TransactionDataHashAlgorithm::Sha256,
                digest: [9_u8; 32],
            }],
        ),
        VerifierErrorReason::InvalidZkPresentation,
    )?;
    expect_verifier_reason(
        verify_response(
            verifier,
            [(bundles[0], QUERY_A), (bundles[1], QUERY_B)],
            [
                (QUERY_A, tamper_first_stage_proof(values[0].clone())?),
                (QUERY_B, values[1].clone()),
            ],
            verification_time_unix,
        ),
        VerifierErrorReason::InvalidZkPresentation,
    )
}
