// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::PresentationValue;
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, ResponseValidationOptions, SessionRecord,
    VerifierErrorReason, ZkCommonCredentialRootVerificationPolicy, ZkHolderBindingVerifier,
    ZkVerificationRequirements,
};
use reallyme_zk_api::keys::ZkIssuerPublicKey;
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};

use crate::{
    artifacts::StageResolver, constants::COMMON_CREDENTIAL_ROOT_QUERY,
    direct_post::authorization_response, error::HarnessError, openid::expect_verifier_reason,
};

pub(crate) fn expect_common_credential_root_policy_rejects(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    trusted_issuers: &[ZkIssuerPublicKey],
    policy: ZkCommonCredentialRootVerificationPolicy<'_>,
    session: &SessionRecord,
    value: &PresentationValue,
    verification_time_unix: u64,
    expected_reason: VerifierErrorReason,
) -> Result<(), HarnessError> {
    let rejected_verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        provider,
        trusted_issuers,
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: true,
        },
        provider,
        policy,
    );
    let rejected = diagnose_authorization_response_with_options(
        session,
        &authorization_response([(COMMON_CREDENTIAL_ROOT_QUERY, value.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&rejected_verifier),
        },
    )
    .map_err(HarnessError::from);
    expect_verifier_reason(rejected, expected_reason)
}
