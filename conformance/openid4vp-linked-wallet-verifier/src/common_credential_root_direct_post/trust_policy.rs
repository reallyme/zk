// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::PresentationValue;
use reallyme_openid4vp_verifier::{SessionRecord, VerifierErrorReason};
use reallyme_zk_api::{errors::ZkErrorReason, keys::ZkIssuerPublicKey};
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};

use crate::{
    artifacts::StageResolver,
    common_credential_root_issuance::sign_test_status_list,
    error::{HarnessError, HarnessPhase},
};

use super::{
    model::{
        CommonCredentialRootFixture, CommonCredentialRootPolicyOverrides,
        HarnessCommonCredentialRootPresentation,
    },
    policy_rejection::expect_common_credential_root_policy_rejects,
};

pub(super) fn expect_common_credential_root_trust_policy_rejections(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    trusted_issuers: &[ZkIssuerPublicKey],
    fixture: &CommonCredentialRootFixture,
    presentation: &HarnessCommonCredentialRootPresentation,
    session: &SessionRecord,
    value: &PresentationValue,
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    let fresh_until = verification_time_unix
        .checked_add(60)
        .ok_or(HarnessError::InvalidLength)?;
    let mut wrong_status_root = fixture.status_root;
    wrong_status_root[0] ^= 1;
    let wrong_status_policy = fixture.verification_policy_with(
        &presentation.issuer_status_lists,
        verification_time_unix,
        CommonCredentialRootPolicyOverrides {
            status_root: wrong_status_root,
            attestation_signer: fixture.attestation_signer,
            assurance_policy_id: fixture.assurance_policy_id,
            expires_unix: fresh_until,
            policy_build_time_unix: verification_time_unix,
        },
    );
    match wrong_status_policy {
        Err(HarnessError::Verifier(error))
            if error.reason() == VerifierErrorReason::InvalidRootAssuranceStatus => {}
        Err(_) => return Err(HarnessError::InvalidPresentationAccepted),
        Ok(policy) => {
            expect_common_credential_root_policy_rejects(
                provider,
                trusted_issuers,
                policy,
                session,
                value,
                verification_time_unix,
                VerifierErrorReason::InvalidZkPresentation,
            )
            .map_err(|_| {
                HarnessError::Phase(HarnessPhase::CommonCredentialRootWrongStatusPolicy)
            })?;
        }
    }
    let mut wrong_signer = fixture.attestation_signer;
    wrong_signer.x[0] ^= 1;
    let wrong_signer_policy = fixture.verification_policy_with(
        &presentation.issuer_status_lists,
        verification_time_unix,
        CommonCredentialRootPolicyOverrides {
            status_root: fixture.status_root,
            attestation_signer: wrong_signer,
            assurance_policy_id: fixture.assurance_policy_id,
            expires_unix: fresh_until,
            policy_build_time_unix: verification_time_unix,
        },
    )?;
    let mut wrong_assurance_id = fixture.assurance_policy_id;
    wrong_assurance_id[0] ^= 1;
    let wrong_assurance_policy = fixture.verification_policy_with(
        &presentation.issuer_status_lists,
        verification_time_unix,
        CommonCredentialRootPolicyOverrides {
            status_root: fixture.status_root,
            attestation_signer: fixture.attestation_signer,
            assurance_policy_id: wrong_assurance_id,
            expires_unix: fresh_until,
            policy_build_time_unix: verification_time_unix,
        },
    )?;
    let stale_status_policy = fixture.verification_policy_with(
        &presentation.issuer_status_lists,
        verification_time_unix,
        CommonCredentialRootPolicyOverrides {
            status_root: fixture.status_root,
            attestation_signer: fixture.attestation_signer,
            assurance_policy_id: fixture.assurance_policy_id,
            expires_unix: verification_time_unix,
            policy_build_time_unix: verification_time_unix
                .checked_sub(1)
                .ok_or(HarnessError::InvalidLength)?,
        },
    );
    let stale_status_policy = match stale_status_policy {
        Err(HarnessError::Verifier(error))
            if error.reason() == VerifierErrorReason::InvalidRootAssuranceStatus =>
        {
            None
        }
        Err(_) => return Err(HarnessError::InvalidPresentationAccepted),
        Ok(policy) => Some(policy),
    };
    for (rejected_policy, expected_reason, phase) in [
        (
            wrong_signer_policy,
            VerifierErrorReason::InvalidZkPresentation,
            HarnessPhase::CommonCredentialRootWrongSignerPolicy,
        ),
        (
            wrong_assurance_policy,
            VerifierErrorReason::InvalidZkPresentation,
            HarnessPhase::CommonCredentialRootWrongAssurancePolicy,
        ),
    ] {
        expect_common_credential_root_policy_rejects(
            provider,
            trusted_issuers,
            rejected_policy,
            session,
            value,
            verification_time_unix,
            expected_reason,
        )
        .map_err(|_| HarnessError::Phase(phase))?;
    }
    if let Some(rejected_policy) = stale_status_policy {
        match expect_common_credential_root_policy_rejects(
            provider,
            trusted_issuers,
            rejected_policy,
            session,
            value,
            verification_time_unix,
            VerifierErrorReason::InvalidRootAssuranceStatus,
        ) {
            Ok(()) => {}
            Err(HarnessError::Zk(error))
                if error.reason() == ZkErrorReason::PresentationExpired => {}
            Err(_) => {
                return Err(HarnessError::Phase(
                    HarnessPhase::CommonCredentialRootStaleStatusPolicy,
                ))
            }
        }
    }
    // A newer, correctly signed revocation list is authoritative even when
    // the holder's proof was made against an earlier active list. The verifier
    // must reject the old issuer-status proof rather than trusting its bit.
    let mut revoked_lists =
        std::array::from_fn(|index| copy_status_list(&presentation.issuer_status_lists[index]));
    revoked_lists[0].issued_at = revoked_lists[0]
        .issued_at
        .checked_add(1)
        .ok_or(HarnessError::InvalidLength)?;
    *revoked_lists[0]
        .encoded_list
        .get_mut(1)
        .ok_or(HarnessError::InvalidLength)? = 0b0000_0010;
    sign_test_status_list(&mut revoked_lists[0], 11)?;
    let independent_fixture = CommonCredentialRootFixture::read()?;
    let revoked_policy =
        independent_fixture.verification_policy(&revoked_lists, verification_time_unix)?;
    expect_common_credential_root_policy_rejects(
        provider,
        trusted_issuers,
        revoked_policy,
        session,
        value,
        verification_time_unix,
        VerifierErrorReason::InvalidZkPresentation,
    )?;
    Ok(())
}

fn copy_status_list(list: &StatusList) -> StatusList {
    StatusList {
        issuer: list.issuer.clone(),
        purpose: list.purpose,
        issued_at: list.issued_at,
        next_update: list.next_update,
        encoded_list: list.encoded_list.clone(),
        length: list.length,
        list_id: list.list_id,
        signature: StatusListSignature {
            alg: list.signature.alg,
            sig_bytes: list.signature.sig_bytes.clone(),
        },
    }
}
use reallyme_credential_status::{StatusList, StatusListSignature};
