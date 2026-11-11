// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use reallyme_openid4vp_types::{AuthorizationRequestObject, PresentationValue};
use reallyme_openid4vp_verifier::{HolderBindingVerifier, SessionRecord};

use crate::{
    constants::COMMON_CREDENTIAL_ROOT_QUERY,
    direct_post::{
        direct_post_body, expect_runtime_rejects, identity_runtime, product_store,
        request_from_body,
    },
    error::{HarnessError, HarnessPhase},
    openid::tamper_first_stage_proof,
    runtime::SESSION_KEY,
};

pub(super) enum RuntimeAcceptance {
    Initial,
    Second,
}

pub(super) fn expect_runtime_accepts_once(
    request: AuthorizationRequestObject,
    session: SessionRecord,
    verifier: Arc<dyn HolderBindingVerifier>,
    body: Vec<u8>,
    verification_time_unix: u64,
    acceptance: RuntimeAcceptance,
) -> Result<(), HarnessError> {
    let (store, _store_directory) = product_store(request, session).map_err(|error| {
        if matches!(acceptance, RuntimeAcceptance::Second) {
            HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondRuntimeStore)
        } else {
            error
        }
    })?;
    let runtime =
        identity_runtime(store, verifier, verification_time_unix, body.len()).map_err(|_| {
            HarnessError::Phase(match acceptance {
                RuntimeAcceptance::Initial => HarnessPhase::CommonCredentialRootRuntimeSetup,
                RuntimeAcceptance::Second => HarnessPhase::CommonCredentialRootSecondRuntimeSetup,
            })
        })?;
    let accepted = runtime.handle_direct_post(SESSION_KEY, &request_from_body(body.clone()));
    if accepted.status != 200 {
        return Err(HarnessError::Phase(match acceptance {
            RuntimeAcceptance::Initial => HarnessPhase::CommonCredentialRootRuntimeAccept,
            RuntimeAcceptance::Second => HarnessPhase::CommonCredentialRootSecondRuntimeAccept,
        }));
    }
    let replay = runtime.handle_direct_post(SESSION_KEY, &request_from_body(body));
    if replay.status == 200 {
        return Err(match acceptance {
            RuntimeAcceptance::Initial => HarnessError::InvalidPresentationAccepted,
            RuntimeAcceptance::Second => {
                HarnessError::Phase(HarnessPhase::CommonCredentialRootSecondRuntimeReplay)
            }
        });
    }
    Ok(())
}

pub(super) fn expect_invalid_runtime_presentations(
    verifier: Arc<dyn HolderBindingVerifier>,
    session: &SessionRecord,
    value: &PresentationValue,
    body: &[u8],
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    expect_runtime_rejects(
        verifier.clone(),
        session.to_owned(),
        direct_post_body([(
            COMMON_CREDENTIAL_ROOT_QUERY,
            tamper_first_stage_proof(value.to_owned())?,
        )])?,
        verification_time_unix,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootRuntimeTamperedProof))?;
    let mut wrong_session = session.to_owned();
    wrong_session.binding.nonce = "wrong-common-credential-root-direct-post-nonce-v1".to_owned();
    expect_runtime_rejects(
        verifier.clone(),
        wrong_session,
        body.to_vec(),
        verification_time_unix,
    )
    .map_err(|_| HarnessError::Phase(HarnessPhase::CommonCredentialRootRuntimeWrongSession))?;
    Ok(())
}
