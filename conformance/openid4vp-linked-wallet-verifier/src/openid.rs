// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_runtime::{
    RuntimeHttpMethod, RuntimeHttpRequest, VerifierHttpEndpoint, VerifierHttpRuntime,
    VerifierRuntimeConfig, VerifierRuntimeService,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, AuthorizationResponse, PresentationValue, ResponseMode,
    ResponseType,
};
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, HolderBindingVerifier, RequestBinding,
    ResponseValidationOptions, SessionRecord, TransactionDataBinding, VerifiedDisclosureSet,
    VerifierErrorReason, ZkHolderBindingVerifier,
};
use reallyme_openid4vp_wallet::{
    prepare_zk_presentation_from_status_qualified_bundle, validate_unsigned_dc_api_request,
    VerifiedPlatformOrigin, WalletInvocationContext,
};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::ZkSessionBinding,
};
use serde_json::{json, Map as JsonMap, Value as JsonValue};

use crate::constants::{REQUEST_NONCE, VERIFIER_ORIGIN};
use crate::direct_post::{DIRECT_POST_CLIENT_ID, DIRECT_POST_RESPONSE_URI};
use crate::error::HarnessError;
use crate::fixture::lower_hex;
use crate::runtime::{FixedClock, InMemorySessionStore, MissingRequestObjectStore, SESSION_KEY};

pub(crate) fn openid_session_binding() -> ZkSessionBinding {
    let binding = reallyme_openid4vp_formats::build_zk_presentation_binding(
        REQUEST_NONCE,
        &format_origin_audience(VERIFIER_ORIGIN),
        None,
    );
    ZkSessionBinding {
        nonce_hash: binding.nonce_hash,
        audience_hash: binding.audience_hash,
        transaction_data_hash: None,
    }
}

pub(crate) fn dc_api_invocation() -> Result<WalletInvocationContext, HarnessError> {
    Ok(WalletInvocationContext::DigitalCredentialsApi(
        VerifiedPlatformOrigin::from_browser_security_context(VERIFIER_ORIGIN.to_owned())?,
    ))
}

pub(crate) fn status_qualified_wallet_value(
    qualified: &reallyme_zk_api::claim_bundle::ZkStatusQualifiedClaimProofBundle,
    query_id: &str,
    invocation: &WalletInvocationContext,
) -> Result<PresentationValue, HarnessError> {
    let query_id = QueryId::parse(query_id)?;
    let request = validate_unsigned_dc_api_request(&request_for_bundles([(
        &query_id,
        qualified.claim_proof_bundle(),
    )])?)?;
    Ok(prepare_zk_presentation_from_status_qualified_bundle(
        &request, invocation, &query_id, qualified,
    )?)
}

pub(crate) fn verify_response<'a>(
    verifier: &ZkHolderBindingVerifier<'_>,
    queries: [(
        &'a reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
        &'a str,
    ); 2],
    presentations: [(&'a str, PresentationValue); 2],
    verification_time_unix: u64,
) -> Result<reallyme_openid4vp_verifier::NonAuthorizingResponseDiagnostics, HarnessError> {
    verify_response_with_session(
        verifier,
        queries,
        presentations,
        verification_time_unix,
        REQUEST_NONCE,
        VERIFIER_ORIGIN,
        Vec::new(),
    )
}

pub(crate) fn verify_response_with_session<'a>(
    verifier: &ZkHolderBindingVerifier<'_>,
    queries: [(
        &'a reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
        &'a str,
    ); 2],
    presentations: [(&'a str, PresentationValue); 2],
    verification_time_unix: u64,
    nonce: &str,
    dc_api_origin: &str,
    transaction_data_bindings: Vec<TransactionDataBinding>,
) -> Result<reallyme_openid4vp_verifier::NonAuthorizingResponseDiagnostics, HarnessError> {
    let request = request_for_bundles([
        (&QueryId::parse(queries[0].1)?, queries[0].0),
        (&QueryId::parse(queries[1].1)?, queries[1].0),
    ])?;
    let mut vp_token = BTreeMap::new();
    for (query_id, value) in presentations {
        vp_token.insert(QueryId::parse(query_id)?, vec![value]);
    }
    let response = AuthorizationResponse {
        vp_token,
        state: None,
    };
    diagnose_authorization_response_with_options(
        &session_record(
            request,
            verification_time_unix,
            nonce,
            dc_api_origin,
            transaction_data_bindings,
            ResponseMode::DcApi,
        )?,
        &response,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(verifier),
        },
    )
    .map_err(HarnessError::from)
}

pub(crate) fn expect_direct_post_rejects_dc_api_bound_presentation<'a>(
    verifier: Arc<dyn HolderBindingVerifier>,
    queries: [(
        &'a reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
        &'a str,
    ); 2],
    presentations: [(&'a str, PresentationValue); 2],
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    let request = direct_post_request_for_bundles([
        (&QueryId::parse(queries[0].1)?, queries[0].0),
        (&QueryId::parse(queries[1].1)?, queries[1].0),
    ])?;
    let session = direct_post_session_record(request, verification_time_unix)?;
    let body = direct_post_body(presentations)?;
    let store = Arc::new(InMemorySessionStore::new(session.clone()));
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_holder_binding_verifier(verifier),
        )),
        store.clone(),
        Arc::new(MissingRequestObjectStore),
        Arc::new(FixedClock {
            now_unix: verification_time_unix,
        }),
    )
    .with_max_direct_post_body_bytes(body.len());
    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: SESSION_KEY,
        },
        &RuntimeHttpRequest {
            method: RuntimeHttpMethod::Post,
            accept: None,
            content_type: Some("application/x-www-form-urlencoded".to_owned()),
            body,
        },
    );
    if response.status != 400 {
        return Err(HarnessError::RuntimeStatus(response.status));
    }
    match store.committed_result() {
        Err(HarnessError::RuntimeCommitMissing) => Ok(()),
        Err(error) => Err(error),
        Ok(_committed) => Err(HarnessError::InvalidPresentationAccepted),
    }
}

pub(crate) fn request_for_bundles<const N: usize>(
    bundles: [(&QueryId, &reallyme_zk_api::claim_bundle::ZkClaimProofBundle); N],
) -> Result<AuthorizationRequestObject, HarnessError> {
    let mut credentials = Vec::new();
    credentials
        .try_reserve_exact(N)
        .map_err(|_| HarnessError::InvalidLength)?;
    for (query_id, bundle) in bundles {
        credentials.push(credential_query(query_id.clone(), bundle)?);
    }
    Ok(AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApi),
        response_uri: None,
        redirect_uri: None,
        nonce: REQUEST_NONCE.to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials,
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    })
}

pub(crate) fn tamper_first_stage_proof(
    mut value: PresentationValue,
) -> Result<PresentationValue, HarnessError> {
    let PresentationValue::Json(ref mut json) = value else {
        return Err(HarnessError::MissingField);
    };
    let first_byte = json
        .get_mut("stages")
        .and_then(JsonValue::as_array_mut)
        .and_then(|stages| stages.first_mut())
        .and_then(|stage| stage.get_mut("proof"))
        .and_then(JsonValue::as_array_mut)
        .and_then(|proof| proof.first_mut())
        .ok_or(HarnessError::MissingField)?;
    let current = first_byte.as_u64().ok_or(HarnessError::InvalidLength)?;
    *first_byte = JsonValue::from(if current == 0 { 1 } else { current ^ 1 });
    Ok(value)
}

pub(crate) fn zk_claim_pair(
    diagnostics: &reallyme_openid4vp_verifier::NonAuthorizingResponseDiagnostics,
) -> Result<
    (
        &reallyme_openid4vp_verifier::VerifiedZkClaim,
        &reallyme_openid4vp_verifier::VerifiedZkClaim,
    ),
    HarnessError,
> {
    let presentations = diagnostics.verified_presentations();
    let first = presentations.first().ok_or(HarnessError::MissingZkClaim)?;
    let second = presentations.get(1).ok_or(HarnessError::MissingZkClaim)?;
    Ok((zk_claim(first)?, zk_claim(second)?))
}

pub(crate) fn expect_zk_reason(
    result: Result<(), ZkError>,
    expected: ZkErrorReason,
) -> Result<(), HarnessError> {
    match result {
        Ok(()) => Err(HarnessError::WrongPersonaAccepted),
        Err(error) if error.reason() == expected => Ok(()),
        Err(error) => Err(HarnessError::Zk(error)),
    }
}

pub(crate) fn expect_verifier_reason<T>(
    result: Result<T, HarnessError>,
    expected: VerifierErrorReason,
) -> Result<(), HarnessError> {
    match result {
        Ok(_value) => Err(HarnessError::InvalidPresentationAccepted),
        Err(HarnessError::Verifier(error)) if error.reason() == expected => Ok(()),
        Err(error) => Err(error),
    }
}

fn direct_post_body<const N: usize>(
    presentations: [(&str, PresentationValue); N],
) -> Result<Vec<u8>, HarnessError> {
    let mut vp_token = JsonMap::new();
    for (query_id, value) in presentations {
        let PresentationValue::Json(value) = &value else {
            return Err(HarnessError::MissingField);
        };
        vp_token.insert(query_id.to_owned(), JsonValue::Array(vec![value.clone()]));
    }
    let encoded = serde_json::to_string(&JsonValue::Object(vp_token))?;
    let mut body = String::new();
    let capacity = encoded
        .len()
        .checked_mul(3)
        .and_then(|length| length.checked_add("vp_token=".len()))
        .ok_or(HarnessError::InvalidLength)?;
    body.try_reserve_exact(capacity)
        .map_err(|_| HarnessError::InvalidLength)?;
    body.push_str("vp_token=");
    append_form_component(&mut body, encoded.as_bytes())?;
    Ok(body.into_bytes())
}

fn append_form_component(out: &mut String, bytes: &[u8]) -> Result<(), HarnessError> {
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            write!(out, "%{byte:02X}").map_err(|_| HarnessError::InvalidLength)?;
        }
    }
    Ok(())
}

fn credential_query(
    query_id: QueryId,
    bundle: &reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
) -> Result<CredentialQuery, HarnessError> {
    let statement = bundle.decode_claimed_statement()?;
    Ok(CredentialQuery {
        id: query_id,
        format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())?,
        multiple: false,
        meta: json!({
            "profile": "private_persona_claim_v1",
            "hash_strategy": "sha256",
            "claim_name_hash": lower_hex(&statement.claim_name_hash())?,
        })
        .as_object()
        .ok_or(HarnessError::MissingField)?
        .clone(),
        trusted_authorities: None,
        require_cryptographic_holder_binding: true,
        claims: None,
        claim_sets: None,
    })
}

fn direct_post_request_for_bundles<const N: usize>(
    bundles: [(&QueryId, &reallyme_zk_api::claim_bundle::ZkClaimProofBundle); N],
) -> Result<AuthorizationRequestObject, HarnessError> {
    let mut request = request_for_bundles(bundles)?;
    request.client_id = Some(reallyme_openid4vp_types::ClientIdentifier::parse(
        DIRECT_POST_CLIENT_ID,
    )?);
    request.response_mode = Some(ResponseMode::DirectPost);
    request.response_uri = Some(DIRECT_POST_RESPONSE_URI.to_owned());
    Ok(request)
}

fn direct_post_session_record(
    request: AuthorizationRequestObject,
    verification_time_unix: u64,
) -> Result<SessionRecord, HarnessError> {
    Ok(SessionRecord {
        binding: RequestBinding {
            client_id: reallyme_openid4vp_types::ClientIdentifier::parse(DIRECT_POST_CLIENT_ID)?,
            nonce: REQUEST_NONCE.to_owned(),
            response_uri: Some(DIRECT_POST_RESPONSE_URI.to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: verification_time_unix
                .checked_add(60)
                .ok_or(HarnessError::InvalidLength)?,
            request_time_unix: verification_time_unix,
            transaction_data_bindings: Vec::new(),
        },
        state: None,
        dcql_query: request.dcql_query.clone(),
        response_mode: ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    })
}

fn session_record(
    request: AuthorizationRequestObject,
    verification_time_unix: u64,
    nonce: &str,
    dc_api_origin: &str,
    transaction_data_bindings: Vec<TransactionDataBinding>,
    response_mode: ResponseMode,
) -> Result<SessionRecord, HarnessError> {
    Ok(SessionRecord {
        binding: RequestBinding {
            client_id: reallyme_openid4vp_types::ClientIdentifier::parse(
                "x509_san_dns:ignored.example",
            )?,
            nonce: nonce.to_owned(),
            response_uri: None,
            redirect_uri: None,
            dc_api_origin: Some(dc_api_origin.to_owned()),
            expiry_unix: verification_time_unix
                .checked_add(60)
                .ok_or(HarnessError::InvalidLength)?,
            request_time_unix: verification_time_unix,
            transaction_data_bindings,
        },
        state: None,
        dcql_query: request.dcql_query.clone(),
        response_mode,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    })
}

fn zk_claim(
    presentation: &reallyme_openid4vp_verifier::VerifiedPresentation,
) -> Result<&reallyme_openid4vp_verifier::VerifiedZkClaim, HarnessError> {
    match presentation.holder_binding().disclosures() {
        VerifiedDisclosureSet::ZkClaim(claim) => Ok(claim.as_ref()),
        _ => Err(HarnessError::MissingZkClaim),
    }
}

fn format_origin_audience(origin: &str) -> String {
    ["origin:", origin].concat()
}
