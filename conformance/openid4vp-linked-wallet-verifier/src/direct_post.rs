// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use reallyme_identity_openid4vp_product::{
    IdentityOpenId4VpVerifierConfig, IdentityOpenId4VpVerifierRuntime,
};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_runtime::{RuntimeHttpMethod, RuntimeHttpRequest};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, AuthorizationResponse, ClientIdentifier, PresentationValue,
    ResponseMode, ResponseType,
};
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, HolderBindingVerifier, RequestBinding,
    ResponseValidationOptions, SessionRecord, VerifiedDisclosureSet,
};
use reallyme_openid4vp_wallet::{
    prepare_zk_presentation_from_status_qualified_bundle, verify_signed_request_object,
    JoseRequestObjectVerification, JoseRequestObjectVerificationResolver,
    JoseSignedRequestObjectVerifier, VerifiedClientIdentifierBinding, WalletError,
    WalletInvocationContext,
};
use reallyme_zk_api::proofs::ZkSessionBinding;
use serde_json::{json, Map as JsonMap, Value as JsonValue};

use crate::constants::{QUERY_A, QUERY_B, REQUEST_NONCE};
use crate::error::HarnessError;
use crate::fixture::lower_hex;
use crate::runtime::{FixedClock, InMemorySessionStore, SESSION_KEY};

mod store;

pub(crate) use store::{product_store, status_floor_store};

pub(crate) const DIRECT_POST_CLIENT_ID: &str = "decentralized_identifier:did:example:verifier";
pub(crate) const DIRECT_POST_RESPONSE_URI: &str = "https://verifier.example/response";
const REQUEST_OBJECT_AUDIENCE: &str = "wallet";
pub(super) const REQUEST_OBJECT_KEY: &str = "linked-request-object-0123456789";
pub(super) static TEST_P256_SECRET: [u8; 32] = [
    0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf, 0xee,
    0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91, 0xc3, 0x44,
];

pub(crate) fn direct_post_session_binding() -> ZkSessionBinding {
    let binding = reallyme_openid4vp_formats::build_zk_presentation_binding(
        REQUEST_NONCE,
        DIRECT_POST_CLIENT_ID,
        None,
    );
    ZkSessionBinding {
        nonce_hash: binding.nonce_hash,
        audience_hash: binding.audience_hash,
        transaction_data_hash: None,
    }
}

pub(crate) fn direct_post_status_qualified_wallet_values(
    first: &reallyme_zk_api::claim_bundle::ZkStatusQualifiedClaimProofBundle,
    second: &reallyme_zk_api::claim_bundle::ZkStatusQualifiedClaimProofBundle,
    verification_time_unix: u64,
) -> Result<(PresentationValue, PresentationValue), HarnessError> {
    let first_id = QueryId::parse(QUERY_A)?;
    let second_id = QueryId::parse(QUERY_B)?;
    let request = request_for_bundles([
        (&first_id, first.claim_proof_bundle()),
        (&second_id, second.claim_proof_bundle()),
    ])?;
    let verified = verified_request(request, verification_time_unix)?;
    let invocation = WalletInvocationContext::ProtocolTransport;
    let first_value = prepare_zk_presentation_from_status_qualified_bundle(
        &verified,
        &invocation,
        &first_id,
        first,
    )?;
    let second_value = prepare_zk_presentation_from_status_qualified_bundle(
        &verified,
        &invocation,
        &second_id,
        second,
    )?;
    Ok((first_value, second_value))
}

pub(crate) fn expect_direct_post_accepts_once(
    verifier: Arc<dyn HolderBindingVerifier>,
    first: &reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
    second: &reallyme_zk_api::claim_bundle::ZkClaimProofBundle,
    values: (PresentationValue, PresentationValue),
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    let first_id = QueryId::parse(QUERY_A)?;
    let second_id = QueryId::parse(QUERY_B)?;
    let request = request_for_bundles([(&first_id, first), (&second_id, second)])?;
    let session = session_record(request.clone(), verification_time_unix)?;
    let diagnosed = diagnose_authorization_response_with_options(
        &session,
        &authorization_response([(QUERY_A, values.0.clone()), (QUERY_B, values.1.clone())])?,
        verification_time_unix,
        ResponseValidationOptions {
            holder_binding_verifier: Some(verifier.as_ref()),
        },
    )?;
    let claims = zk_claim_pair(diagnosed.verified_presentations())?;
    if !claims.0.same_presenting_key_in_session(claims.1) {
        return Err(HarnessError::WrongPersonaAccepted);
    }
    let body = direct_post_body([(QUERY_A, values.0.clone()), (QUERY_B, values.1.clone())])?;
    expect_runtime_rejects(
        verifier.clone(),
        session.clone(),
        direct_post_body([
            (QUERY_A, tamper_first_stage_proof(values.0.clone())?),
            (QUERY_B, values.1.clone()),
        ])?,
        verification_time_unix,
    )?;
    let mut wrong_session = session.clone();
    wrong_session.binding.nonce = "wrong-linked-direct-post-nonce-v1".to_owned();
    expect_runtime_rejects(
        verifier.clone(),
        wrong_session,
        body.clone(),
        verification_time_unix,
    )?;
    let (store, _store_directory) = product_store(request.clone(), session)?;
    let runtime = identity_runtime(store.clone(), verifier, verification_time_unix, body.len())?;
    let accepted = runtime.handle_direct_post(SESSION_KEY, &request_from_body(body.clone()));
    if accepted.status != 200 {
        return Err(HarnessError::RuntimeStatus(accepted.status));
    }
    let replay = runtime.handle_direct_post(SESSION_KEY, &request_from_body(body));
    if replay.status == 200 {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok(())
}

pub(crate) fn expect_runtime_rejects(
    verifier: Arc<dyn HolderBindingVerifier>,
    session: SessionRecord,
    body: Vec<u8>,
    verification_time_unix: u64,
) -> Result<(), HarnessError> {
    let store = Arc::new(InMemorySessionStore::new(session));
    let runtime = identity_runtime(store.clone(), verifier, verification_time_unix, body.len())?;
    let response = runtime.handle_direct_post(SESSION_KEY, &request_from_body(body));
    if response.status != 400 {
        return Err(HarnessError::RuntimeStatus(response.status));
    }
    match store.committed_result() {
        Err(HarnessError::RuntimeCommitMissing) => Ok(()),
        Err(error) => Err(error),
        Ok(_committed) => Err(HarnessError::InvalidPresentationAccepted),
    }
}

pub(crate) fn identity_runtime(
    store: Arc<dyn reallyme_identity_openid4vp_product::VerifierProductStore>,
    verifier: Arc<dyn HolderBindingVerifier>,
    verification_time_unix: u64,
    max_body_bytes: usize,
) -> Result<IdentityOpenId4VpVerifierRuntime, HarnessError> {
    Ok(IdentityOpenId4VpVerifierRuntime::try_new(
        IdentityOpenId4VpVerifierConfig::new(
            store,
            Arc::new(FixedClock {
                now_unix: verification_time_unix,
            }),
        )
        .with_holder_binding_verifier(verifier)
        .with_max_direct_post_body_bytes(max_body_bytes),
    )?)
}

pub(crate) fn authorization_response<const N: usize>(
    presentations: [(&str, PresentationValue); N],
) -> Result<AuthorizationResponse, HarnessError> {
    let mut vp_token = BTreeMap::new();
    for (query_id, value) in presentations {
        vp_token.insert(QueryId::parse(query_id)?, vec![value]);
    }
    Ok(AuthorizationResponse {
        vp_token,
        state: None,
    })
}

pub(crate) fn verified_request(
    request: AuthorizationRequestObject,
    verification_time_unix: u64,
) -> Result<reallyme_openid4vp_wallet::VerifiedWalletRequest, HarnessError> {
    let resolver = FixtureKeyResolver::try_new()?;
    let jwt = reallyme_jose::jwt::encode_signed_jwt_with_header_options(
        &request,
        &resolver.jwk,
        &TEST_P256_SECRET,
        &reallyme_jose::jwt::JwtHeaderEncodeOptions::new(Some("oauth-authz-req+jwt".to_owned())),
    )
    .map_err(|_| HarnessError::InvalidLength)?;
    let verifier =
        JoseSignedRequestObjectVerifier::new(resolver, REQUEST_OBJECT_AUDIENCE.to_owned());
    verify_signed_request_object(
        &verifier,
        &jwt,
        &WalletInvocationContext::ProtocolTransport,
        verification_time_unix,
    )
    .map_err(HarnessError::from)
}

struct FixtureKeyResolver {
    jwk: reallyme_crypto::jwk::Jwk,
    public_key: Vec<u8>,
}

impl FixtureKeyResolver {
    fn try_new() -> Result<Self, HarnessError> {
        let (public_key, _secret_key) =
            reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_SECRET)
                .map_err(|_| HarnessError::InvalidLength)?;
        let jwk = reallyme_crypto::jwk::p256_public_key_to_jwk(
            &public_key,
            reallyme_crypto::jwk::JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: Some("verifier-key-1".to_owned()),
            },
        )
        .map_err(|_| HarnessError::InvalidLength)?;
        Ok(Self {
            jwk: reallyme_crypto::jwk::Jwk::Ec(jwk),
            public_key,
        })
    }
}

impl JoseRequestObjectVerificationResolver for FixtureKeyResolver {
    fn resolve_request_object_verification(
        &self,
        _jwt: &str,
        claimed_client_identifier: Option<&ClientIdentifier>,
        _x509_chain: Option<&reallyme_openid4vp_wallet::BoundedX509CertificateChain>,
        _now_unix: u64,
    ) -> Result<JoseRequestObjectVerification, WalletError> {
        let mut verification =
            JoseRequestObjectVerification::new(self.jwk.clone(), self.public_key.clone());
        if let Some(client_id) = claimed_client_identifier {
            verification = verification.with_client_identifier_binding(
                VerifiedClientIdentifierBinding::new(client_id.clone(), &self.public_key)?,
            );
        }
        Ok(verification)
    }
}

fn request_for_bundles<const N: usize>(
    bundles: [(&QueryId, &reallyme_zk_api::claim_bundle::ZkClaimProofBundle); N],
) -> Result<AuthorizationRequestObject, HarnessError> {
    let mut credentials = Vec::new();
    credentials
        .try_reserve_exact(N)
        .map_err(|_| HarnessError::InvalidLength)?;
    for (query_id, bundle) in bundles {
        credentials.push(credential_query(query_id.clone(), bundle)?);
    }
    let iat = 1_u64;
    let exp = u64::MAX / 2;
    Ok(AuthorizationRequestObject {
        client_id: Some(ClientIdentifier::parse(DIRECT_POST_CLIENT_ID)?),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPost),
        response_uri: Some(DIRECT_POST_RESPONSE_URI.to_owned()),
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
        iss: Some(DIRECT_POST_CLIENT_ID.to_owned()),
        aud: Some(vec![REQUEST_OBJECT_AUDIENCE.to_owned()]),
        iat: Some(iat),
        exp: Some(exp),
    })
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

pub(crate) fn session_record(
    request: AuthorizationRequestObject,
    verification_time_unix: u64,
) -> Result<SessionRecord, HarnessError> {
    let protocol_expiry = verification_time_unix
        .checked_add(3_600)
        .ok_or(HarnessError::InvalidLength)?;
    let storage_expiry = current_unix()?
        .checked_add(3_600)
        .ok_or(HarnessError::InvalidLength)?;
    Ok(SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse(DIRECT_POST_CLIENT_ID)?,
            nonce: request.nonce.clone(),
            response_uri: Some(DIRECT_POST_RESPONSE_URI.to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: protocol_expiry.max(storage_expiry),
            request_time_unix: request.iat.ok_or(HarnessError::MissingField)?,
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

fn current_unix() -> Result<u64, HarnessError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HarnessError::InvalidLength)
}

pub(crate) fn direct_post_body<const N: usize>(
    presentations: [(&str, PresentationValue); N],
) -> Result<Vec<u8>, HarnessError> {
    let mut vp_token = JsonMap::new();
    for (query_id, value) in presentations {
        let encoded = match &value {
            PresentationValue::Json(value) => value.clone(),
            PresentationValue::Compact(value) => JsonValue::String(value.clone()),
        };
        vp_token.insert(query_id.to_owned(), JsonValue::Array(vec![encoded]));
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

fn tamper_first_stage_proof(
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

pub(crate) fn request_from_body(body: Vec<u8>) -> RuntimeHttpRequest {
    RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body,
    }
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

fn zk_claim_pair(
    presentations: &[reallyme_openid4vp_verifier::VerifiedPresentation],
) -> Result<
    (
        &reallyme_openid4vp_verifier::VerifiedZkClaim,
        &reallyme_openid4vp_verifier::VerifiedZkClaim,
    ),
    HarnessError,
> {
    let first = presentations.first().ok_or(HarnessError::MissingZkClaim)?;
    let second = presentations.get(1).ok_or(HarnessError::MissingZkClaim)?;
    Ok((zk_claim(first)?, zk_claim(second)?))
}

fn zk_claim(
    presentation: &reallyme_openid4vp_verifier::VerifiedPresentation,
) -> Result<&reallyme_openid4vp_verifier::VerifiedZkClaim, HarnessError> {
    match presentation.holder_binding().disclosures() {
        VerifiedDisclosureSet::ZkClaim(claim) => Ok(claim.as_ref()),
        _ => Err(HarnessError::MissingZkClaim),
    }
}
