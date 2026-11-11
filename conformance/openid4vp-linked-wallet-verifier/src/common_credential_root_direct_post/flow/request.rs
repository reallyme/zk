// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm, common_root::ZkCommonCredentialRootPersonaMode,
};
use serde_json::json;

use super::super::model::CommonCredentialRootFixture;
use crate::{
    constants::REQUEST_NONCE,
    direct_post::{DIRECT_POST_CLIENT_ID, DIRECT_POST_RESPONSE_URI},
    error::HarnessError,
    fixture::lower_hex,
};

pub(in crate::common_credential_root_direct_post) fn request_for_common_credential_root_fixture(
    query_id: &QueryId,
    fixture: Option<&CommonCredentialRootFixture>,
) -> Result<AuthorizationRequestObject, HarnessError> {
    request_for_common_credential_root_fixture_profile(
        query_id,
        fixture,
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
    )
}

pub(in crate::common_credential_root_direct_post) fn request_for_common_credential_root_fixture_profile(
    query_id: &QueryId,
    fixture: Option<&CommonCredentialRootFixture>,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<AuthorizationRequestObject, HarnessError> {
    let issued_at = fixture.map_or(1, |value| value.request_time_unix);
    request_for_common_credential_root_fixture_at_profile(
        query_id,
        fixture,
        issued_at,
        persona_mode,
        credential_hash_algorithm,
    )
}

pub(in crate::common_credential_root_direct_post) fn request_for_common_credential_root_fixture_at(
    query_id: &QueryId,
    fixture: Option<&CommonCredentialRootFixture>,
    issued_at: u64,
) -> Result<AuthorizationRequestObject, HarnessError> {
    request_for_common_credential_root_fixture_at_profile(
        query_id,
        fixture,
        issued_at,
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
    )
}

fn request_for_common_credential_root_fixture_at_profile(
    query_id: &QueryId,
    fixture: Option<&CommonCredentialRootFixture>,
    issued_at: u64,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<AuthorizationRequestObject, HarnessError> {
    let expires_at = issued_at
        .checked_add(COMMON_CREDENTIAL_ROOT_DIRECT_POST_REQUEST_WINDOW_SECONDS)
        .ok_or(HarnessError::InvalidLength)?;
    let credential = if let Some(fixture) = fixture {
        common_credential_root_credential_query(
            query_id.clone(),
            fixture,
            persona_mode,
            credential_hash_algorithm,
        )?
    } else {
        common_credential_root_placeholder_credential_query(
            query_id.clone(),
            persona_mode,
            credential_hash_algorithm,
        )?
    };
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
            credentials: vec![credential],
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: Some(DIRECT_POST_CLIENT_ID.to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(fixture.map_or(issued_at, |value| value.request_time_unix)),
        exp: Some(expires_at),
    })
}

fn common_credential_root_credential_query(
    query_id: QueryId,
    fixture: &CommonCredentialRootFixture,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<CredentialQuery, HarnessError> {
    Ok(CredentialQuery {
        id: query_id,
        format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())?,
        multiple: false,
        meta: json!({
            "profile": profile_meta(persona_mode)?,
            "hash_strategy": credential_hash_algorithm_meta(credential_hash_algorithm)?,
            "claim_0_name_hash": lower_hex(&fixture.first_claim.claim_name_hash)?,
            "claim_0_value_b64u": bytes_to_base64url(&fixture.first_claim.value),
            "claim_1_name_hash": lower_hex(&fixture.second_claim.claim_name_hash)?,
            "claim_1_value_b64u": bytes_to_base64url(&fixture.second_claim.value),
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

fn common_credential_root_placeholder_credential_query(
    query_id: QueryId,
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<CredentialQuery, HarnessError> {
    Ok(CredentialQuery {
        id: query_id,
        format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())?,
        multiple: false,
        meta: json!({
            "profile": profile_meta(persona_mode)?,
            "hash_strategy": credential_hash_algorithm_meta(credential_hash_algorithm)?,
            "claim_0_name_hash": lower_hex(&[1_u8; 32])?,
            "claim_0_value_b64u": bytes_to_base64url(&[1_u8]),
            "claim_1_name_hash": lower_hex(&[2_u8; 32])?,
            "claim_1_value_b64u": bytes_to_base64url(&[2_u8]),
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

fn profile_meta(
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> Result<&'static str, HarnessError> {
    match persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            Ok("common_credential_root_v1_private_persona")
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            Ok("common_credential_root_v1_public_persona")
        }
    }
}

fn credential_hash_algorithm_meta(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<&'static str, HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => Ok("sha256"),
        ZkCredentialHashAlgorithm::Poseidon2 => Ok("poseidon2"),
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

const COMMON_CREDENTIAL_ROOT_DIRECT_POST_REQUEST_WINDOW_SECONDS: u64 = 3_600;
