// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One signed SD-JWT crosses the OpenID4VCI response and OpenID4VP verifier.

use std::sync::Arc;

use openid4vci_issuer::{
    encode_immediate_response_with_verified_proofs, IssuedCredential, JoseJwtProofVerifier,
    PassThroughCredentialEncoder, ProofAlgorithm, ProofVerificationContext, ProofVerifier,
};
use openid4vci_types::{
    CredentialFormat as VciCredentialFormat, CredentialPayload, CredentialRequest,
    CredentialSelector, Proofs,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_credential_status::{
    build_token_status_list_payload, issue_token_status_list_jwt, verify_token_status_list_jwt,
    TokenStatusBits, TokenStatusListClaims, TokenStatusListFreshnessPolicy, TokenStatusListProfile,
    TokenStatusValue,
};
use reallyme_crypto::{
    core::Algorithm,
    dispatch::{generate_keypair, sign},
    jwk::{ed25519_public_key_to_jwk, Jwk, JwkOptions},
};
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::sd_jwt::{
    verify_sd_jwt_presentation, SdJwtFormatError, SdJwtFormatErrorReason, SdJwtIssuerIdentity,
    SdJwtIssuerKeySource, SdJwtPresentationVerificationInput, SdJwtTrustProvider,
    SdJwtVerificationKeyMaterial,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, PresentationValue, ResponseMode, ResponseType,
};
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, HolderBindingVerificationContext,
    HolderBindingVerifier, ResponseValidationOptions, SdJwtHolderBindingVerifier,
    VerifiedHolderBinding, VerifierError,
};
use reallyme_sd_jwt::{
    build_key_binding_jwt, create_object_property_disclosure, digest_disclosure,
    serialize_sd_jwt_compact, KeyBindingJwtBuildOptions, SdJwtHashAlgorithm,
};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::direct_post::{
    authorization_response, direct_post_body, identity_runtime, product_store, request_from_body,
    session_record, DIRECT_POST_CLIENT_ID, DIRECT_POST_RESPONSE_URI,
};
use crate::error::HarnessError;
use crate::runtime::SESSION_KEY;

const ISSUER: &str = "https://issuer.example";
const VCT: &str = "https://credentials.example/pid";
const AUDIENCE: &str = DIRECT_POST_CLIENT_ID;
const NONCE: &str = "sd-jwt-roundtrip-nonce";
const VCI_NONCE: &str = "vci-issuance-nonce";
const STATUS_URI: &str = "https://issuer.example/status/1";
const STATUS_INDEX: u64 = 7;
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_000_900;
const DISCLOSURE_SALT: &str = "MDEyMzQ1Njc4OWFiY2RlZg";

struct SigningKey {
    public: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
    jwk: Jwk,
}

impl SigningKey {
    fn generate() -> Result<Self, HarnessError> {
        let (public, private) =
            generate_keypair(Algorithm::Ed25519).map_err(|_| HarnessError::SdJwtRoundtrip)?;
        let jwk = ed25519_public_key_to_jwk(
            &public,
            JwkOptions {
                alg: true,
                use_sig: true,
                ..JwkOptions::default()
            },
        )
        .map_err(|_| HarnessError::SdJwtRoundtrip)?;
        Ok(Self {
            public,
            private,
            jwk: Jwk::Okp(jwk.into()),
        })
    }
}

#[derive(Clone)]
struct TrustProvider {
    issuer_jwk: Jwk,
    issuer_public: Vec<u8>,
    holder_jwk: Jwk,
    holder_public: Vec<u8>,
    status_token: String,
    status_check_time_unix: u64,
}

struct OwnedSdJwtVerifier {
    trust: TrustProvider,
}

impl HolderBindingVerifier for OwnedSdJwtVerifier {
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        SdJwtHolderBindingVerifier::new(&self.trust).verify_holder_binding(presentation, context)
    }
}

impl SdJwtTrustProvider for TrustProvider {
    fn resolve_verification_keys(
        &self,
        _compact: &str,
        _query: &CredentialQuery,
        _now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError> {
        Ok(SdJwtVerificationKeyMaterial::new(
            self.issuer_jwk.clone(),
            self.issuer_public.clone(),
            self.holder_jwk.clone(),
            self.holder_public.clone(),
            SdJwtIssuerKeySource::Resolved,
            SdJwtIssuerIdentity::new(ISSUER.to_owned())?,
        ))
    }

    fn verify_credential_status(
        &self,
        issuer_payload: &Value,
        _resolved_payload: &Value,
    ) -> Result<(), SdJwtFormatError> {
        let status = issuer_payload
            .get("status")
            .and_then(|value| value.get("status_list"));
        let status_matches = status.is_some_and(|value| {
            value.get("uri").and_then(Value::as_str) == Some(STATUS_URI)
                && value.get("idx").and_then(Value::as_u64) == Some(STATUS_INDEX)
        });
        if !status_matches {
            return Err(invalid_status());
        }
        let verified = verify_token_status_list_jwt(
            &self.status_token,
            &self.issuer_jwk,
            &self.issuer_public,
            STATUS_URI,
            self.status_check_time_unix,
            TokenStatusListFreshnessPolicy { max_age_secs: 300 },
        )
        .map_err(|_| invalid_status())?;
        let status_index = usize::try_from(STATUS_INDEX).map_err(|_| invalid_status())?;
        if verified
            .status(status_index)
            .map_err(|_| invalid_status())?
            != TokenStatusValue::Valid
        {
            return Err(invalid_status());
        }
        Ok(())
    }
}

pub(crate) fn run_sd_jwt_roundtrip() -> Result<(), HarnessError> {
    let issuer = SigningKey::generate()?;
    let holder = SigningKey::generate()?;
    let disclosed_name =
        create_object_property_disclosure(DISCLOSURE_SALT, "given_name", json!("Ada"))
            .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let disclosure = disclosed_name.encoded().to_owned();
    let digest = digest_disclosure(&disclosure, SdJwtHashAlgorithm::Sha256)
        .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let disclosures = [disclosure];
    let signed = encode_signed_jwt_with_header_options(
        &json!({
            "iss": ISSUER,
            "vct": VCT,
            "_sd_alg": "sha-256",
            "_sd": [digest],
            "cnf": {"jwk": holder.jwk},
            "status": {"status_list": {"uri": STATUS_URI, "idx": STATUS_INDEX}},
            "iat": ISSUED_AT,
            "exp": EXPIRES_AT,
        }),
        &issuer.jwk,
        issuer.private.as_slice(),
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let compact = serialize_sd_jwt_compact(&signed, &disclosures)
        .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let proof_jwt = signed_vci_proof(&holder)?;
    let proofs = Proofs {
        jwt: vec![proof_jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let verified = JoseJwtProofVerifier::new().verify(
        &proofs,
        &ProofVerificationContext {
            credential_request_profile: openid4vci_issuer::CredentialRequestProfile::OpenId4Vci,
            credential_issuer: ISSUER.to_owned(),
            selector: CredentialSelector::ConfigurationId("pid".to_owned()),
            client_id: None,
            accepted_proof_algorithms: vec![ProofAlgorithm::EdDsa],
            nonce_required: true,
            current_time: i64::try_from(ISSUED_AT).map_err(|_| HarnessError::SdJwtRoundtrip)?,
            key_attestation_policy: None,
        },
    )?;
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(proofs),
        credential_response_encryption: None,
        reallyme_zk_v1_issuance: None,
    };
    let issued = [IssuedCredential::new(
        VciCredentialFormat::SdJwtVc,
        Value::String(compact),
    )?];
    let response = encode_immediate_response_with_verified_proofs(
        &request,
        Some(&verified),
        &PassThroughCredentialEncoder::new(VciCredentialFormat::SdJwtVc),
        &issued,
        None,
    )?;
    let received = response
        .credentials
        .as_ref()
        .and_then(|credentials| credentials.first())
        .ok_or(HarnessError::SdJwtRoundtrip)?;
    let CredentialPayload::Compact(received) = &received.credential else {
        return Err(HarnessError::SdJwtRoundtrip);
    };
    let key_binding = build_key_binding_jwt(
        &signed,
        &disclosures,
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: holder.private.as_slice(),
            audience: AUDIENCE,
            nonce: NONCE,
            issued_at_unix: ISSUED_AT,
        },
    )
    .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let presentation = format!("{received}{key_binding}");
    let query = CredentialQuery {
        id: QueryId::parse("pid")?,
        format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())?,
        multiple: false,
        meta: Map::from_iter([("vct_values".to_owned(), json!([VCT]))]),
        trusted_authorities: None,
        require_cryptographic_holder_binding: true,
        claims: None,
        claim_sets: None,
    };
    let trust = TrustProvider {
        status_token: signed_status_list(&issuer, false)?,
        status_check_time_unix: ISSUED_AT + 1,
        issuer_jwk: issuer.jwk.clone(),
        issuer_public: issuer.public.clone(),
        holder_jwk: holder.jwk,
        holder_public: holder.public,
    };
    let verified =
        verify_sd_jwt_presentation(input(&presentation, NONCE, &query, ISSUED_AT + 1), &trust)
            .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    if verified.nonce != NONCE
        || verified.audience != [AUDIENCE]
        || verified.resolved_payload.get("given_name") != Some(&json!("Ada"))
    {
        return Err(HarnessError::SdJwtRoundtrip);
    }
    verify_openid4vp_response(&presentation, &query, &trust)?;
    if verify_sd_jwt_presentation(
        input(&presentation, "wrong-nonce", &query, ISSUED_AT + 1),
        &trust,
    )
    .is_ok()
        || verify_sd_jwt_presentation(input(&presentation, NONCE, &query, EXPIRES_AT + 1), &trust)
            .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    if verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            expected_audience: "https://another-verifier.example",
            ..input(&presentation, NONCE, &query, ISSUED_AT + 1)
        },
        &trust,
    )
    .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let stale_status = TrustProvider {
        status_check_time_unix: ISSUED_AT + 301,
        ..trust.clone()
    };
    if verify_sd_jwt_presentation(
        input(&presentation, NONCE, &query, ISSUED_AT + 301),
        &stale_status,
    )
    .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let revoked = TrustProvider {
        status_token: signed_status_list(&issuer, true)?,
        ..trust
    };
    if verify_sd_jwt_presentation(input(&presentation, NONCE, &query, ISSUED_AT + 1), &revoked)
        .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok(())
}

fn verify_openid4vp_response(
    presentation: &str,
    query: &CredentialQuery,
    trust: &TrustProvider,
) -> Result<(), HarnessError> {
    let request = AuthorizationRequestObject {
        client_id: Some(ClientIdentifier::parse(DIRECT_POST_CLIENT_ID)?),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPost),
        response_uri: Some(DIRECT_POST_RESPONSE_URI.to_owned()),
        redirect_uri: None,
        nonce: NONCE.to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![query.clone()],
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: Some(DIRECT_POST_CLIENT_ID.to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(ISSUED_AT),
        exp: Some(EXPIRES_AT),
    };
    let session = session_record(request.clone(), ISSUED_AT + 1)?;
    let response =
        authorization_response([("pid", PresentationValue::Compact(presentation.to_owned()))])?;
    let verifier = SdJwtHolderBindingVerifier::new(trust);
    let diagnosed = diagnose_authorization_response_with_options(
        &session,
        &response,
        ISSUED_AT + 1,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )?;
    if diagnosed.verified_presentations().len() != 1 {
        return Err(HarnessError::SdJwtRoundtrip);
    }
    let body = direct_post_body([("pid", PresentationValue::Compact(presentation.to_owned()))])?;
    let (store, _directory) = product_store(request, session)?;
    let runtime = identity_runtime(
        store,
        Arc::new(OwnedSdJwtVerifier {
            trust: trust.clone(),
        }),
        ISSUED_AT + 1,
        body.len(),
    )?;
    if runtime
        .handle_direct_post(SESSION_KEY, &request_from_body(body.clone()))
        .status
        != 200
    {
        return Err(HarnessError::SdJwtRoundtrip);
    }
    if runtime
        .handle_direct_post(SESSION_KEY, &request_from_body(body))
        .status
        == 200
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok(())
}

fn signed_vci_proof(holder: &SigningKey) -> Result<String, HarnessError> {
    let header = serde_json::to_vec(&json!({
        "alg": "EdDSA",
        "typ": "openid4vci-proof+jwt",
        "jwk": holder.jwk,
    }))
    .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let claims = serde_json::to_vec(&json!({
        "aud": ISSUER,
        "nonce": VCI_NONCE,
        "iat": ISSUED_AT,
    }))
    .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let signing_input = format!(
        "{}.{}",
        bytes_to_base64url(&header),
        bytes_to_base64url(&claims)
    );
    let signature = sign(
        Algorithm::Ed25519,
        holder.private.as_slice(),
        signing_input.as_bytes(),
    )
    .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    Ok(format!(
        "{signing_input}.{}",
        bytes_to_base64url(&signature)
    ))
}

fn invalid_status() -> SdJwtFormatError {
    SdJwtFormatError::new(SdJwtFormatErrorReason::InvalidCredentialStatus)
}

fn signed_status_list(issuer: &SigningKey, revoked: bool) -> Result<String, HarnessError> {
    let mut values = [0_u8; 8];
    if revoked {
        values[usize::try_from(STATUS_INDEX).map_err(|_| HarnessError::SdJwtRoundtrip)?] = 1;
    }
    let status_list = build_token_status_list_payload(&values, TokenStatusBits::One, None)
        .map_err(|_| HarnessError::SdJwtRoundtrip)?;
    let claims = TokenStatusListClaims {
        profile: TokenStatusListProfile::IetfDraft21,
        sub: STATUS_URI.to_owned(),
        iat: ISSUED_AT,
        exp: Some(EXPIRES_AT),
        ttl: Some(300),
        status_list,
    };
    issue_token_status_list_jwt(&claims, &issuer.jwk, issuer.private.as_slice())
        .map_err(|_| HarnessError::SdJwtRoundtrip)
}

fn input<'a>(
    compact: &'a str,
    nonce: &'a str,
    query: &'a CredentialQuery,
    now_unix: u64,
) -> SdJwtPresentationVerificationInput<'a> {
    SdJwtPresentationVerificationInput {
        compact,
        expected_audience: AUDIENCE,
        expected_nonce: nonce,
        now_unix,
        credential_query: query,
    }
}
