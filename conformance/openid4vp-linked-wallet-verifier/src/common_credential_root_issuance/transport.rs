// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use openid4vci_issuer::{
    encode_immediate_response_with_verified_proofs, CommonRootCredentialEncoder,
    CommonRootIssuanceRequestBinding, CommonRootIssuedCredential, IssuanceStatusEvidence,
    JoseJwtProofVerifier, ProofAlgorithm, ProofVerificationContext, ProofVerifier,
};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as vci_pb;
use openid4vci_proto_codec::convert::credential_envelope_to_proto as vci_envelope_to_proto;
use openid4vci_types::{
    CredentialPayload, CredentialRequest, CredentialResponse, CredentialSelector, Proofs,
    ReallyMeZkV1IssuanceRequest,
};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_credential::committed::proof_binding::{
    validate_credential_proof_binding_public, CredentialProofBinding,
};
use reallyme_credential::credential_envelope_from_proto;
use reallyme_credential_status::{
    status_list_from_proto, verify_status_list_authenticity_with_policy, CredentialStatusError,
    StatusListAlgorithm, StatusListFreshnessPolicy, StatusListVerifier,
};
use reallyme_crypto::{
    core::Algorithm as CryptoAlgorithm, dispatch::verify, p256::p256_ecdsa_jose_signature_to_der,
};
use reallyme_identity::zk::validate_zk_common_root_issuance;
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::status::v1 as status_pb;
use reallyme_ssi_proto::{zeroize_credential_envelope, zeroize_status_list};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        verify_common_credential_root_poseidon2_issuer_claims_root,
        verify_common_credential_root_sha256_issuer_claims_root, ZkCommonCredentialRootClaim,
        ZkCommonCredentialRootSubjectPublicKey,
    },
};
use reallyme_zk_proto_codec::wallet_stored_credential::{
    decode_wallet_stored_credential_for_lane, encode_wallet_stored_credential,
};
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::HarnessError;

use super::{
    crypto::{
        coordinates, hash_parts, issuance_policy, issuer_key, public_key, raw32, scalar, sign_raw,
    },
    IssuedCredential, VerifiedZkStoredCredential, MAX_CREDENTIAL_PROTO_BYTES,
    MAX_STATUS_PROTO_BYTES, MAX_WIRE_PROTO_BYTES, PROTO_RECURSION_LIMIT,
};

struct HarnessStatusVerifier<'a> {
    issuer: &'a str,
    trusted_public_key: &'a [u8],
}

impl StatusListVerifier for HarnessStatusVerifier<'_> {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer != self.issuer || alg != StatusListAlgorithm::P256 {
            return Err(CredentialStatusError::InvalidSignature);
        }
        let signature = p256_ecdsa_jose_signature_to_der(signature)
            .map_err(|_| CredentialStatusError::InvalidSignature)?;
        verify(
            CryptoAlgorithm::P256,
            self.trusted_public_key,
            payload,
            signature.as_slice(),
        )
        .map_err(|_| CredentialStatusError::InvalidSignature)
    }
}

pub(super) fn transport_one(
    issued: IssuedCredential,
    issuer_scalar: u8,
    subject_scalar: u8,
) -> Result<VerifiedZkStoredCredential, HarnessError> {
    let trusted_issuer_public = public_key(&scalar(issuer_scalar))?;
    let subject_public = public_key(&scalar(subject_scalar))?;
    let proofs = Proofs {
        jwt: vec![signed_vci_proof(subject_scalar, &subject_public)?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let verified_proofs = JoseJwtProofVerifier::new().verify(
        &proofs,
        &ProofVerificationContext {
            credential_request_profile: openid4vci_issuer::CredentialRequestProfile::OpenId4Vci,
            credential_issuer: "https://issuer.example".to_owned(),
            selector: CredentialSelector::ConfigurationId("reallyme_zk_v1".to_owned()),
            client_id: None,
            accepted_proof_algorithms: vec![ProofAlgorithm::Es256],
            nonce_required: true,
            current_time: 1_700_000_000,
            key_attestation_policy: None,
        },
    )?;
    let verified_holder_proof = verified_proofs
        .proofs()
        .first()
        .ok_or(HarnessError::MissingField)?;
    validate_zk_common_root_issuance(
        &issued.envelope,
        verified_holder_proof,
        &issued.binding,
        issuer_key(&issued.binding),
        issuance_policy(issued.envelope.status.status_list_id),
    )?;
    let lineage_value = issued
        .private_claims
        .openings()
        .first()
        .ok_or(HarnessError::MissingField)?
        .value();
    let lineage_tag = lineage_value
        .get(32..64)
        .ok_or(HarnessError::InvalidLength)?;
    let claims_root = issued.private_claims.root();
    let opening_commitment = hash_parts(&[
        b"reallyme.zk.wallet-opening-commitment.v1",
        &claims_root,
        lineage_tag,
        issued
            .private_claims
            .openings()
            .first()
            .ok_or(HarnessError::MissingField)?
            .salt(),
    ]);
    let mut intent = vci_pb::ReallyMeZkV1IssuanceRequest::default();
    intent.version = 1;
    intent.claims_root = issued.private_claims.root().to_vec();
    intent.verified_holder_public_key = subject_public.clone();
    intent.lineage_tag_commitment =
        hash_parts(&[b"reallyme.zk.lineage-tag-commitment.v1", lineage_tag]).to_vec();
    intent.wallet_opening_commitment = opening_commitment.to_vec();
    // The OpenID4VCI wire field keeps its v1 name; it carries the salted
    // lineage claim digest from which the issuer derives the lineage leaf.
    intent.opaque_lineage_leaf = issued
        .private_claims
        .opaque_lineage_claim_digest()
        .map_err(|_| HarnessError::InvalidPresentationAccepted)?
        .to_vec();
    let request = CredentialRequest {
        credential_configuration_id: Some("reallyme_zk_v1".to_owned()),
        credential_identifier: None,
        proofs: Some(proofs),
        credential_response_encryption: None,
        reallyme_zk_v1_issuance: Some(
            ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&intent.encode_to_vec()))
                .map_err(|_| HarnessError::InvalidPresentationAccepted)?,
        ),
    };
    let claims = [ZkCommonCredentialRootClaim {
        name: &issued.claim_name,
        value: issued.claim_value.as_slice(),
        salt: &issued.claim_salt,
    }];
    let request_credential_hash_algorithm = common_credential_root_credential_hash_algorithm(
        &issued.envelope.claims_commitment.hash_alg,
    )?;
    let status_verifier = HarnessStatusVerifier {
        issuer: &issued.status_list.issuer,
        trusted_public_key: &trusted_issuer_public,
    };
    let status_freshness = StatusListFreshnessPolicy {
        max_age_secs: 3_600,
    };
    verify_status_list_authenticity_with_policy(
        &issued.status_list,
        issued.status_list.issued_at,
        status_freshness,
        &status_verifier,
    )?;
    verify_issuer_claims_root(
        request_credential_hash_algorithm,
        issued.private_claims.root(),
        raw32(&intent.opaque_lineage_leaf)?,
        &claims,
    )?;
    validate_credential_proof_binding_public(
        &issued.envelope,
        &issued.binding,
        &trusted_issuer_public,
    )?;
    let credential = CommonRootIssuedCredential::from_authorized_common_root_issuance(
        &issued.envelope,
        &issued.binding,
        &trusted_issuer_public,
        &IssuanceStatusEvidence::new(
            &issued.status_list,
            &status_verifier,
            issued.status_list.issued_at,
            status_freshness,
        ),
        &subject_public,
        CommonRootIssuanceRequestBinding::new(
            raw32(&intent.lineage_tag_commitment)?,
            raw32(&intent.wallet_opening_commitment)?,
            raw32(&intent.opaque_lineage_leaf)?,
        )?,
        &claims,
    )?
    .into_issued_credential()?;
    let response = encode_immediate_response_with_verified_proofs(
        &request,
        Some(&verified_proofs),
        &CommonRootCredentialEncoder::new(),
        &[credential],
        None,
    )?;
    let wire = response.to_json()?;
    let parsed = CredentialResponse::parse_json(&wire)?;
    let response_credential = match parsed.credentials.as_ref().and_then(|items| items.first()) {
        Some(item) => item,
        None => return Err(HarnessError::MissingField),
    };
    let encoded = match &response_credential.credential {
        CredentialPayload::Compact(encoded) => encoded,
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    };
    let bytes =
        Zeroizing::new(base64url_to_bytes(encoded).map_err(|_| HarnessError::InvalidLength)?);
    if bytes.is_empty()
        || bytes.len() > MAX_WIRE_PROTO_BYTES
        || bytes_to_base64url(&bytes) != *encoded
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let wire = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_WIRE_PROTO_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<vci_pb::ReallyMeZkV1Credential>(&bytes)
        .map_err(|_| HarnessError::InvalidLength)?;
    if wire.version != 1
        || wire.verified_holder_public_key != subject_public
        || wire.lineage_tag_commitment != intent.lineage_tag_commitment
        || wire.wallet_opening_commitment != intent.wallet_opening_commitment
        || wire.opaque_lineage_leaf != intent.opaque_lineage_leaf
        || wire.credential_envelope_pb.is_empty()
        || wire.credential_envelope_pb.len() > MAX_CREDENTIAL_PROTO_BYTES
        || wire.status_list_pb.is_empty()
        || wire.status_list_pb.len() > MAX_STATUS_PROTO_BYTES
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let mut proto = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_CREDENTIAL_PROTO_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<credential_pb::CredentialEnvelope>(&wire.credential_envelope_pb)
        .map_err(|_| HarnessError::InvalidLength)?;
    let envelope = credential_envelope_from_proto(&proto);
    zeroize_credential_envelope(&mut proto);
    let envelope = envelope?;
    let response_credential_hash_algorithm =
        common_credential_root_credential_hash_algorithm(&envelope.claims_commitment.hash_alg)?;
    let mut status_proto = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_STATUS_PROTO_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<status_pb::StatusList>(&wire.status_list_pb)
        .map_err(|_| HarnessError::InvalidLength)?;
    let status_list = status_list_from_proto(&status_proto);
    zeroize_status_list(&mut status_proto);
    let status_list = status_list?;
    let binding = binding_from_proto(
        wire.proof_binding
            .as_option()
            .ok_or(HarnessError::MissingField)?,
    )?;
    let proof = verified_proofs
        .proofs()
        .first()
        .ok_or(HarnessError::MissingField)?;
    validate_zk_common_root_issuance(
        &envelope,
        proof,
        &binding,
        issuer_key(&binding),
        issuance_policy(envelope.status.status_list_id),
    )?;
    let credential_envelope_pb = Zeroizing::new(
        vci_envelope_to_proto(response_credential)
            .map_err(|_| HarnessError::InvalidPresentationAccepted)?
            .encode_to_vec(),
    );
    let stored_plaintext = encode_wallet_stored_credential(
        &credential_envelope_pb,
        &issued.private_claims,
        &issued.private_lineage,
        issuer_key(&binding),
        ZkCommonCredentialRootSubjectPublicKey {
            x: coordinates(&public_key(&scalar(subject_scalar))?)?.0,
            y: coordinates(&public_key(&scalar(subject_scalar))?)?.1,
        },
        binding.claims_root,
        binding.issuance_binding,
    )
    .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
    let stored = decode_wallet_stored_credential_for_lane(
        &stored_plaintext,
        &credential_envelope_pb,
        issuer_key(&binding),
        ZkCommonCredentialRootSubjectPublicKey {
            x: coordinates(&public_key(&scalar(subject_scalar))?)?.0,
            y: coordinates(&public_key(&scalar(subject_scalar))?)?.1,
        },
        response_credential_hash_algorithm,
        binding.claims_root,
        binding.issuance_binding,
    )
    .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
    let private_lineage = stored.private_lineage();
    let private_lineage_root = Zeroizing::new(*private_lineage.root());
    let relationship_did_hash =
        Zeroizing::new(hash_parts(&[private_lineage.relationship_did().as_bytes()]));
    let relationship_nonce = Zeroizing::new(*private_lineage.nonce());
    let private_claims = stored.into_prepared_claims();
    Ok(VerifiedZkStoredCredential {
        envelope,
        binding,
        status_list,
        private_claims,
        private_lineage_root,
        relationship_did_hash,
        relationship_nonce,
    })
}

fn common_credential_root_credential_hash_algorithm(
    hash_alg: &str,
) -> Result<ZkCredentialHashAlgorithm, HarnessError> {
    match hash_alg {
        "sha-256" => Ok(ZkCredentialHashAlgorithm::Sha256),
        "poseidon2-bn254" => Ok(ZkCredentialHashAlgorithm::Poseidon2),
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

fn verify_issuer_claims_root(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proposed_root: [u8; 32],
    opaque_lineage_claim_digest: [u8; 32],
    claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<(), HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            verify_common_credential_root_sha256_issuer_claims_root(
                proposed_root,
                opaque_lineage_claim_digest,
                claims,
            )
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            verify_common_credential_root_poseidon2_issuer_claims_root(
                proposed_root,
                opaque_lineage_claim_digest,
                claims,
            )
        }
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    }
    .map(|_| ())
    .map_err(|_| HarnessError::InvalidPresentationAccepted)
}

fn signed_vci_proof(subject_scalar: u8, subject_public: &[u8]) -> Result<String, HarnessError> {
    let (x, y) = coordinates(subject_public)?;
    let header = serde_json::to_vec(&json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": bytes_to_base64url(&x),
            "y": bytes_to_base64url(&y),
        },
    }))?;
    let claims = serde_json::to_vec(&json!({
        "aud": "https://issuer.example",
        "nonce": "issuance-nonce",
        "iat": 1_700_000_000_u64,
        "key_binding_id": "holder-tag",
    }))?;
    let signing_input = format!(
        "{}.{}",
        bytes_to_base64url(&header),
        bytes_to_base64url(&claims)
    );
    let signature = sign_raw(&scalar(subject_scalar), signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        bytes_to_base64url(&signature)
    ))
}

fn binding_from_proto(
    value: &vci_pb::ReallyMeZkV1ProofBinding,
) -> Result<CredentialProofBinding, HarnessError> {
    if value.version != 1 {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    fn bytes<const N: usize>(value: &[u8]) -> Result<[u8; N], HarnessError> {
        value.try_into().map_err(|_| HarnessError::InvalidLength)
    }
    Ok(CredentialProofBinding {
        version: value.version,
        envelope_hash: bytes(&value.envelope_hash)?,
        claims_root: bytes(&value.claims_root)?,
        issuer_public_key_x: bytes(&value.issuer_public_key_x)?,
        issuer_public_key_y: bytes(&value.issuer_public_key_y)?,
        subject_public_key_x: bytes(&value.subject_public_key_x)?,
        subject_public_key_y: bytes(&value.subject_public_key_y)?,
        issuer_envelope_signature: bytes(&value.issuer_envelope_signature)?,
        issuer_root_binding_signature: bytes(&value.issuer_root_binding_signature)?,
        issuer_subject_binding_signature: bytes(&value.issuer_subject_binding_signature)?,
        issuer_validity_status_signature: bytes(&value.issuer_validity_status_signature)?,
        issuance_binding: bytes(&value.issuance_binding)?,
    })
}
