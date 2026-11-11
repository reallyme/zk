// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_p256::{sign_p256_sha256_digest_low_s_der, P256Sha256Digest};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_credential::committed::proof_binding::CredentialProofBinding;
use reallyme_credential::AssuranceLevel;
use reallyme_credential_claims::{
    CredentialAlgorithm, KeyAssurance, KeyReference, PublicKeyRef, PublicKeyRepresentation,
    RawPublicKeySerialization,
};
use reallyme_crypto::p256::{
    generate_p256_keypair_from_secret_key, p256_ecdsa_der_to_jose_signature,
};
use reallyme_identity::zk::ZkIssuanceAssurancePolicy;
use reallyme_zk_api::keys::ZkIssuerPublicKey;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkSensitiveProviderRequest;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::HarnessError;

use super::{PROFILE_ID, STATUS_LIST_INDEX};

pub(super) fn verified_proof(
    binding: &CredentialProofBinding,
) -> Result<openid4vci_issuer::VerifiedProof, HarnessError> {
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&binding.subject_public_key_x);
    public_key.extend_from_slice(&binding.subject_public_key_y);
    openid4vci_issuer::VerifiedProof::new(
        openid4vci_issuer::ProofKind::Jwt,
        Some("issuance-nonce".to_owned()),
        Some("https://issuer.example".to_owned()),
        Some("holder-tag".to_owned()),
        None,
        Some(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": bytes_to_base64url(&binding.subject_public_key_x),
            "y": bytes_to_base64url(&binding.subject_public_key_y),
        })),
        Some(openid4vci_issuer::ConfirmationJwk {
            algorithm: openid4vci_issuer::ProofAlgorithm::Es256,
            public_key,
            key_id: None,
        }),
    )
    .map_err(HarnessError::from)
}

pub(super) fn issuance_policy(status_list_id: [u8; 32]) -> ZkIssuanceAssurancePolicy<'static> {
    ZkIssuanceAssurancePolicy {
        profile_id: PROFILE_ID,
        minimum_assurance: AssuranceLevel::Substantial,
        status_list_id,
        status_list_index: STATUS_LIST_INDEX,
        subject_tag: Some("holder-tag"),
    }
}

pub(super) fn issuer_key(binding: &CredentialProofBinding) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: binding.issuer_public_key_x,
        y: binding.issuer_public_key_y,
    }
}

pub(super) fn scalar(value: u8) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = value;
    secret
}

pub(super) fn public_key(secret: &[u8; 32]) -> Result<Vec<u8>, HarnessError> {
    let (public, _) = generate_p256_keypair_from_secret_key(secret)?;
    let uncompressed = reallyme_crypto::p256::decompress_public_key(public.as_slice())?;
    if uncompressed.len() != 65 || uncompressed.first() != Some(&0x04) {
        return Err(HarnessError::InvalidLength);
    }
    Ok(uncompressed)
}

pub(super) fn raw_key(public: &[u8]) -> PublicKeyRepresentation {
    PublicKeyRepresentation::Raw {
        serialization: RawPublicKeySerialization::Sec1Uncompressed,
        bytes: public.to_vec(),
    }
}

pub(super) fn key_ref(public: &[u8]) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DirectPublicKey,
        public_key: raw_key(public),
        assurance: KeyAssurance::None,
    }
}

pub(super) fn coordinates(public: &[u8]) -> Result<([u8; 32], [u8; 32]), HarnessError> {
    if public.len() != 65 || public.first() != Some(&0x04) {
        return Err(HarnessError::InvalidLength);
    }
    Ok((
        public[1..33]
            .try_into()
            .map_err(|_| HarnessError::InvalidLength)?,
        public[33..65]
            .try_into()
            .map_err(|_| HarnessError::InvalidLength)?,
    ))
}

pub(super) fn coordinates_from_proto(
    key: &pb::ZkInputP256PublicKey,
) -> Result<([u8; 32], [u8; 32]), HarnessError> {
    Ok((input32(&key.x)?, input32(&key.y)?))
}

pub(super) fn sign_raw(secret: &[u8; 32], payload: &[u8]) -> Result<[u8; 64], HarnessError> {
    sign_hash_parts(secret, &[payload])
}

pub(super) fn sign_digest(secret: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64], HarnessError> {
    let digest = P256Sha256Digest::new(*digest);
    let der = sign_p256_sha256_digest_low_s_der(secret, &digest)?;
    p256_ecdsa_der_to_jose_signature(der.as_slice()).map_err(HarnessError::from)
}

fn sign_hash_parts(secret: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; 64], HarnessError> {
    let digest = hash_parts(parts);
    let digest = P256Sha256Digest::new(digest);
    let der = sign_p256_sha256_digest_low_s_der(secret, &digest)?;
    p256_ecdsa_der_to_jose_signature(der.as_slice()).map_err(HarnessError::from)
}

pub(super) fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub(super) fn input32(
    field: &buffa::MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<[u8; 32], HarnessError> {
    field
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn input16(
    field: &buffa::MessageField<pb::ZkInputBytes16, buffa::Inline<pb::ZkInputBytes16>>,
) -> Result<[u8; 16], HarnessError> {
    field
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn input64(
    field: &buffa::MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>,
) -> Result<[u8; 64], HarnessError> {
    field
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn raw32(value: &[u8]) -> Result<[u8; 32], HarnessError> {
    value.try_into().map_err(|_| HarnessError::InvalidLength)
}

pub(super) fn replace32(
    field: &mut buffa::MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
    value: &[u8; 32],
) -> Result<(), HarnessError> {
    let bytes = &mut field
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?
        .value;
    if bytes.len() != 32 {
        return Err(HarnessError::InvalidLength);
    }
    bytes.copy_from_slice(value);
    Ok(())
}

pub(super) fn replace64(
    field: &mut buffa::MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>,
    value: &[u8; 64],
) -> Result<(), HarnessError> {
    let bytes = &mut field
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?
        .value;
    if bytes.len() != 64 {
        return Err(HarnessError::InvalidLength);
    }
    bytes.copy_from_slice(value);
    Ok(())
}

pub(super) fn stage(
    request: &ZkSensitiveProviderRequest,
) -> Result<&pb::ZkCommonCredentialRootStageProveOperation, HarnessError> {
    match request.request().operation.as_ref() {
        Some(pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(
            stage,
        )) => Ok(stage),
        _ => Err(HarnessError::MissingField),
    }
}

pub(super) fn stage_mut(
    request: &mut ZkSensitiveProviderRequest,
) -> Result<&mut pb::ZkCommonCredentialRootStageProveOperation, HarnessError> {
    match request.request_mut().operation.as_mut() {
        Some(pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(
            stage,
        )) => Ok(stage),
        _ => Err(HarnessError::MissingField),
    }
}
