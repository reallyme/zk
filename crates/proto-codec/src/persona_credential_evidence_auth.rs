// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict transcript construction for persona credential evidence presentations.
//!
//! The authenticated request is constructed by the protocol adapter from a
//! verified origin and policy. Presentation-supplied request bytes are never
//! an authority for those fields. Both direct and OpenID4VP adapters use this
//! codec so that a signature cannot acquire different meanings by transport.

use buffa::{DecodeOptions, EnumValue, Message};
pub use reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode;
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const DIGEST_BYTES: usize = 32;
const REQUEST_DOMAIN: &[u8; 8] = b"RMPREQ1\0";
const AUTH_DOMAIN: &[u8; 8] = b"RMPAUTH1";
pub(crate) const REQUEST_WIRE_LIMIT: usize = 256;
pub(crate) const AUTH_WIRE_LIMIT: usize = 128;
pub(crate) const RECURSION_LIMIT: u32 = 4;

/// A supported source protocol for the authenticated verifier request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZkPersonaCredentialEvidenceRequestProtocol {
    /// Native ReallyMe request verified by the direct adapter.
    ReallyMeDirect,
    /// OpenID4VP request verified by the OpenID4VP adapter.
    OpenId4Vp,
}

/// A supported response mode, bound into the request digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZkPersonaCredentialEvidenceResponseMode {
    /// Direct ReallyMe response.
    Direct,
    /// OpenID4VP direct_post response.
    DirectPost,
    /// OpenID4VP direct_post.jwt response.
    DirectPostJwt,
    /// OpenID4VP fragment response.
    Fragment,
    /// OpenID4VP form_post response.
    FormPost,
    /// OpenID4VP Digital Credentials API response.
    DcApi,
    /// OpenID4VP encrypted Digital Credentials API response.
    DcApiJwt,
}

/// Stable rejection reason without request contents, proof bytes, or PII.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ZkPersonaCredentialEvidenceAuthReason {
    /// The wire encoding is malformed, noncanonical, or too large.
    #[error("invalid prepared authentication encoding")]
    InvalidEncoding,
    /// A field or mode is unsupported or has the wrong length.
    #[error("invalid prepared authentication field")]
    InvalidField,
    /// The request validity interval is empty or reversed.
    #[error("invalid prepared request interval")]
    InvalidInterval,
    /// The request is not current at the verifier's time.
    #[error("prepared request is not current")]
    NotCurrent,
    /// A verified package or request does not match the signed transcript.
    #[error("prepared authentication binding mismatch")]
    BindingMismatch,
    /// The selected holder key did not sign the canonical authentication.
    #[error("prepared holder signature invalid")]
    InvalidSignature,
}

/// Typed prepared-authentication error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("prepared authentication rejected: {reason}")]
pub struct ZkPersonaCredentialEvidenceAuthError {
    reason: ZkPersonaCredentialEvidenceAuthReason,
}

impl ZkPersonaCredentialEvidenceAuthError {
    /// Return a deterministic, non-sensitive failure reason.
    #[must_use]
    pub const fn reason(self) -> ZkPersonaCredentialEvidenceAuthReason {
        self.reason
    }
}

fn error(reason: ZkPersonaCredentialEvidenceAuthReason) -> ZkPersonaCredentialEvidenceAuthError {
    ZkPersonaCredentialEvidenceAuthError { reason }
}

/// Validated, protocol-neutral request values from an authenticated adapter.
/// A caller must derive digests from the verified request, never from a
/// response or an unauthenticated wallet hint.
pub struct ZkPersonaCredentialEvidenceVerifierRequest {
    /// Authenticated source protocol.
    pub protocol: ZkPersonaCredentialEvidenceRequestProtocol,
    /// Authenticated delivery mode.
    pub response_mode: ZkPersonaCredentialEvidenceResponseMode,
    /// Single-use verifier challenge.
    pub nonce: [u8; DIGEST_BYTES],
    /// SHA-256 of the authenticated verifier identity and origin.
    pub audience_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of canonical transaction data, including the empty-data encoding.
    pub transaction_data_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of the exact requested claims and predicates.
    pub requested_claims_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of the verifier's effective policy.
    pub verifier_policy_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of remaining protocol context, including response destination.
    pub transport_context_sha256: [u8; DIGEST_BYTES],
    /// Start of the authenticated request interval, inclusive.
    pub issued_at_unix: u64,
    /// End of the authenticated request interval, exclusive.
    pub expires_at_unix: u64,
}

impl Drop for ZkPersonaCredentialEvidenceVerifierRequest {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.audience_sha256.zeroize();
        self.transaction_data_sha256.zeroize();
        self.requested_claims_sha256.zeroize();
        self.verifier_policy_sha256.zeroize();
        self.transport_context_sha256.zeroize();
    }
}

impl ZkPersonaCredentialEvidenceVerifierRequest {
    /// Encode the exact request that will be authenticated by the holder.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ZkPersonaCredentialEvidenceAuthError> {
        validate_request(self)?;
        let mut wire = pb::ZkPersonaCredentialEvidenceVerifierRequestV1::default();
        wire.protocol = EnumValue::from(protocol_to_proto(self.protocol));
        wire.response_mode = EnumValue::from(response_mode_to_proto(self.response_mode));
        wire.nonce = self.nonce.to_vec();
        wire.audience_sha256 = self.audience_sha256.to_vec();
        wire.transaction_data_sha256 = self.transaction_data_sha256.to_vec();
        wire.requested_claims_sha256 = self.requested_claims_sha256.to_vec();
        wire.verifier_policy_sha256 = self.verifier_policy_sha256.to_vec();
        wire.transport_context_sha256 = self.transport_context_sha256.to_vec();
        wire.issued_at_unix = self.issued_at_unix;
        wire.expires_at_unix = self.expires_at_unix;
        let encoded = Zeroizing::new(wire.encode_to_vec());
        if encoded.len() > REQUEST_WIRE_LIMIT {
            return Err(error(
                ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding,
            ));
        }
        Ok(encoded)
    }

    /// Digest the canonical request with a distinct domain from the final
    /// presentation-authentication signature transcript.
    pub fn digest(&self) -> Result<Digest32, ZkPersonaCredentialEvidenceAuthError> {
        let encoded = self.encode()?;
        let mut transcript = Zeroizing::new(Vec::new());
        let capacity = REQUEST_DOMAIN
            .len()
            .checked_add(encoded.len())
            .ok_or_else(|| error(ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding))?;
        transcript
            .try_reserve_exact(capacity)
            .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding))?;
        transcript.extend_from_slice(REQUEST_DOMAIN);
        transcript.extend_from_slice(&encoded);
        Ok(Digest32::sha256(&transcript))
    }

    /// Check the exclusive request expiry against the verifier's trusted time.
    pub fn validate_at(&self, now_unix: u64) -> Result<(), ZkPersonaCredentialEvidenceAuthError> {
        validate_request(self)?;
        if now_unix < self.issued_at_unix || now_unix >= self.expires_at_unix {
            return Err(error(ZkPersonaCredentialEvidenceAuthReason::NotCurrent));
        }
        Ok(())
    }
}

/// Decode only canonical bytes with no unknown fields or enum extensions.
pub fn decode_persona_credential_evidence_verifier_request(
    encoded: &[u8],
) -> Result<ZkPersonaCredentialEvidenceVerifierRequest, ZkPersonaCredentialEvidenceAuthError> {
    let wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_element_memory_limit(REQUEST_WIRE_LIMIT)
        .with_max_message_size(REQUEST_WIRE_LIMIT)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidenceVerifierRequestV1>(encoded)
        .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding))?;
    if Zeroizing::new(wire.encode_to_vec()).as_slice() != encoded {
        return Err(error(
            ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding,
        ));
    }
    let request = ZkPersonaCredentialEvidenceVerifierRequest {
        protocol: protocol_from_proto(&wire.protocol)?,
        response_mode: response_mode_from_proto(&wire.response_mode)?,
        nonce: exact_digest(&wire.nonce)?,
        audience_sha256: exact_digest(&wire.audience_sha256)?,
        transaction_data_sha256: exact_digest(&wire.transaction_data_sha256)?,
        requested_claims_sha256: exact_digest(&wire.requested_claims_sha256)?,
        verifier_policy_sha256: exact_digest(&wire.verifier_policy_sha256)?,
        transport_context_sha256: exact_digest(&wire.transport_context_sha256)?,
        issued_at_unix: wire.issued_at_unix,
        expires_at_unix: wire.expires_at_unix,
    };
    validate_request(&request)?;
    Ok(request)
}

/// Canonical holder authentication over validated prepared evidence, current
/// status evidence, and an independently verified request.
pub struct ZkPersonaCredentialEvidencePresentationAuth {
    /// The proof mode that authenticated the selected holder key.
    pub mode: ZkPersonaCredentialEvidenceMode,
    /// SHA-256 of the exact canonical prepared proof package verified by Bob.
    pub evidence_proof_set_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of the exact current-status evidence verified by Bob.
    pub current_state_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of the verified request transcript.
    pub verifier_request_sha256: [u8; DIGEST_BYTES],
}

impl Drop for ZkPersonaCredentialEvidencePresentationAuth {
    fn drop(&mut self) {
        self.evidence_proof_set_sha256.zeroize();
        self.current_state_sha256.zeroize();
        self.verifier_request_sha256.zeroize();
    }
}

impl ZkPersonaCredentialEvidencePresentationAuth {
    /// Bind the exact canonical prepared and current-state package bytes.
    /// Construction does not verify either proof. The verifier must validate
    /// both packages and trusted status before accepting this transcript.
    pub fn from_canonical_packages(
        mode: ZkPersonaCredentialEvidenceMode,
        evidence_proof_set: &[u8],
        current_state: &[u8],
        request: &ZkPersonaCredentialEvidenceVerifierRequest,
    ) -> Result<Self, ZkPersonaCredentialEvidenceAuthError> {
        Ok(Self {
            mode,
            evidence_proof_set_sha256: *Digest32::sha256(evidence_proof_set).as_bytes(),
            current_state_sha256: *Digest32::sha256(current_state).as_bytes(),
            verifier_request_sha256: *request.digest()?.as_bytes(),
        })
    }

    /// Recompute all three bindings from what the verifier actually accepts.
    /// The caller must first verify each package's proof and status semantics.
    pub fn validate_verified_packages(
        &self,
        mode: ZkPersonaCredentialEvidenceMode,
        evidence_proof_set: &[u8],
        current_state: &[u8],
        request: &ZkPersonaCredentialEvidenceVerifierRequest,
    ) -> Result<(), ZkPersonaCredentialEvidenceAuthError> {
        let expected =
            Self::from_canonical_packages(mode, evidence_proof_set, current_state, request)?;
        let matches = self.mode == expected.mode
            && bool::from(
                self.evidence_proof_set_sha256
                    .ct_eq(&expected.evidence_proof_set_sha256),
            )
            && bool::from(
                self.current_state_sha256
                    .ct_eq(&expected.current_state_sha256),
            )
            && bool::from(
                self.verifier_request_sha256
                    .ct_eq(&expected.verifier_request_sha256),
            );
        if !matches {
            return Err(error(
                ZkPersonaCredentialEvidenceAuthReason::BindingMismatch,
            ));
        }
        Ok(())
    }

    /// Encode the single structure signed by either the public persona key or
    /// the private mode's reserved one-time key.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ZkPersonaCredentialEvidenceAuthError> {
        validate_nonzero(&self.evidence_proof_set_sha256)?;
        validate_nonzero(&self.current_state_sha256)?;
        validate_nonzero(&self.verifier_request_sha256)?;
        let mut wire = pb::ZkPersonaCredentialEvidencePresentationAuthV1::default();
        wire.mode_id = EnumValue::from(profile_to_proto(self.mode));
        wire.evidence_proof_set_sha256 = self.evidence_proof_set_sha256.to_vec();
        wire.current_state_sha256 = self.current_state_sha256.to_vec();
        wire.verifier_request_sha256 = self.verifier_request_sha256.to_vec();
        let encoded = Zeroizing::new(wire.encode_to_vec());
        if encoded.len() > AUTH_WIRE_LIMIT {
            return Err(error(
                ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding,
            ));
        }
        Ok(encoded)
    }

    /// Digest to be signed and verified by the selected holder key.
    pub fn signing_digest(&self) -> Result<Digest32, ZkPersonaCredentialEvidenceAuthError> {
        let encoded = self.encode()?;
        let mut transcript = Zeroizing::new(Vec::new());
        let capacity = AUTH_DOMAIN
            .len()
            .checked_add(encoded.len())
            .ok_or_else(|| error(ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding))?;
        transcript
            .try_reserve_exact(capacity)
            .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding))?;
        transcript.extend_from_slice(AUTH_DOMAIN);
        transcript.extend_from_slice(&encoded);
        Ok(Digest32::sha256(&transcript))
    }

    /// Verify the live low-S P-256 signature under the key exposed by the
    /// prepared claim proof. The verifier must first check the proof and its
    /// joins; caller-supplied coordinates alone are not holder authority.
    #[cfg(any(feature = "native", feature = "wasm"))]
    pub fn verify_holder_signature(
        &self,
        holder_x: &[u8; DIGEST_BYTES],
        holder_y: &[u8; DIGEST_BYTES],
        signature_raw: &[u8; 64],
    ) -> Result<(), ZkPersonaCredentialEvidenceAuthError> {
        let mut public_key = [0_u8; 65];
        public_key[0] = 0x04;
        public_key[1..33].copy_from_slice(holder_x);
        public_key[33..65].copy_from_slice(holder_y);
        let der = crypto_p256::p256_ecdsa_jose_signature_to_der(signature_raw)
            .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidSignature))?;
        let digest = self.signing_digest()?;
        // The crypto boundary requires an explicit prehashed value, preventing
        // this digest from being mistaken for message bytes and hashed twice.
        let p256_digest = crypto_p256::P256Sha256Digest::new(*digest.as_bytes());
        crypto_p256::verify_p256_sha256_digest_low_s_der(&der, &p256_digest, &public_key)
            .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidSignature))
    }
}

/// Decode only canonical authentication bytes with the supported mode set.
pub fn decode_persona_credential_evidence_presentation_auth(
    encoded: &[u8],
) -> Result<ZkPersonaCredentialEvidencePresentationAuth, ZkPersonaCredentialEvidenceAuthError> {
    let wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_element_memory_limit(AUTH_WIRE_LIMIT)
        .with_max_message_size(AUTH_WIRE_LIMIT)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidencePresentationAuthV1>(encoded)
        .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding))?;
    if Zeroizing::new(wire.encode_to_vec()).as_slice() != encoded {
        return Err(error(
            ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding,
        ));
    }
    let auth = ZkPersonaCredentialEvidencePresentationAuth {
        mode: profile_from_proto(&wire.mode_id)?,
        evidence_proof_set_sha256: exact_digest(&wire.evidence_proof_set_sha256)?,
        current_state_sha256: exact_digest(&wire.current_state_sha256)?,
        verifier_request_sha256: exact_digest(&wire.verifier_request_sha256)?,
    };
    auth.encode()?;
    Ok(auth)
}

fn validate_request(
    request: &ZkPersonaCredentialEvidenceVerifierRequest,
) -> Result<(), ZkPersonaCredentialEvidenceAuthError> {
    if request.issued_at_unix >= request.expires_at_unix {
        return Err(error(
            ZkPersonaCredentialEvidenceAuthReason::InvalidInterval,
        ));
    }
    for digest in [
        &request.nonce,
        &request.audience_sha256,
        &request.transaction_data_sha256,
        &request.requested_claims_sha256,
        &request.verifier_policy_sha256,
        &request.transport_context_sha256,
    ] {
        validate_nonzero(digest)?;
    }
    match (request.protocol, request.response_mode) {
        (
            ZkPersonaCredentialEvidenceRequestProtocol::ReallyMeDirect,
            ZkPersonaCredentialEvidenceResponseMode::Direct,
        )
        | (
            ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
            ZkPersonaCredentialEvidenceResponseMode::DirectPost,
        )
        | (
            ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
            ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt,
        )
        | (
            ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
            ZkPersonaCredentialEvidenceResponseMode::Fragment,
        )
        | (
            ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
            ZkPersonaCredentialEvidenceResponseMode::FormPost,
        )
        | (
            ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
            ZkPersonaCredentialEvidenceResponseMode::DcApi,
        )
        | (
            ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
            ZkPersonaCredentialEvidenceResponseMode::DcApiJwt,
        ) => Ok(()),
        _ => Err(error(ZkPersonaCredentialEvidenceAuthReason::InvalidField)),
    }
}

fn validate_nonzero(
    bytes: &[u8; DIGEST_BYTES],
) -> Result<(), ZkPersonaCredentialEvidenceAuthError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(error(ZkPersonaCredentialEvidenceAuthReason::InvalidField));
    }
    Ok(())
}

mod wire;
use wire::{
    exact_digest, profile_from_proto, profile_to_proto, protocol_from_proto, protocol_to_proto,
    response_mode_from_proto, response_mode_to_proto,
};

#[cfg(test)]
#[path = "persona_credential_evidence_auth/tests.rs"]
mod tests;
