// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common-credential-root persona transcripts shared by wallets and proof adapters.
//!
//! These helpers mirror the fixed SHA-256 transcripts consumed by the Noir
//! common-credential-root v1 persona circuits. Keeping them in the proof-system-agnostic
//! API prevents SDK adapters from copying fixture-generation logic when they
//! need to sign request-bound holder/persona authorizations.

use crypto_poseidon2::{hash_bytes as poseidon2_hash_bytes, Poseidon2ErrorReason};
use crypto_sha2_256::digest as sha2_256_digest;

use crate::{
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootRequestJoinContext,
        ZkCommonCredentialRootSubjectPublicKey,
    },
    errors::{ZkError, ZkErrorReason},
};

const FIELD_BYTES: usize = 32;
const COMPRESSED_P256_BYTES: usize = 33;
const P256_COMPRESSED_EVEN_Y: u8 = 0x02;
const P256_COMPRESSED_ODD_Y: u8 = 0x03;
const PUBLIC_PERSONA_SESSION_BINDING_DOMAIN: &[u8; 6] = b"PSESB1";
const PRIVATE_PERSONA_SESSION_BINDING_DOMAIN: &[u8; 6] = b"PSESB2";
const PUBLIC_PERSONA_AUTHORIZATION_DOMAIN: &[u8; 5] = b"PERS1";
const PRIVATE_PERSONA_AUTHORIZATION_DOMAIN: &[u8; 5] = b"PERS2";
const SUBJECT_PERSONA_LINK_DOMAIN: &[u8; 5] = b"LINK1";
const SESSION_BINDING_PREIMAGE_BYTES: usize =
    PRIVATE_PERSONA_SESSION_BINDING_DOMAIN.len() + (5 * FIELD_BYTES) + 8;
const SESSION_AUTHORIZATION_PREIMAGE_BYTES: usize =
    PRIVATE_PERSONA_AUTHORIZATION_DOMAIN.len() + (3 * FIELD_BYTES) + 8;
const SUBJECT_PERSONA_LINK_PREIMAGE_BYTES: usize =
    SUBJECT_PERSONA_LINK_DOMAIN.len() + COMPRESSED_P256_BYTES;
const LINK_DOMAIN_END: usize = SUBJECT_PERSONA_LINK_DOMAIN.len();
const LINK_COMPRESSED_START: usize = LINK_DOMAIN_END;
const LINK_COMPRESSED_END: usize = SUBJECT_PERSONA_LINK_PREIMAGE_BYTES;
const AUTH_DOMAIN_END: usize = PRIVATE_PERSONA_AUTHORIZATION_DOMAIN.len();
const AUTH_CHALLENGE_START: usize = AUTH_DOMAIN_END;
const AUTH_CHALLENGE_END: usize = AUTH_CHALLENGE_START + FIELD_BYTES;
const AUTH_AUDIENCE_START: usize = AUTH_CHALLENGE_END;
const AUTH_AUDIENCE_END: usize = AUTH_AUDIENCE_START + FIELD_BYTES;
const AUTH_TRANSACTION_START: usize = AUTH_AUDIENCE_END;
const AUTH_TRANSACTION_END: usize = AUTH_TRANSACTION_START + FIELD_BYTES;
const AUTH_EXPIRY_START: usize = AUTH_TRANSACTION_END;
const AUTH_EXPIRY_END: usize = SESSION_AUTHORIZATION_PREIMAGE_BYTES;
const BIND_DOMAIN_END: usize = PRIVATE_PERSONA_SESSION_BINDING_DOMAIN.len();
const BIND_PERSONA_X_START: usize = BIND_DOMAIN_END;
const BIND_PERSONA_X_END: usize = BIND_PERSONA_X_START + FIELD_BYTES;
const BIND_PERSONA_Y_START: usize = BIND_PERSONA_X_END;
const BIND_PERSONA_Y_END: usize = BIND_PERSONA_Y_START + FIELD_BYTES;
const BIND_CHALLENGE_START: usize = BIND_PERSONA_Y_END;
const BIND_CHALLENGE_END: usize = BIND_CHALLENGE_START + FIELD_BYTES;
const BIND_AUDIENCE_START: usize = BIND_CHALLENGE_END;
const BIND_AUDIENCE_END: usize = BIND_AUDIENCE_START + FIELD_BYTES;
const BIND_TRANSACTION_START: usize = BIND_AUDIENCE_END;
const BIND_TRANSACTION_END: usize = BIND_TRANSACTION_START + FIELD_BYTES;
const BIND_EXPIRY_START: usize = BIND_TRANSACTION_END;
const BIND_EXPIRY_END: usize = SESSION_BINDING_PREIMAGE_BYTES;

/// Return the SEC1 compressed encoding used by the common-credential-root link circuit.
///
/// The circuit uses the standard parity-prefixed P-256 public key. This
/// serialization helper does not establish curve membership: callers must
/// admit the holder key through their authenticated key boundary before using
/// this value in a signature or proof request.
#[must_use]
pub fn common_credential_root_sha256_compressed_persona_key(
    persona_key: ZkCommonCredentialRootSubjectPublicKey,
) -> [u8; COMPRESSED_P256_BYTES] {
    let mut compressed = [0_u8; COMPRESSED_P256_BYTES];
    compressed[0] = if persona_key.y[FIELD_BYTES - 1] & 1 == 1 {
        P256_COMPRESSED_ODD_Y
    } else {
        P256_COMPRESSED_EVEN_Y
    };
    compressed[1..].copy_from_slice(&persona_key.x);
    compressed
}

/// Digest signed by the credential subject to authorize a persona key.
///
/// Selected-claim circuits verify this digest with the credential subject key
/// and the `subject_link_sig` witness. The digest is intentionally independent
/// of the verifier session; a wallet may rotate persona keys by policy. The
/// separate session proof requires live control of this same linked key.
#[must_use]
pub fn common_credential_root_sha256_subject_persona_link(
    persona_key: ZkCommonCredentialRootSubjectPublicKey,
) -> [u8; FIELD_BYTES] {
    let compressed = common_credential_root_sha256_compressed_persona_key(persona_key);
    let mut preimage = [0_u8; SUBJECT_PERSONA_LINK_PREIMAGE_BYTES];
    preimage[..LINK_DOMAIN_END].copy_from_slice(SUBJECT_PERSONA_LINK_DOMAIN);
    preimage[LINK_COMPRESSED_START..LINK_COMPRESSED_END].copy_from_slice(&compressed);
    sha2_256_digest(preimage.as_slice()).into_bytes()
}

/// Poseidon2 digest signed by the credential subject to authorize a persona key.
///
/// This is the Poseidon2-lane equivalent of
/// [`common_credential_root_sha256_subject_persona_link`]. It uses the shared ReallyMe
/// crypto byte sponge so Rust, mobile, and Noir transcript code share one
/// reviewed implementation.
pub fn common_credential_root_poseidon2_subject_persona_link(
    persona_key: ZkCommonCredentialRootSubjectPublicKey,
) -> Result<[u8; FIELD_BYTES], ZkError> {
    let compressed = common_credential_root_sha256_compressed_persona_key(persona_key);
    let mut preimage = [0_u8; SUBJECT_PERSONA_LINK_PREIMAGE_BYTES];
    preimage[..LINK_DOMAIN_END].copy_from_slice(SUBJECT_PERSONA_LINK_DOMAIN);
    preimage[LINK_COMPRESSED_START..LINK_COMPRESSED_END].copy_from_slice(&compressed);
    poseidon2_digest(preimage.as_slice())
}

/// Digest signed by the persona key for this exact OpenID4VP request.
///
/// Private persona mode signs `PERS2`; public persona mode signs `PERS1`.
/// Both modes bind the verifier challenge, audience, transaction-data hash,
/// and presentation expiry without exposing credential-private material.
#[must_use]
pub fn common_credential_root_sha256_persona_session_authorization(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    request: ZkCommonCredentialRootRequestJoinContext,
    expiry_unix: u64,
) -> [u8; FIELD_BYTES] {
    let domain = persona_authorization_domain(persona_mode);
    let mut preimage = [0_u8; SESSION_AUTHORIZATION_PREIMAGE_BYTES];
    preimage[..AUTH_DOMAIN_END].copy_from_slice(domain);
    preimage[AUTH_CHALLENGE_START..AUTH_CHALLENGE_END].copy_from_slice(&request.challenge);
    preimage[AUTH_AUDIENCE_START..AUTH_AUDIENCE_END].copy_from_slice(&request.audience_hash);
    preimage[AUTH_TRANSACTION_START..AUTH_TRANSACTION_END]
        .copy_from_slice(&request.transaction_data_hash);
    preimage[AUTH_EXPIRY_START..AUTH_EXPIRY_END].copy_from_slice(&expiry_unix.to_be_bytes());
    sha2_256_digest(preimage.as_slice()).into_bytes()
}

/// Poseidon2 digest signed by the persona key for this exact OpenID4VP request.
pub fn common_credential_root_poseidon2_persona_session_authorization(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    request: ZkCommonCredentialRootRequestJoinContext,
    expiry_unix: u64,
) -> Result<[u8; FIELD_BYTES], ZkError> {
    let domain = persona_authorization_domain(persona_mode);
    let mut preimage = [0_u8; SESSION_AUTHORIZATION_PREIMAGE_BYTES];
    preimage[..AUTH_DOMAIN_END].copy_from_slice(domain);
    preimage[AUTH_CHALLENGE_START..AUTH_CHALLENGE_END].copy_from_slice(&request.challenge);
    preimage[AUTH_AUDIENCE_START..AUTH_AUDIENCE_END].copy_from_slice(&request.audience_hash);
    preimage[AUTH_TRANSACTION_START..AUTH_TRANSACTION_END]
        .copy_from_slice(&request.transaction_data_hash);
    preimage[AUTH_EXPIRY_START..AUTH_EXPIRY_END].copy_from_slice(&expiry_unix.to_be_bytes());
    poseidon2_digest(preimage.as_slice())
}

/// Public session binding expected by common-credential-root persona and claim proofs.
///
/// Private persona mode hashes `PSESB2`; public persona mode hashes `PSESB1`.
/// The selected-claim stages and session stage must publish this same value.
#[must_use]
pub fn common_credential_root_sha256_persona_session_binding(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    persona_key: ZkCommonCredentialRootSubjectPublicKey,
    request: ZkCommonCredentialRootRequestJoinContext,
    expiry_unix: u64,
) -> [u8; FIELD_BYTES] {
    let domain = persona_session_binding_domain(persona_mode);
    let mut preimage = [0_u8; SESSION_BINDING_PREIMAGE_BYTES];
    preimage[..BIND_DOMAIN_END].copy_from_slice(domain);
    preimage[BIND_PERSONA_X_START..BIND_PERSONA_X_END].copy_from_slice(&persona_key.x);
    preimage[BIND_PERSONA_Y_START..BIND_PERSONA_Y_END].copy_from_slice(&persona_key.y);
    preimage[BIND_CHALLENGE_START..BIND_CHALLENGE_END].copy_from_slice(&request.challenge);
    preimage[BIND_AUDIENCE_START..BIND_AUDIENCE_END].copy_from_slice(&request.audience_hash);
    preimage[BIND_TRANSACTION_START..BIND_TRANSACTION_END]
        .copy_from_slice(&request.transaction_data_hash);
    preimage[BIND_EXPIRY_START..BIND_EXPIRY_END].copy_from_slice(&expiry_unix.to_be_bytes());
    sha2_256_digest(preimage.as_slice()).into_bytes()
}

/// Poseidon2 public session binding expected by common-credential-root persona proofs.
pub fn common_credential_root_poseidon2_persona_session_binding(
    persona_mode: ZkCommonCredentialRootPersonaMode,
    persona_key: ZkCommonCredentialRootSubjectPublicKey,
    request: ZkCommonCredentialRootRequestJoinContext,
    expiry_unix: u64,
) -> Result<[u8; FIELD_BYTES], ZkError> {
    let domain = persona_session_binding_domain(persona_mode);
    let mut preimage = [0_u8; SESSION_BINDING_PREIMAGE_BYTES];
    preimage[..BIND_DOMAIN_END].copy_from_slice(domain);
    preimage[BIND_PERSONA_X_START..BIND_PERSONA_X_END].copy_from_slice(&persona_key.x);
    preimage[BIND_PERSONA_Y_START..BIND_PERSONA_Y_END].copy_from_slice(&persona_key.y);
    preimage[BIND_CHALLENGE_START..BIND_CHALLENGE_END].copy_from_slice(&request.challenge);
    preimage[BIND_AUDIENCE_START..BIND_AUDIENCE_END].copy_from_slice(&request.audience_hash);
    preimage[BIND_TRANSACTION_START..BIND_TRANSACTION_END]
        .copy_from_slice(&request.transaction_data_hash);
    preimage[BIND_EXPIRY_START..BIND_EXPIRY_END].copy_from_slice(&expiry_unix.to_be_bytes());
    poseidon2_digest(preimage.as_slice())
}

fn poseidon2_digest(preimage: &[u8]) -> Result<[u8; FIELD_BYTES], ZkError> {
    poseidon2_hash_bytes(preimage)
        .map(crypto_poseidon2::Poseidon2Digest::into_bytes)
        .map_err(|error| {
            ZkError::new(match error.reason() {
                Poseidon2ErrorReason::InputTooLong => ZkErrorReason::ClaimPayloadTooLarge,
                Poseidon2ErrorReason::InvalidLength => ZkErrorReason::LengthOverflow,
                _ => ZkErrorReason::BackendFailure,
            })
        })
}

const fn persona_session_binding_domain(
    mode: ZkCommonCredentialRootPersonaMode,
) -> &'static [u8; 6] {
    match mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => PRIVATE_PERSONA_SESSION_BINDING_DOMAIN,
        ZkCommonCredentialRootPersonaMode::PublicPersona => PUBLIC_PERSONA_SESSION_BINDING_DOMAIN,
    }
}

const fn persona_authorization_domain(mode: ZkCommonCredentialRootPersonaMode) -> &'static [u8; 5] {
    match mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => PRIVATE_PERSONA_AUTHORIZATION_DOMAIN,
        ZkCommonCredentialRootPersonaMode::PublicPersona => PUBLIC_PERSONA_AUTHORIZATION_DOMAIN,
    }
}

#[cfg(test)]
#[path = "common_credential_root_persona/tests.rs"]
mod tests;
