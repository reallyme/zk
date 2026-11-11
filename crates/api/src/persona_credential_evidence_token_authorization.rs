// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persona authorization transcript for a private one-time prepared token.

use crypto_sha2_256::digest as sha2_256_digest;

use crate::persona_evidence::{
    ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceValidityWindow,
};

const DOMAIN: &[u8; 7] = b"PKAUTH1";
const COMPRESSED_KEY_BYTES: usize = 33;
const TOKEN_NONCE_BYTES: usize = 32;
const TIME_BYTES: usize = 8;
const PREIMAGE_BYTES: usize =
    DOMAIN.len() + COMPRESSED_KEY_BYTES + TOKEN_NONCE_BYTES + 2 * TIME_BYTES;

/// Digest signed by a hidden persona to authorize exactly one holder key,
/// token nonce, and prepared interval. The private claim circuit checks this
/// same PKAUTH1 transcript before accepting the one-time holder key.
#[must_use]
pub fn persona_credential_evidence_private_token_authorization_digest(
    holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
    token_nonce: [u8; TOKEN_NONCE_BYTES],
    proof_window: ZkPersonaCredentialEvidenceValidityWindow,
) -> [u8; 32] {
    let mut preimage = [0_u8; PREIMAGE_BYTES];
    preimage[..DOMAIN.len()].copy_from_slice(DOMAIN);
    let key_start = DOMAIN.len();
    preimage[key_start] = if holder_key.y[31] & 1 == 1 {
        0x03
    } else {
        0x02
    };
    preimage[key_start + 1..key_start + COMPRESSED_KEY_BYTES].copy_from_slice(&holder_key.x);
    let nonce_start = key_start + COMPRESSED_KEY_BYTES;
    preimage[nonce_start..nonce_start + TOKEN_NONCE_BYTES].copy_from_slice(&token_nonce);
    let from_start = nonce_start + TOKEN_NONCE_BYTES;
    preimage[from_start..from_start + TIME_BYTES]
        .copy_from_slice(&proof_window.valid_from_unix().to_be_bytes());
    let until_start = from_start + TIME_BYTES;
    preimage[until_start..until_start + TIME_BYTES]
        .copy_from_slice(&proof_window.valid_until_unix().to_be_bytes());
    sha2_256_digest(preimage.as_slice()).into_bytes()
}

#[cfg(test)]
#[path = "persona_credential_evidence_token_authorization/tests.rs"]
mod tests;
