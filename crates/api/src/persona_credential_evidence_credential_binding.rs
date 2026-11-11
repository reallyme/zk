// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token-specific issuer-credential join for persona credential evidence proofs.
//!
//! Every prepared evidence and status stage derives this value from the same
//! hidden issuer credential and subject. Including the subject key prevents a
//! signed envelope for one subject from joining a persona authorization made
//! by another subject. A fresh token nonce and holder key prevent reuse as a
//! cross-presentation handle.

use crypto_poseidon2::{hash_bytes as poseidon2_hash_bytes, Poseidon2ErrorReason};
use crypto_sha2_256::digest as sha2_256_digest;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    persona_evidence::ZkPersonaCredentialEvidenceValidityWindow,
};

const FIELD_BYTES: usize = 32;
const DOMAIN: &[u8; 6] = b"PRECB2";
const PREIMAGE_BYTES: usize = DOMAIN.len() + (9 * FIELD_BYTES) + (2 * core::mem::size_of::<u64>());

/// P-256 key authenticated by a persona credential evidence claim proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZkPersonaCredentialEvidenceHolderPublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; FIELD_BYTES],
    /// Big-endian affine y coordinate.
    pub y: [u8; FIELD_BYTES],
}

/// Hidden P-256 credential subject key authenticated by the issuer.
/// This is intentionally distinct from the public or one-time holder key.
pub struct ZkPersonaCredentialEvidenceSubjectPublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; FIELD_BYTES],
    /// Big-endian affine y coordinate.
    pub y: [u8; FIELD_BYTES],
}

impl Zeroize for ZkPersonaCredentialEvidenceSubjectPublicKey {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

impl Drop for ZkPersonaCredentialEvidenceSubjectPublicKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceSubjectPublicKey {}

/// Secret credential material and public token context for `PRECB2`.
///
/// This value is consumed by the derivation and wiped even on error. It is not
/// serializable, cloneable, or exposed through a generic debug formatter.
pub struct ZkPersonaCredentialEvidenceBindingInputs {
    /// Issuer key authenticated by the selected stored credential.
    pub issuer_key: ZkIssuerPublicKey,
    /// Hidden issuer credential envelope digest.
    pub envelope_hash: [u8; FIELD_BYTES],
    /// Hidden issuer-signed claim root.
    pub claims_root: [u8; FIELD_BYTES],
    /// Hidden credential subject key authenticated by the issuer.
    pub subject_key: ZkPersonaCredentialEvidenceSubjectPublicKey,
    /// Holder key exposed by the prepared claim proof.
    pub holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
    /// Independent CSPRNG nonce for one prepared token.
    pub token_nonce: [u8; FIELD_BYTES],
    /// Wallet-selected proof interval proven within issuer validity.
    pub proof_window: ZkPersonaCredentialEvidenceValidityWindow,
}

impl Zeroize for ZkPersonaCredentialEvidenceBindingInputs {
    fn zeroize(&mut self) {
        self.issuer_key.x.zeroize();
        self.issuer_key.y.zeroize();
        self.envelope_hash.zeroize();
        self.claims_root.zeroize();
        self.subject_key.x.zeroize();
        self.subject_key.y.zeroize();
        self.holder_key.x.zeroize();
        self.holder_key.y.zeroize();
        self.token_nonce.zeroize();
    }
}

impl Drop for ZkPersonaCredentialEvidenceBindingInputs {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceBindingInputs {}

/// Derive the v1 prepared-credential join used by both hash lanes.
pub fn derive_persona_credential_evidence_binding(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    inputs: ZkPersonaCredentialEvidenceBindingInputs,
) -> Result<[u8; FIELD_BYTES], ZkError> {
    if inputs.token_nonce.iter().all(|byte| *byte == 0)
        || (inputs.subject_key.x.iter().all(|byte| *byte == 0)
            && inputs.subject_key.y.iter().all(|byte| *byte == 0))
        || (inputs.holder_key.x.iter().all(|byte| *byte == 0)
            && inputs.holder_key.y.iter().all(|byte| *byte == 0))
    {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    let mut preimage = Zeroizing::new([0_u8; PREIMAGE_BYTES]);
    preimage[..DOMAIN.len()].copy_from_slice(DOMAIN);
    let mut cursor = DOMAIN.len();
    for field in [
        &inputs.issuer_key.x,
        &inputs.issuer_key.y,
        &inputs.envelope_hash,
        &inputs.claims_root,
        &inputs.subject_key.x,
        &inputs.subject_key.y,
        &inputs.holder_key.x,
        &inputs.holder_key.y,
        &inputs.token_nonce,
    ] {
        write(&mut preimage, &mut cursor, field)?;
    }
    write(
        &mut preimage,
        &mut cursor,
        &inputs.proof_window.valid_from_unix().to_be_bytes(),
    )?;
    write(
        &mut preimage,
        &mut cursor,
        &inputs.proof_window.valid_until_unix().to_be_bytes(),
    )?;
    if cursor != PREIMAGE_BYTES {
        return Err(ZkError::new(ZkErrorReason::LengthOverflow));
    }
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => Ok(sha2_256_digest(preimage.as_slice()).into_bytes()),
        ZkCredentialHashAlgorithm::Poseidon2 => poseidon2_hash_bytes(preimage.as_slice())
            .map(crypto_poseidon2::Poseidon2Digest::into_bytes)
            .map_err(|error| {
                ZkError::new(match error.reason() {
                    Poseidon2ErrorReason::InputTooLong => ZkErrorReason::ClaimPayloadTooLarge,
                    Poseidon2ErrorReason::InvalidLength => ZkErrorReason::LengthOverflow,
                    _ => ZkErrorReason::BackendFailure,
                })
            }),
    }
}

fn write<const N: usize>(
    preimage: &mut [u8; PREIMAGE_BYTES],
    cursor: &mut usize,
    field: &[u8; N],
) -> Result<(), ZkError> {
    let end = cursor
        .checked_add(N)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    preimage
        .get_mut(*cursor..end)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        .copy_from_slice(field);
    *cursor = end;
    Ok(())
}

#[cfg(test)]
#[cfg(any(feature = "native", feature = "wasm"))]
#[path = "persona_credential_evidence_credential_binding/tests.rs"]
mod tests;
