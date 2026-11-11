// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common-credential-root credential binding transcript shared by wallets and SDKs.
//!
//! The lineage and selected-claim circuits publish a request-scoped credential
//! binding. The transcript is hash-lane dependent: SHA-256 lanes use SHA-256,
//! while Poseidon2 lanes use the reviewed ReallyMe Poseidon2 byte sponge.
//! Keeping this derivation here prevents Identity or OpenID4VP adapters from
//! hardcoding circuit offsets or accidentally reusing the SHA-only SSI helper.

use crypto_poseidon2::{hash_bytes as poseidon2_hash_bytes, Poseidon2ErrorReason};
use crypto_sha2_256::digest as sha2_256_digest;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::ZkCommonCredentialRootRequestJoinContext,
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
};

const FIELD_BYTES: usize = 32;
const CREDENTIAL_BINDING_DOMAIN: &[u8; 6] = b"CREDB1";
const CREDENTIAL_BINDING_PREIMAGE_BYTES: usize =
    CREDENTIAL_BINDING_DOMAIN.len() + (7 * FIELD_BYTES) + core::mem::size_of::<u64>();

/// Authenticated selected credential material used by the common-credential-root circuits.
#[derive(PartialEq, Eq)]
pub struct ZkCommonCredentialRootCredentialBindingInputs {
    /// Issuer public key authenticated by the selected stored credential.
    pub issuer_key: ZkIssuerPublicKey,
    /// Credential envelope digest authenticated by the issuer.
    pub envelope_hash: [u8; FIELD_BYTES],
    /// Issuer claim-root digest authenticated by the issuer.
    pub claims_root: [u8; FIELD_BYTES],
    /// Active verifier request binding.
    pub request: ZkCommonCredentialRootRequestJoinContext,
    /// Presentation expiry used by the selected stage.
    pub expiry_unix: u64,
}

impl Zeroize for ZkCommonCredentialRootCredentialBindingInputs {
    fn zeroize(&mut self) {
        self.issuer_key.x.zeroize();
        self.issuer_key.y.zeroize();
        self.envelope_hash.zeroize();
        self.claims_root.zeroize();
        self.request.challenge.zeroize();
        self.request.audience_hash.zeroize();
        self.request.transaction_data_hash.zeroize();
        self.expiry_unix.zeroize();
    }
}

impl Drop for ZkCommonCredentialRootCredentialBindingInputs {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootCredentialBindingInputs {}

/// Derive the public credential binding expected in common-credential-root lineage outputs.
pub fn derive_common_credential_root_credential_binding(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    inputs: ZkCommonCredentialRootCredentialBindingInputs,
) -> Result<[u8; FIELD_BYTES], ZkError> {
    let mut preimage = Zeroizing::new([0_u8; CREDENTIAL_BINDING_PREIMAGE_BYTES]);
    preimage[..CREDENTIAL_BINDING_DOMAIN.len()].copy_from_slice(CREDENTIAL_BINDING_DOMAIN);
    let mut cursor = CREDENTIAL_BINDING_DOMAIN.len();
    write_field(&mut preimage, &mut cursor, &inputs.issuer_key.x)?;
    write_field(&mut preimage, &mut cursor, &inputs.issuer_key.y)?;
    write_field(&mut preimage, &mut cursor, &inputs.envelope_hash)?;
    write_field(&mut preimage, &mut cursor, &inputs.claims_root)?;
    write_field(&mut preimage, &mut cursor, &inputs.request.challenge)?;
    write_field(&mut preimage, &mut cursor, &inputs.request.audience_hash)?;
    write_field(
        &mut preimage,
        &mut cursor,
        &inputs.request.transaction_data_hash,
    )?;
    let expiry_end = cursor
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    preimage
        .get_mut(cursor..expiry_end)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        .copy_from_slice(&inputs.expiry_unix.to_be_bytes());

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

fn write_field(
    preimage: &mut [u8; CREDENTIAL_BINDING_PREIMAGE_BYTES],
    cursor: &mut usize,
    field: &[u8; FIELD_BYTES],
) -> Result<(), ZkError> {
    let end = cursor
        .checked_add(FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    preimage
        .get_mut(*cursor..end)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        .copy_from_slice(field);
    *cursor = end;
    Ok(())
}

#[cfg(test)]
#[path = "common_credential_root_credential_binding/tests.rs"]
mod tests;
