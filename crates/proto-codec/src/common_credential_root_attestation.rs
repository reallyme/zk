// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical private root-assurance attestation record.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::{common_root::ZkRootAssuranceAttestation, keys::ZkAttestationPublicKey};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FORMAT_VERSION: u32 = 1;
const RECURSION_LIMIT: u32 = 8;
/// Maximum canonical root-assurance attestation wire size.
pub const MAX_ROOT_ASSURANCE_ATTESTATION_BYTES: usize = 256;

// Buffa owns copies of the reusable private commitment and its signed record.
// Keep those copies behind a cleanup owner on successful and rejected decodes.
struct SensitiveAttestationMessage(pb::ZkRootAssuranceAttestation);

impl Drop for SensitiveAttestationMessage {
    fn drop(&mut self) {
        self.0.root_commitment.zeroize();
        self.0.assurance_policy_id.zeroize();
        self.0.signature.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveAttestationMessage {}

/// Stable failure category for a private root-assurance record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkRootAssuranceCodecReason {
    /// The record is too large, malformed, or not canonical protobuf.
    #[error("invalid root assurance encoding")]
    InvalidEncoding,
}

/// Typed codec error without the commitment, signer, or signature.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("root assurance codec rejected: {reason}")]
pub struct ZkRootAssuranceCodecError {
    reason: ZkRootAssuranceCodecReason,
}

impl ZkRootAssuranceCodecError {
    /// Return the stable, non-sensitive failure reason.
    #[must_use]
    pub const fn reason(self) -> ZkRootAssuranceCodecReason {
        self.reason
    }
}

/// Encode a shape-validated record for authenticated encrypted wallet storage.
pub fn encode_root_assurance_attestation(
    attestation: &ZkRootAssuranceAttestation,
) -> Result<Zeroizing<Vec<u8>>, ZkRootAssuranceCodecError> {
    let mut wire = SensitiveAttestationMessage(pb::ZkRootAssuranceAttestation::default());
    wire.0.format_version = FORMAT_VERSION;
    wire.0.root_commitment = attestation.root_commitment().to_vec();
    wire.0.assurance_policy_id = attestation.assurance_policy_id().to_vec();
    wire.0.issued_unix = attestation.issued_unix();
    wire.0.expires_unix = attestation.expires_unix();
    wire.0.epoch = attestation.epoch();
    wire.0.signer = MessageField::some(pb::ZkP256PublicKey {
        x: attestation.signer().x.to_vec(),
        y: attestation.signer().y.to_vec(),
        ..Default::default()
    });
    wire.0.signature = attestation.signature().to_vec();
    let encoded = Zeroizing::new(wire.0.encode_to_vec());
    if encoded.len() > MAX_ROOT_ASSURANCE_ATTESTATION_BYTES {
        return Err(invalid());
    }
    Ok(encoded)
}

/// Decode canonical bytes; the wallet must then verify root, signer, and policy.
pub fn decode_root_assurance_attestation(
    bytes: &[u8],
) -> Result<ZkRootAssuranceAttestation, ZkRootAssuranceCodecError> {
    if bytes.is_empty() || bytes.len() > MAX_ROOT_ASSURANCE_ATTESTATION_BYTES {
        return Err(invalid());
    }
    let mut wire = SensitiveAttestationMessage(
        DecodeOptions::new()
            .with_recursion_limit(RECURSION_LIMIT)
            .with_element_memory_limit(MAX_ROOT_ASSURANCE_ATTESTATION_BYTES)
            .with_max_message_size(MAX_ROOT_ASSURANCE_ATTESTATION_BYTES)
            .with_unknown_field_limit(0)
            .decode_from_slice::<pb::ZkRootAssuranceAttestation>(bytes)
            .map_err(|_| invalid())?,
    );
    let canonical = Zeroizing::new(wire.0.encode_to_vec());
    if wire.0.format_version != FORMAT_VERSION || canonical.as_slice() != bytes {
        return Err(invalid());
    }
    let signer = wire.0.signer.take().ok_or_else(invalid)?;
    let signer = ZkAttestationPublicKey {
        x: fixed::<32>(&signer.x)?,
        y: fixed::<32>(&signer.y)?,
    };
    ZkRootAssuranceAttestation::try_from_signed_parts(
        fixed::<32>(&wire.0.root_commitment)?,
        fixed::<32>(&wire.0.assurance_policy_id)?,
        wire.0.issued_unix,
        wire.0.expires_unix,
        wire.0.epoch,
        signer,
        fixed::<64>(&wire.0.signature)?,
    )
    .map_err(|_| invalid())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ZkRootAssuranceCodecError> {
    bytes.try_into().map_err(|_| invalid())
}

const fn invalid() -> ZkRootAssuranceCodecError {
    ZkRootAssuranceCodecError {
        reason: ZkRootAssuranceCodecReason::InvalidEncoding,
    }
}

#[cfg(test)]
#[path = "common_credential_root_attestation/tests.rs"]
mod tests;
