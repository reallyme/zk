// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Format-specific plaintext for a wallet-encrypted ZK credential record.
//!
//! The codec authenticates private openings against caller-supplied issuer
//! evidence, but encryption, key custody, and receipt verification belong to
//! the Wallet. Neither this message nor its encoded bytes may be stored bare.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootPrivateLineageMaterial,
        ZkCommonCredentialRootSubjectPublicKey, MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::common_credential_root_private_claims::{
    decode_prepared_claims_for_lane, encode_prepared_claims,
};

/// Current wallet-encrypted ZK credential record format.
pub const ZK_WALLET_STORED_CREDENTIAL_FORMAT_VERSION: u32 = 2;
/// Maximum relationship identifier admitted by the versioned encrypted record.
pub const MAX_ZK_RELATIONSHIP_DID_BYTES: usize = MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES;
const MAX_CREDENTIAL_ENVELOPE_PROTO_BYTES: usize = 1024 * 1024;
const MAX_PREPARED_CLAIMS_PROTO_BYTES: usize = 32 * 1024;
const MAX_STORED_CREDENTIAL_BYTES: usize = MAX_CREDENTIAL_ENVELOPE_PROTO_BYTES
    + MAX_PREPARED_CLAIMS_PROTO_BYTES
    + MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES
    + 1024;
const PROTO_RECURSION_LIMIT: u32 = 16;

// Encoding and decoding through Buffa allocate separate owned copies of the
// encrypted-record plaintext. Keep the generated message behind an owner that
// wipes both byte fields on normal return and on validation failures.
struct SensitiveStoredMessage(pb::ZkWalletStoredCredential);

impl Drop for SensitiveStoredMessage {
    fn drop(&mut self) {
        self.0.credential_pb.zeroize();
        self.0.prepared_claims_pb.zeroize();
        if let Some(lineage) = self.0.private_lineage.as_option_mut() {
            lineage.root.zeroize();
            lineage.relationship_did.zeroize();
            lineage.nonce.zeroize();
        }
    }
}

impl ZeroizeOnDrop for SensitiveStoredMessage {}

/// Stable, non-sensitive reason for rejecting wallet-private record bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkWalletStoredCredentialReason {
    /// The protected payload is malformed, oversized, or has an unsupported version.
    #[error("invalid protected credential payload")]
    InvalidEncoding,
    /// Private openings do not match this issuer-authenticated credential.
    #[error("private claim binding mismatch")]
    PrivateClaimMismatch,
    /// The encrypted lineage input does not reconstruct the signed claim tree.
    #[error("private lineage binding mismatch")]
    PrivateLineageMismatch,
}

/// Error returned by the wallet-private credential codec.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("protected ZK credential conversion failed: {reason}")]
pub struct ZkWalletStoredCredentialError {
    reason: ZkWalletStoredCredentialReason,
}

impl ZkWalletStoredCredentialError {
    /// Return the stable failure reason without logging protected data.
    #[must_use]
    pub const fn reason(self) -> ZkWalletStoredCredentialReason {
        self.reason
    }
}

/// Validated private openings and the original OpenID4VCI envelope protobuf.
///
/// The caller must validate the returned envelope as an issuer receipt before
/// using its claims. Its bytes remain owned and zeroize when dropped.
pub struct ZkWalletStoredCredential {
    credential_envelope_pb: Zeroizing<Vec<u8>>,
    prepared_claims: ZkCommonCredentialRootClaimsCommitment,
    private_lineage: ZkCommonCredentialRootPrivateLineageMaterial,
}

impl ZkWalletStoredCredential {
    /// Borrow the original credential-envelope protobuf for issuer validation.
    #[must_use]
    pub fn credential_envelope_pb(&self) -> &[u8] {
        &self.credential_envelope_pb
    }

    /// Borrow openings that have already matched the authenticated root.
    #[must_use]
    pub const fn prepared_claims(&self) -> &ZkCommonCredentialRootClaimsCommitment {
        &self.prepared_claims
    }

    /// Borrow lineage inputs only while constructing a validated private witness.
    #[must_use]
    pub const fn private_lineage(&self) -> &ZkCommonCredentialRootPrivateLineageMaterial {
        &self.private_lineage
    }

    /// Transfer validated openings to the witness owner after receipt checks.
    #[must_use]
    pub fn into_prepared_claims(self) -> ZkCommonCredentialRootClaimsCommitment {
        self.prepared_claims
    }
}

/// Encode only after the received issuer credential and status are validated.
///
/// `issuer_root` and `issuance_binding` must come from that receipt. The
/// returned bytes are plaintext for the wallet's authenticated encryption.
pub fn encode_wallet_stored_credential(
    credential_envelope_pb: &[u8],
    prepared_claims: &ZkCommonCredentialRootClaimsCommitment,
    private_lineage: &ZkCommonCredentialRootPrivateLineageMaterial,
    issuer_key: ZkIssuerPublicKey,
    subject_key: ZkCommonCredentialRootSubjectPublicKey,
    issuer_root: [u8; 32],
    issuance_binding: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ZkWalletStoredCredentialError> {
    if credential_envelope_pb.is_empty()
        || credential_envelope_pb.len() > MAX_CREDENTIAL_ENVELOPE_PROTO_BYTES
        || prepared_claims.root() != issuer_root
    {
        return Err(invalid(
            ZkWalletStoredCredentialReason::PrivateClaimMismatch,
        ));
    }
    private_lineage
        .validate_against(issuer_key, subject_key, prepared_claims)
        .map_err(|_| invalid(ZkWalletStoredCredentialReason::PrivateLineageMismatch))?;
    let encoded_claims = encode_prepared_claims(prepared_claims, issuance_binding)
        .map_err(|_| invalid(ZkWalletStoredCredentialReason::PrivateClaimMismatch))?;
    let mut message = SensitiveStoredMessage(pb::ZkWalletStoredCredential::default());
    message.0.format_version = ZK_WALLET_STORED_CREDENTIAL_FORMAT_VERSION;
    message.0.credential_pb = credential_envelope_pb.to_vec();
    message.0.prepared_claims_pb = encoded_claims.to_vec();
    let mut lineage_wire = pb::ZkCommonCredentialRootPrivateLineageMaterial::default();
    lineage_wire.root = private_lineage.root().to_vec();
    lineage_wire.relationship_did = private_lineage.relationship_did().to_owned();
    lineage_wire.nonce = private_lineage.nonce().to_vec();
    message.0.private_lineage = MessageField::some(lineage_wire);
    let bytes = Zeroizing::new(message.0.encode_to_vec());
    if bytes.len() > MAX_STORED_CREDENTIAL_BYTES {
        return Err(invalid(ZkWalletStoredCredentialReason::InvalidEncoding));
    }
    Ok(bytes)
}

/// Decode after authenticated decryption and issuer receipt validation.
///
/// `expected_credential_envelope_pb` is the exact canonical protobuf from
/// the validated issuer receipt. Comparing it here prevents the caller from
/// accidentally pairing another envelope with otherwise valid openings.
pub fn decode_wallet_stored_credential(
    plaintext: &[u8],
    expected_credential_envelope_pb: &[u8],
    issuer_key: ZkIssuerPublicKey,
    subject_key: ZkCommonCredentialRootSubjectPublicKey,
    issuer_root: [u8; 32],
    issuance_binding: [u8; 32],
) -> Result<ZkWalletStoredCredential, ZkWalletStoredCredentialError> {
    decode_wallet_stored_credential_for_lane(
        plaintext,
        expected_credential_envelope_pb,
        issuer_key,
        subject_key,
        ZkCredentialHashAlgorithm::Sha256,
        issuer_root,
        issuance_binding,
    )
}

/// Decode a wallet-private credential under its issuer-authenticated lane.
pub fn decode_wallet_stored_credential_for_lane(
    plaintext: &[u8],
    expected_credential_envelope_pb: &[u8],
    issuer_key: ZkIssuerPublicKey,
    subject_key: ZkCommonCredentialRootSubjectPublicKey,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    issuer_root: [u8; 32],
    issuance_binding: [u8; 32],
) -> Result<ZkWalletStoredCredential, ZkWalletStoredCredentialError> {
    if plaintext.is_empty() || plaintext.len() > MAX_STORED_CREDENTIAL_BYTES {
        return Err(invalid(ZkWalletStoredCredentialReason::InvalidEncoding));
    }
    let mut message = SensitiveStoredMessage(
        DecodeOptions::new()
            .with_recursion_limit(PROTO_RECURSION_LIMIT)
            .with_element_memory_limit(MAX_STORED_CREDENTIAL_BYTES)
            .with_max_message_size(MAX_STORED_CREDENTIAL_BYTES)
            .with_unknown_field_limit(0)
            .decode_from_slice::<pb::ZkWalletStoredCredential>(plaintext)
            .map_err(|_| invalid(ZkWalletStoredCredentialReason::InvalidEncoding))?,
    );
    if Zeroizing::new(message.0.encode_to_vec()).as_slice() != plaintext {
        return Err(invalid(ZkWalletStoredCredentialReason::InvalidEncoding));
    }
    if message.0.format_version != ZK_WALLET_STORED_CREDENTIAL_FORMAT_VERSION
        || message.0.credential_pb.is_empty()
        || message.0.credential_pb.len() > MAX_CREDENTIAL_ENVELOPE_PROTO_BYTES
        || message.0.credential_pb != expected_credential_envelope_pb
        || message.0.prepared_claims_pb.is_empty()
        || message.0.prepared_claims_pb.len() > MAX_PREPARED_CLAIMS_PROTO_BYTES
    {
        return Err(invalid(ZkWalletStoredCredentialReason::InvalidEncoding));
    }
    let prepared_claims = decode_prepared_claims_for_lane(
        &message.0.prepared_claims_pb,
        expected_credential_hash_algorithm,
        issuer_root,
        issuance_binding,
    )
    .map_err(|_| invalid(ZkWalletStoredCredentialReason::PrivateClaimMismatch))?;
    let lineage_wire = message
        .0
        .private_lineage
        .as_option_mut()
        .ok_or_else(|| invalid(ZkWalletStoredCredentialReason::InvalidEncoding))?;
    if lineage_wire.root.len() != 32
        || lineage_wire.nonce.len() != 32
        || lineage_wire.relationship_did.is_empty()
        || lineage_wire.relationship_did.len() > MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES
    {
        return Err(invalid(ZkWalletStoredCredentialReason::InvalidEncoding));
    }
    let root = lineage_wire
        .root
        .as_slice()
        .try_into()
        .map_err(|_| invalid(ZkWalletStoredCredentialReason::InvalidEncoding))?;
    let nonce = lineage_wire
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| invalid(ZkWalletStoredCredentialReason::InvalidEncoding))?;
    let private_lineage = ZkCommonCredentialRootPrivateLineageMaterial::new(
        root,
        core::mem::take(&mut lineage_wire.relationship_did),
        nonce,
        issuer_key,
        subject_key,
        &prepared_claims,
    )
    .map_err(|_| invalid(ZkWalletStoredCredentialReason::PrivateLineageMismatch))?;
    Ok(ZkWalletStoredCredential {
        credential_envelope_pb: Zeroizing::new(core::mem::take(&mut message.0.credential_pb)),
        prepared_claims,
        private_lineage,
    })
}

const fn invalid(reason: ZkWalletStoredCredentialReason) -> ZkWalletStoredCredentialError {
    ZkWalletStoredCredentialError { reason }
}
