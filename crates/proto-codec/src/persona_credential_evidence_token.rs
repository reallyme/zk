// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared prepared credential token context and its protobuf scalar encoders.

use buffa::MessageField;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    keys::ZkIssuerPublicKey,
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceMode,
        ZkPersonaCredentialEvidenceValidityWindow,
    },
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wallet-selected token context shared by every prepared credential stage.
/// The private mode uses an independently generated one-time holder key.
pub struct ZkPersonaCredentialEvidenceToken {
    /// Public persona or private one-time persona presentation contract.
    pub mode: ZkPersonaCredentialEvidenceMode,
    /// Exact hash lane of the credential and sealed circuit release.
    pub credential_hash_algorithm: ZkCredentialHashAlgorithm,
    /// Deployment-trusted credential issuer key.
    pub issuer_key: ZkIssuerPublicKey,
    /// Public persona or independently generated one-time holder key.
    pub holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
    /// Fresh CSPRNG nonce unique to this prepared token.
    pub token_nonce: [u8; 32],
    /// Wallet-selected proof interval, later checked inside issuer validity.
    pub proof_window: ZkPersonaCredentialEvidenceValidityWindow,
}

impl Zeroize for ZkPersonaCredentialEvidenceToken {
    fn zeroize(&mut self) {
        self.issuer_key.x.zeroize();
        self.issuer_key.y.zeroize();
        self.holder_key.x.zeroize();
        self.holder_key.y.zeroize();
        self.token_nonce.zeroize();
    }
}

impl Drop for ZkPersonaCredentialEvidenceToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceToken {}

pub(crate) fn bytes32(
    value: [u8; 32],
) -> MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>> {
    MessageField::some(pb::ZkInputBytes32 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

pub(crate) fn bytes64(
    value: [u8; 64],
) -> MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>> {
    MessageField::some(pb::ZkInputBytes64 {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

pub(crate) fn key(
    x: [u8; 32],
    y: [u8; 32],
) -> MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>> {
    MessageField::some(pb::ZkInputP256PublicKey {
        x: bytes32(x),
        y: bytes32(y),
        __buffa_unknown_fields: Default::default(),
    })
}
