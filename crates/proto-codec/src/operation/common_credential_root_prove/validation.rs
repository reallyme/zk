// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{Inline, MessageField};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use subtle::ConstantTimeEq;

pub(super) fn bytes32_field(
    field: &MessageField<pb::ZkInputBytes32, Inline<pb::ZkInputBytes32>>,
) -> Result<[u8; 32], ZkError> {
    let bytes = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    bytes
        .value
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

pub(super) fn public_key_field(
    field: &MessageField<pb::ZkInputP256PublicKey, Inline<pb::ZkInputP256PublicKey>>,
) -> Result<ZkIssuerPublicKey, ZkError> {
    let key = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkIssuerPublicKey {
        x: bytes32_field(&key.x)?,
        y: bytes32_field(&key.y)?,
    })
}

pub(super) fn require_same_bytes32(left: [u8; 32], right: [u8; 32]) -> Result<(), ZkError> {
    if bool::from(left.ct_eq(&right)) {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::BindingMismatch))
    }
}

pub(super) fn require_same_key(
    left: ZkIssuerPublicKey,
    right: ZkIssuerPublicKey,
) -> Result<(), ZkError> {
    if bool::from(left.x.ct_eq(&right.x)) && bool::from(left.y.ct_eq(&right.y)) {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::BindingMismatch))
    }
}
