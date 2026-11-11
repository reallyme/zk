// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict conversion of presentation-session binding inputs.

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::ZkSessionBinding,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

pub(crate) fn session_binding_from_proto_message(
    mut session_binding: buffa::MessageField<
        pb::ZkSessionBinding,
        impl buffa::ProtoBox<pb::ZkSessionBinding>,
    >,
) -> Result<ZkSessionBinding, ZkError> {
    let mut session_binding = session_binding
        .take()
        .ok_or(ZkError::new(ZkErrorReason::BindingMismatch))?;
    let transaction_data_hash = if session_binding.transaction_data_hash.is_empty() {
        None
    } else {
        Some(fixed_32(core::mem::take(
            &mut session_binding.transaction_data_hash,
        ))?)
    };

    Ok(ZkSessionBinding {
        nonce_hash: fixed_32(core::mem::take(&mut session_binding.nonce_hash))?,
        audience_hash: fixed_32(core::mem::take(&mut session_binding.audience_hash))?,
        transaction_data_hash,
    })
}

fn fixed_32(bytes: Vec<u8>) -> Result<[u8; 32], ZkError> {
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != 32 {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let mut fixed = [0_u8; 32];
    fixed.copy_from_slice(&bytes);
    Ok(fixed)
}

pub(crate) fn session_binding_to_proto_message(binding: ZkSessionBinding) -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding
            .transaction_data_hash
            .map(|hash| hash.to_vec())
            .unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    }
}
