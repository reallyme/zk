// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::ZK_INPUT_BYTES_32;

pub(super) fn expected_session_binding(
    input: &pb::ZkStageWitnessInput,
) -> Result<ZkSessionBinding, ZkError> {
    use pb::zk_stage_witness_input::Input;

    match input
        .input
        .as_ref()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?
    {
        Input::CredentialSubjectClaimSession(input) => {
            session_binding_from_session_context(&input.session_context)
        }
        Input::PrivatePersonaSession(input) => {
            session_binding_from_session_context(&input.session_context)
        }
        Input::CredentialEnvelope(input) => {
            session_binding_from_issuer_context(&input.issuer_context)
        }
        Input::CredentialRoot(input) => session_binding_from_issuer_context(&input.issuer_context),
        Input::CredentialSubjectClaim(input) => {
            session_binding_from_issuer_context(&input.issuer_context)
        }
        Input::PrivatePersonaClaim(input) => {
            session_binding_from_issuer_context(&input.issuer_context)
        }
    }
}

fn session_binding_from_session_context(
    field: &MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>>,
) -> Result<ZkSessionBinding, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkSessionBinding {
        nonce_hash: fixed_bytes32(&context.challenge)?,
        audience_hash: fixed_bytes32(&context.audience_hash)?,
        transaction_data_hash: optional_transaction_hash(fixed_bytes32(
            &context.transaction_data_hash,
        )?),
    })
}

fn session_binding_from_issuer_context(
    field: &MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>>,
) -> Result<ZkSessionBinding, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkSessionBinding {
        nonce_hash: fixed_bytes32(&context.challenge)?,
        audience_hash: fixed_bytes32(&context.audience_hash)?,
        transaction_data_hash: optional_transaction_hash(fixed_bytes32(
            &context.transaction_data_hash,
        )?),
    })
}

fn optional_transaction_hash(hash: [u8; ZK_INPUT_BYTES_32]) -> Option<[u8; ZK_INPUT_BYTES_32]> {
    if hash == ABSENT_TRANSACTION_DATA_HASH {
        None
    } else {
        Some(hash)
    }
}

fn fixed_bytes32(
    field: &MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<[u8; ZK_INPUT_BYTES_32], ZkError> {
    let bytes = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    bytes
        .value
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}
