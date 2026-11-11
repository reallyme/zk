// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkWitness,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::domain::circuit_ref_from_proto_message;

/// Stage witness source admitted by the exact-stage proving operation.
pub enum ZkStageWitnessSource {
    /// Diagnostic/raw harness witness bytes.
    Raw(ZkWitness),
    /// Opaque native context handle.
    NativeHandle(ZkNativeStageWitnessHandle),
}

/// Opaque native witness handle transported through generated protobuf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkNativeStageWitnessHandle {
    /// Provider-local handle identity.
    pub native_handle_id: u64,
    /// Exact circuit bound to the retained witness.
    pub circuit_ref: ZkCircuitRef,
}

pub(super) fn stage_witness_handle_from_proto(
    handle: pb::ZkStageWitnessHandle,
    expected_ref: ZkCircuitRef,
) -> Result<ZkNativeStageWitnessHandle, ZkError> {
    let handle = stage_witness_handle_from_proto_unbound(handle)?;
    if handle.circuit_ref != expected_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    Ok(handle)
}

pub(super) fn stage_witness_handle_from_proto_unbound(
    handle: pb::ZkStageWitnessHandle,
) -> Result<ZkNativeStageWitnessHandle, ZkError> {
    if handle.native_handle_id == 0 {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    let circuit_ref = circuit_ref_from_proto_message(handle.circuit_ref)?;
    match handle.encoding.as_known() {
        Some(pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1) => {
            Ok(ZkNativeStageWitnessHandle {
                native_handle_id: handle.native_handle_id,
                circuit_ref,
            })
        }
        Some(pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}
