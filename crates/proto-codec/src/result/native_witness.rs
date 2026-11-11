// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::binding::session_binding_from_proto_message;
use crate::domain::circuit_ref_from_proto_message;
use crate::operation::ZkNativeStageWitnessHandle;

/// Native-owned stage witness plus public statement returned by a platform
/// provider. The handle is provider-local and cannot be used without the same
/// native context.
#[derive(Debug, PartialEq, Eq)]
pub struct ZkStageWitnessReport {
    /// Opaque provider-local witness handle.
    pub witness_handle: ZkNativeStageWitnessHandle,
    /// Canonical compact public inputs for the same circuit.
    pub public_inputs: reallyme_zk_api::proofs::ZkPublicInputs,
    /// Session binding decoded from the public inputs.
    pub session_binding: reallyme_zk_api::proofs::ZkSessionBinding,
}

/// Provider confirmation that one native-owned witness handle was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkStageWitnessReleaseReport {
    /// Exact circuit bound to the released handle.
    pub circuit_ref: ZkCircuitRef,
}

pub(super) fn stage_witness_from_proto(
    mut witness: pb::ZkStageWitness,
) -> Result<ZkStageWitnessReport, ZkError> {
    let handle = witness
        .witness_handle
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    if handle.native_handle_id == 0 {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    let circuit_ref = circuit_ref_from_proto_message(handle.circuit_ref)?;
    match handle.encoding.as_known() {
        Some(pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1) => {}
        Some(pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_UNSPECIFIED) | None => {
            return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
        }
    }
    let mut public_inputs = witness
        .public_inputs
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let public_inputs = reallyme_zk_api::proofs::ZkPublicInputs::try_from_bytes(core::mem::take(
        &mut public_inputs.encoded,
    ))?;
    let session_binding = session_binding_from_proto_message(witness.session_binding)?;
    session_binding.decode_and_validate(circuit_ref, &public_inputs)?;
    Ok(ZkStageWitnessReport {
        witness_handle: ZkNativeStageWitnessHandle {
            native_handle_id: handle.native_handle_id,
            circuit_ref,
        },
        public_inputs,
        session_binding,
    })
}

pub(super) fn stage_witness_release_from_proto(
    release: pb::ZkStageWitnessRelease,
) -> Result<ZkStageWitnessReleaseReport, ZkError> {
    Ok(ZkStageWitnessReleaseReport {
        circuit_ref: circuit_ref_from_proto_message(release.circuit_ref)?,
    })
}
