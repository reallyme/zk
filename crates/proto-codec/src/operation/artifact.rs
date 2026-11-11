// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::errors::ZkError;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::domain::{circuit_ref_from_proto_message, proof_suite_from_proto};

use super::ZkProviderOperation;

pub(super) fn artifact_operation_from_proto(
    operation: pb::ZkArtifactManifestOperation,
) -> Result<ZkProviderOperation, ZkError> {
    Ok(ZkProviderOperation::GetArtifactManifest {
        circuit_ref: circuit_ref_from_proto_message(operation.circuit_ref)?,
        proof_suite: proof_suite_from_proto(operation.proof_suite)?,
    })
}
