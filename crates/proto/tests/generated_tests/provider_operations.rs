// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Message};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    __buffa::oneof::{
        zk_error::Detail as ZkErrorDetail,
        zk_provider_operation_request::Operation as ProviderOperation,
        zk_provider_operation_response::Outcome as ProviderOutcome,
    },
    ZkBackendErrorReason, ZkError, ZkErrorReason, ZkProviderOperationRequest,
    ZkProviderOperationResponse,
};

#[test]
fn canonical_provider_request_round_trips_one_exact_operation() {
    let request = ZkProviderOperationRequest {
        operation: Some(ProviderOperation::GetArtifactManifest(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = request.encode_to_vec();
    let decoded = ZkProviderOperationRequest::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, request);
}

#[test]
fn canonical_provider_response_uses_structured_error_only() {
    let error = ZkError {
        reason: EnumValue::from(ZkErrorReason::ZK_ERROR_REASON_BACKEND_UNAVAILABLE),
        detail: Some(ZkErrorDetail::BackendReason(EnumValue::from(
            ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_BACKEND_UNAVAILABLE,
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let response = ZkProviderOperationResponse {
        outcome: Some(ProviderOutcome::Error(Box::new(error))),
        request_sha256: vec![7; 32],
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = response.encode_to_vec();
    let decoded = ZkProviderOperationResponse::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, response);
}
