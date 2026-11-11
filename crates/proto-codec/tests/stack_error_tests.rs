// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the optional shared stack-error adapter.

#![cfg(feature = "stack-error")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkErrorReason as ProtoZkErrorReason;
use reallyme_zk_proto_codec::stack_error::{
    zk_stack_error, zk_stack_error_from_proto_reason,
    zk_stack_error_from_proto_reason_with_correlation_id, zk_stack_error_from_reason,
    ZkCorrelationId, ZkCorrelationIdErrorReason, MAX_ZK_CORRELATION_ID_BYTES,
    ZK_STACK_ERROR_DOMAIN,
};
use serde_json::json;

#[test]
fn zk_error_maps_to_ssi_stack_error() {
    let error = zk_stack_error(ZkError::new(ZkErrorReason::BindingMismatch));

    assert_eq!(error.domain, EnumValue::from(ZK_STACK_ERROR_DOMAIN));
    assert_eq!(
        error.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_ZK.to_i32()
    );
    assert_eq!(
        error.reason_code,
        ZkErrorReason::BindingMismatch.reason_code()
    );
    assert_eq!(error.correlation_id, "");
}

#[test]
fn zk_reason_maps_to_ssi_stack_error() {
    let error = zk_stack_error_from_reason(ZkErrorReason::BackendUnavailable);

    assert_eq!(
        error.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_ZK.to_i32()
    );
    assert_eq!(
        error.reason_code,
        ZkErrorReason::BackendUnavailable.reason_code()
    );
}

#[test]
fn proto_reason_maps_to_ssi_stack_error() -> Result<(), ZkError> {
    let error = zk_stack_error_from_proto_reason_with_correlation_id(
        EnumValue::from(ProtoZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF),
        ZkCorrelationId::try_from_token("corr_zk_01")
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
    )?;

    assert_eq!(
        error.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_ZK.to_i32()
    );
    assert_eq!(error.reason_code, ZkErrorReason::InvalidProof.reason_code());
    assert_eq!(error.correlation_id, "corr_zk_01");
    Ok(())
}

#[test]
fn unknown_proto_reason_fails_closed_before_stack_envelope() {
    let error = zk_stack_error_from_proto_reason(EnumValue::from(65_535));

    assert!(matches!(
        error,
        Err(error) if error.reason() == ZkErrorReason::MalformedProtobuf
    ));
}

#[test]
fn unspecified_proto_reason_fails_closed_before_stack_envelope() {
    let error = zk_stack_error_from_proto_reason(EnumValue::from(
        ProtoZkErrorReason::ZK_ERROR_REASON_UNSPECIFIED,
    ));

    assert!(matches!(
        error,
        Err(error) if error.reason() == ZkErrorReason::MalformedProtobuf
    ));
}

#[test]
fn ssi_stack_error_proto_round_trips_with_buffa() -> Result<(), buffa::DecodeError> {
    let error = zk_stack_error_from_reason(ZkErrorReason::ArtifactMismatch);
    let encoded = error.encode_to_vec();
    let decoded = IdentityStackError::decode(&mut encoded.as_slice())?;

    assert_eq!(
        decoded.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_ZK.to_i32()
    );
    assert_eq!(
        decoded.reason_code,
        ZkErrorReason::ArtifactMismatch.reason_code()
    );
    Ok(())
}

#[test]
fn ssi_stack_error_json_encoding_is_stable() -> Result<(), ZkError> {
    let error = zk_stack_error_from_proto_reason_with_correlation_id(
        EnumValue::from(ProtoZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF_ENCODING),
        ZkCorrelationId::try_from_token("corr_zk_02")
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
    )?;
    let serialized =
        serde_json::to_value(error).map_err(|_| ZkError::new(ZkErrorReason::MalformedJson))?;

    assert_eq!(
        serialized,
        json!({
            "domain": "IDENTITY_STACK_ERROR_DOMAIN_ZK",
            "reasonCode": ZkErrorReason::InvalidProofEncoding.reason_code(),
            "correlationId": "corr_zk_02"
        })
    );
    Ok(())
}

#[test]
fn correlation_identifier_rejects_free_form_or_unbounded_values() {
    let oversized = "a".repeat(MAX_ZK_CORRELATION_ID_BYTES + 1);
    for value in ["", "contains space", "pii@example.test", oversized.as_str()] {
        let result = ZkCorrelationId::try_from_token(value);
        assert!(matches!(
            result,
            Err(error) if error.reason() == ZkCorrelationIdErrorReason::InvalidToken
        ));
    }
}
