// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkBackendErrorReason, ZkBindingErrorReason, ZkError, ZkErrorKind, ZkTransportErrorReason,
    IDENTITY_STACK_ERROR_DOMAIN_ZK_CODE,
};
use crate::error_reason::{ZkErrorReason, ZK_ERROR_REASON_UNSPECIFIED_CODE};

const ALL_REASONS: &[(ZkErrorReason, u32)] = &[
    (ZkErrorReason::UnknownCircuit, 1),
    (ZkErrorReason::UnsupportedCircuit, 2),
    (ZkErrorReason::EmptyInput, 3),
    (ZkErrorReason::ProofTooLarge, 4),
    (ZkErrorReason::PublicInputsTooLarge, 5),
    (ZkErrorReason::LengthOverflow, 6),
    (ZkErrorReason::InvalidProofEncoding, 7),
    (ZkErrorReason::InvalidProof, 8),
    (ZkErrorReason::BindingMismatch, 9),
    (ZkErrorReason::ArtifactMismatch, 10),
    (ZkErrorReason::BackendUnavailable, 11),
    (ZkErrorReason::BackendFailure, 12),
    (ZkErrorReason::InvalidPublicInputName, 13),
    (ZkErrorReason::PublicKeyTooLarge, 14),
    (ZkErrorReason::ClaimPayloadTooLarge, 15),
    (ZkErrorReason::InvalidClaimProofBundle, 16),
    (ZkErrorReason::DuplicateStage, 17),
    (ZkErrorReason::MissingStage, 18),
    (ZkErrorReason::StageMismatch, 19),
    (ZkErrorReason::WitnessTooLarge, 20),
    (ZkErrorReason::MalformedProtobuf, 21),
    (ZkErrorReason::MalformedJson, 22),
    (ZkErrorReason::MissingOperation, 23),
    (ZkErrorReason::UnsupportedTransport, 24),
    (ZkErrorReason::MessageTooLarge, 25),
    (ZkErrorReason::ArtifactTooLarge, 26),
    (ZkErrorReason::UnsupportedProofSuite, 27),
    (ZkErrorReason::UntrustedIssuer, 28),
    (ZkErrorReason::PresentationExpired, 29),
    (ZkErrorReason::PresentationExpiryTooFar, 30),
    (ZkErrorReason::ResourceExhausted, 31),
];

#[test]
fn reason_codes_match_proto_contract() -> Result<(), ZkError> {
    for (reason, code) in ALL_REASONS {
        assert_eq!(reason.reason_code(), *code);
        assert_eq!(ZkErrorReason::from_reason_code(*code)?, *reason);
    }
    Ok(())
}

#[test]
fn unknown_reason_codes_fail_closed() {
    let err = ZkErrorReason::from_reason_code(65_535)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn unspecified_reason_code_fails_closed() {
    let err = ZkErrorReason::from_reason_code(ZK_ERROR_REASON_UNSPECIFIED_CODE)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn error_exposes_identity_common_envelope_values() {
    let err = ZkError::new(ZkErrorReason::BindingMismatch);

    assert_eq!(
        err.identity_stack_error_domain_code(),
        IDENTITY_STACK_ERROR_DOMAIN_ZK_CODE
    );
    assert_eq!(err.reason_code(), 9);
}

#[test]
fn error_kind_round_trips_through_top_level_reason() {
    for (reason, code) in ALL_REASONS {
        let kind = reason.kind();
        let err = ZkError::from_kind(kind);

        assert_eq!(ZkErrorReason::from(kind), *reason);
        assert_eq!(err.kind(), kind);
        assert_eq!(err.reason(), *reason);
        assert_eq!(err.reason_code(), *code);
    }
}

#[test]
fn subset_error_enums_construct_structured_error_kinds() {
    let binding = ZkErrorKind::from(ZkBindingErrorReason::BindingMismatch);
    let backend = ZkErrorKind::from(ZkBackendErrorReason::BackendUnavailable);
    let transport = ZkErrorKind::from(ZkTransportErrorReason::MalformedProtobuf);

    assert_eq!(binding.reason(), ZkErrorReason::BindingMismatch);
    assert_eq!(backend.reason(), ZkErrorReason::BackendUnavailable);
    assert_eq!(transport.reason(), ZkErrorReason::MalformedProtobuf);
}
