// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

use super::{error_reason_from_proto, pb};

const ALL_ERROR_REASONS: &[(ZkErrorReason, pb::ZkErrorReason)] = &[
    (
        ZkErrorReason::UnknownCircuit,
        pb::ZkErrorReason::ZK_ERROR_REASON_UNKNOWN_CIRCUIT,
    ),
    (
        ZkErrorReason::UnsupportedCircuit,
        pb::ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT,
    ),
    (
        ZkErrorReason::EmptyInput,
        pb::ZkErrorReason::ZK_ERROR_REASON_EMPTY_INPUT,
    ),
    (
        ZkErrorReason::ProofTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_PROOF_TOO_LARGE,
    ),
    (
        ZkErrorReason::PublicInputsTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE,
    ),
    (
        ZkErrorReason::WitnessTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_WITNESS_TOO_LARGE,
    ),
    (
        ZkErrorReason::LengthOverflow,
        pb::ZkErrorReason::ZK_ERROR_REASON_LENGTH_OVERFLOW,
    ),
    (
        ZkErrorReason::InvalidProofEncoding,
        pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF_ENCODING,
    ),
    (
        ZkErrorReason::InvalidProof,
        pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF,
    ),
    (
        ZkErrorReason::BindingMismatch,
        pb::ZkErrorReason::ZK_ERROR_REASON_BINDING_MISMATCH,
    ),
    (
        ZkErrorReason::ArtifactMismatch,
        pb::ZkErrorReason::ZK_ERROR_REASON_ARTIFACT_MISMATCH,
    ),
    (
        ZkErrorReason::BackendUnavailable,
        pb::ZkErrorReason::ZK_ERROR_REASON_BACKEND_UNAVAILABLE,
    ),
    (
        ZkErrorReason::BackendFailure,
        pb::ZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE,
    ),
    (
        ZkErrorReason::InvalidPublicInputName,
        pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME,
    ),
    (
        ZkErrorReason::PublicKeyTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE,
    ),
    (
        ZkErrorReason::ClaimPayloadTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE,
    ),
    (
        ZkErrorReason::InvalidClaimProofBundle,
        pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE,
    ),
    (
        ZkErrorReason::DuplicateStage,
        pb::ZkErrorReason::ZK_ERROR_REASON_DUPLICATE_STAGE,
    ),
    (
        ZkErrorReason::MissingStage,
        pb::ZkErrorReason::ZK_ERROR_REASON_MISSING_STAGE,
    ),
    (
        ZkErrorReason::StageMismatch,
        pb::ZkErrorReason::ZK_ERROR_REASON_STAGE_MISMATCH,
    ),
    (
        ZkErrorReason::MalformedProtobuf,
        pb::ZkErrorReason::ZK_ERROR_REASON_MALFORMED_PROTOBUF,
    ),
    (
        ZkErrorReason::MalformedJson,
        pb::ZkErrorReason::ZK_ERROR_REASON_MALFORMED_JSON,
    ),
    (
        ZkErrorReason::MissingOperation,
        pb::ZkErrorReason::ZK_ERROR_REASON_MISSING_OPERATION,
    ),
    (
        ZkErrorReason::UnsupportedTransport,
        pb::ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT,
    ),
    (
        ZkErrorReason::MessageTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_MESSAGE_TOO_LARGE,
    ),
    (
        ZkErrorReason::ArtifactTooLarge,
        pb::ZkErrorReason::ZK_ERROR_REASON_ARTIFACT_TOO_LARGE,
    ),
    (
        ZkErrorReason::UnsupportedProofSuite,
        pb::ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE,
    ),
    (
        ZkErrorReason::UntrustedIssuer,
        pb::ZkErrorReason::ZK_ERROR_REASON_UNTRUSTED_ISSUER,
    ),
    (
        ZkErrorReason::PresentationExpired,
        pb::ZkErrorReason::ZK_ERROR_REASON_PRESENTATION_EXPIRED,
    ),
    (
        ZkErrorReason::PresentationExpiryTooFar,
        pb::ZkErrorReason::ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR,
    ),
    (
        ZkErrorReason::ResourceExhausted,
        pb::ZkErrorReason::ZK_ERROR_REASON_RESOURCE_EXHAUSTED,
    ),
];

#[test]
fn proto_error_reason_converts_to_domain_reason() -> Result<(), ZkError> {
    for (domain, proto) in ALL_ERROR_REASONS {
        let converted = error_reason_from_proto(EnumValue::from(*proto))?;

        assert_eq!(converted, *domain);
    }
    Ok(())
}

#[test]
fn unspecified_proto_error_reason_fails_closed() {
    let err = error_reason_from_proto(EnumValue::from(
        pb::ZkErrorReason::ZK_ERROR_REASON_UNSPECIFIED,
    ))
    .err()
    .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn unknown_proto_error_reason_fails_closed() {
    let err = error_reason_from_proto(EnumValue::from(65_535))
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::UnknownCircuit));

    assert_eq!(err.reason(), ZkErrorReason::MalformedProtobuf);
}
