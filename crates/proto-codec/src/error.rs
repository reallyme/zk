// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict bidirectional conversion for privacy-safe ZK errors.

use buffa::{EnumValue, Enumeration};
use reallyme_zk_api::errors::{
    ZkArtifactErrorReason, ZkBackendErrorReason, ZkBindingErrorReason, ZkCircuitErrorReason,
    ZkClaimProofBundleErrorReason, ZkError, ZkErrorKind, ZkErrorReason, ZkInputErrorReason,
    ZkProofErrorReason, ZkTransportErrorReason,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

/// Converts a public ZK API error into the generated proto reason enum.
#[must_use]
pub fn error_to_proto_reason(error: ZkError) -> pb::ZkErrorReason {
    error_reason_to_proto(error.reason())
}

/// Converts a public ZK API reason into the generated proto reason enum.
#[must_use]
pub fn error_reason_to_proto(reason: ZkErrorReason) -> pb::ZkErrorReason {
    match reason {
        ZkErrorReason::UnknownCircuit => pb::ZkErrorReason::ZK_ERROR_REASON_UNKNOWN_CIRCUIT,
        ZkErrorReason::UnsupportedCircuit => pb::ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT,
        ZkErrorReason::EmptyInput => pb::ZkErrorReason::ZK_ERROR_REASON_EMPTY_INPUT,
        ZkErrorReason::ProofTooLarge => pb::ZkErrorReason::ZK_ERROR_REASON_PROOF_TOO_LARGE,
        ZkErrorReason::PublicInputsTooLarge => {
            pb::ZkErrorReason::ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE
        }
        ZkErrorReason::WitnessTooLarge => pb::ZkErrorReason::ZK_ERROR_REASON_WITNESS_TOO_LARGE,
        ZkErrorReason::InvalidPublicInputName => {
            pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME
        }
        ZkErrorReason::PublicKeyTooLarge => pb::ZkErrorReason::ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE,
        ZkErrorReason::ClaimPayloadTooLarge => {
            pb::ZkErrorReason::ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE
        }
        ZkErrorReason::InvalidClaimProofBundle => {
            pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE
        }
        ZkErrorReason::DuplicateStage => pb::ZkErrorReason::ZK_ERROR_REASON_DUPLICATE_STAGE,
        ZkErrorReason::MissingStage => pb::ZkErrorReason::ZK_ERROR_REASON_MISSING_STAGE,
        ZkErrorReason::StageMismatch => pb::ZkErrorReason::ZK_ERROR_REASON_STAGE_MISMATCH,
        ZkErrorReason::LengthOverflow => pb::ZkErrorReason::ZK_ERROR_REASON_LENGTH_OVERFLOW,
        ZkErrorReason::InvalidProofEncoding => {
            pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF_ENCODING
        }
        ZkErrorReason::InvalidProof => pb::ZkErrorReason::ZK_ERROR_REASON_INVALID_PROOF,
        ZkErrorReason::BindingMismatch => pb::ZkErrorReason::ZK_ERROR_REASON_BINDING_MISMATCH,
        ZkErrorReason::ArtifactMismatch => pb::ZkErrorReason::ZK_ERROR_REASON_ARTIFACT_MISMATCH,
        ZkErrorReason::ArtifactTooLarge => pb::ZkErrorReason::ZK_ERROR_REASON_ARTIFACT_TOO_LARGE,
        ZkErrorReason::BackendUnavailable => pb::ZkErrorReason::ZK_ERROR_REASON_BACKEND_UNAVAILABLE,
        ZkErrorReason::BackendFailure => pb::ZkErrorReason::ZK_ERROR_REASON_BACKEND_FAILURE,
        ZkErrorReason::MalformedProtobuf => pb::ZkErrorReason::ZK_ERROR_REASON_MALFORMED_PROTOBUF,
        ZkErrorReason::MalformedJson => pb::ZkErrorReason::ZK_ERROR_REASON_MALFORMED_JSON,
        ZkErrorReason::MissingOperation => pb::ZkErrorReason::ZK_ERROR_REASON_MISSING_OPERATION,
        ZkErrorReason::UnsupportedTransport => {
            pb::ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT
        }
        ZkErrorReason::MessageTooLarge => pb::ZkErrorReason::ZK_ERROR_REASON_MESSAGE_TOO_LARGE,
        ZkErrorReason::UnsupportedProofSuite => {
            pb::ZkErrorReason::ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE
        }
        ZkErrorReason::UntrustedIssuer => pb::ZkErrorReason::ZK_ERROR_REASON_UNTRUSTED_ISSUER,
        ZkErrorReason::PresentationExpired => {
            pb::ZkErrorReason::ZK_ERROR_REASON_PRESENTATION_EXPIRED
        }
        ZkErrorReason::PresentationExpiryTooFar => {
            pb::ZkErrorReason::ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR
        }
        ZkErrorReason::ResourceExhausted => pb::ZkErrorReason::ZK_ERROR_REASON_RESOURCE_EXHAUSTED,
        _ => pb::ZkErrorReason::ZK_ERROR_REASON_UNSPECIFIED,
    }
}

/// Converts a generated proto error reason into the public ZK API reason.
pub(crate) fn error_reason_from_proto(
    reason: EnumValue<pb::ZkErrorReason>,
) -> Result<ZkErrorReason, ZkError> {
    let reason = reason
        .as_known()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let reason_code = u32::try_from(reason.to_i32())
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    ZkErrorReason::from_reason_code(reason_code)
}

/// Converts a public ZK API error into the generated structured proto error.
#[must_use]
pub fn error_to_proto(error: ZkError) -> pb::ZkError {
    error_kind_to_proto(error.kind())
}

/// Converts a public structured ZK API failure into the generated proto error.
#[must_use]
pub fn error_kind_to_proto(kind: ZkErrorKind) -> pb::ZkError {
    pb::ZkError {
        reason: EnumValue::from(error_reason_to_proto(kind.reason())),
        detail: Some(error_kind_to_proto_detail(kind)),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Converts a generated structured proto error into the public ZK API error.
pub(crate) fn error_from_proto(error: pb::ZkError) -> Result<ZkError, ZkError> {
    let top_level_reason = error_reason_from_proto(error.reason)?;
    let detail_kind = error_kind_from_proto_detail(error.detail)?;

    if detail_kind.reason() != top_level_reason {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }

    Ok(ZkError::from_kind(detail_kind))
}

fn error_kind_to_proto_detail(kind: ZkErrorKind) -> pb::__buffa::oneof::zk_error::Detail {
    match kind {
        ZkErrorKind::Circuit(ZkCircuitErrorReason::UnknownCircuit) => {
            pb::__buffa::oneof::zk_error::Detail::CircuitReason(EnumValue::from(
                pb::ZkCircuitErrorReason::ZK_CIRCUIT_ERROR_REASON_UNKNOWN_CIRCUIT,
            ))
        }
        ZkErrorKind::Circuit(ZkCircuitErrorReason::UnsupportedCircuit) => {
            pb::__buffa::oneof::zk_error::Detail::CircuitReason(EnumValue::from(
                pb::ZkCircuitErrorReason::ZK_CIRCUIT_ERROR_REASON_UNSUPPORTED_CIRCUIT,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::EmptyInput) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_EMPTY_INPUT,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::ProofTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_PROOF_TOO_LARGE,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::PublicInputsTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::WitnessTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_WITNESS_TOO_LARGE,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::InvalidPublicInputName) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::PublicKeyTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_PUBLIC_KEY_TOO_LARGE,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::ClaimPayloadTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::LengthOverflow) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_LENGTH_OVERFLOW,
            ))
        }
        ZkErrorKind::Input(ZkInputErrorReason::ResourceExhausted) => {
            pb::__buffa::oneof::zk_error::Detail::InputReason(EnumValue::from(
                pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_RESOURCE_EXHAUSTED,
            ))
        }
        ZkErrorKind::Proof(ZkProofErrorReason::InvalidProofEncoding) => {
            pb::__buffa::oneof::zk_error::Detail::ProofReason(EnumValue::from(
                pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_INVALID_PROOF_ENCODING,
            ))
        }
        ZkErrorKind::Proof(ZkProofErrorReason::InvalidProof) => {
            pb::__buffa::oneof::zk_error::Detail::ProofReason(EnumValue::from(
                pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_INVALID_PROOF,
            ))
        }
        ZkErrorKind::Proof(ZkProofErrorReason::UnsupportedProofSuite) => {
            pb::__buffa::oneof::zk_error::Detail::ProofReason(EnumValue::from(
                pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_UNSUPPORTED_PROOF_SUITE,
            ))
        }
        ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::InvalidClaimProofBundle) => {
            pb::__buffa::oneof::zk_error::Detail::BundleReason(EnumValue::from(
                pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_INVALID_PROOF_BUNDLE,
            ))
        }
        ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::DuplicateStage) => {
            pb::__buffa::oneof::zk_error::Detail::BundleReason(EnumValue::from(
                pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_DUPLICATE_STAGE,
            ))
        }
        ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::MissingStage) => {
            pb::__buffa::oneof::zk_error::Detail::BundleReason(EnumValue::from(
                pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_MISSING_STAGE,
            ))
        }
        ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::StageMismatch) => {
            pb::__buffa::oneof::zk_error::Detail::BundleReason(EnumValue::from(
                pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_STAGE_MISMATCH,
            ))
        }
        ZkErrorKind::Binding(ZkBindingErrorReason::BindingMismatch) => {
            pb::__buffa::oneof::zk_error::Detail::BindingReason(EnumValue::from(
                pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_BINDING_MISMATCH,
            ))
        }
        ZkErrorKind::Binding(ZkBindingErrorReason::UntrustedIssuer) => {
            pb::__buffa::oneof::zk_error::Detail::BindingReason(EnumValue::from(
                pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_UNTRUSTED_ISSUER,
            ))
        }
        ZkErrorKind::Binding(ZkBindingErrorReason::PresentationExpired) => {
            pb::__buffa::oneof::zk_error::Detail::BindingReason(EnumValue::from(
                pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_PRESENTATION_EXPIRED,
            ))
        }
        ZkErrorKind::Binding(ZkBindingErrorReason::PresentationExpiryTooFar) => {
            pb::__buffa::oneof::zk_error::Detail::BindingReason(EnumValue::from(
                pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR,
            ))
        }
        ZkErrorKind::Artifact(ZkArtifactErrorReason::ArtifactMismatch) => {
            pb::__buffa::oneof::zk_error::Detail::ArtifactReason(EnumValue::from(
                pb::ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_ARTIFACT_MISMATCH,
            ))
        }
        ZkErrorKind::Artifact(ZkArtifactErrorReason::ArtifactTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::ArtifactReason(EnumValue::from(
                pb::ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_ARTIFACT_TOO_LARGE,
            ))
        }
        ZkErrorKind::Backend(ZkBackendErrorReason::BackendUnavailable) => {
            pb::__buffa::oneof::zk_error::Detail::BackendReason(EnumValue::from(
                pb::ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_BACKEND_UNAVAILABLE,
            ))
        }
        ZkErrorKind::Backend(ZkBackendErrorReason::BackendFailure) => {
            pb::__buffa::oneof::zk_error::Detail::BackendReason(EnumValue::from(
                pb::ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_BACKEND_FAILURE,
            ))
        }
        ZkErrorKind::Transport(ZkTransportErrorReason::MalformedProtobuf) => {
            pb::__buffa::oneof::zk_error::Detail::TransportReason(EnumValue::from(
                pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MALFORMED_PROTOBUF,
            ))
        }
        ZkErrorKind::Transport(ZkTransportErrorReason::MalformedJson) => {
            pb::__buffa::oneof::zk_error::Detail::TransportReason(EnumValue::from(
                pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MALFORMED_JSON,
            ))
        }
        ZkErrorKind::Transport(ZkTransportErrorReason::MissingOperation) => {
            pb::__buffa::oneof::zk_error::Detail::TransportReason(EnumValue::from(
                pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MISSING_OPERATION,
            ))
        }
        ZkErrorKind::Transport(ZkTransportErrorReason::UnsupportedTransport) => {
            pb::__buffa::oneof::zk_error::Detail::TransportReason(EnumValue::from(
                pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_UNSUPPORTED_TRANSPORT,
            ))
        }
        ZkErrorKind::Transport(ZkTransportErrorReason::MessageTooLarge) => {
            pb::__buffa::oneof::zk_error::Detail::TransportReason(EnumValue::from(
                pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MESSAGE_TOO_LARGE,
            ))
        }
    }
}

fn error_kind_from_proto_detail(
    detail: Option<pb::__buffa::oneof::zk_error::Detail>,
) -> Result<ZkErrorKind, ZkError> {
    let detail = detail.ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    match detail {
        pb::__buffa::oneof::zk_error::Detail::CircuitReason(reason) => {
            circuit_error_reason_from_proto(reason).map(ZkErrorKind::Circuit)
        }
        pb::__buffa::oneof::zk_error::Detail::InputReason(reason) => {
            input_error_reason_from_proto(reason).map(ZkErrorKind::Input)
        }
        pb::__buffa::oneof::zk_error::Detail::ProofReason(reason) => {
            proof_error_reason_from_proto(reason).map(ZkErrorKind::Proof)
        }
        pb::__buffa::oneof::zk_error::Detail::BundleReason(reason) => {
            bundle_error_reason_from_proto(reason).map(ZkErrorKind::Bundle)
        }
        pb::__buffa::oneof::zk_error::Detail::BindingReason(reason) => {
            binding_error_reason_from_proto(reason).map(ZkErrorKind::Binding)
        }
        pb::__buffa::oneof::zk_error::Detail::ArtifactReason(reason) => {
            artifact_error_reason_from_proto(reason).map(ZkErrorKind::Artifact)
        }
        pb::__buffa::oneof::zk_error::Detail::BackendReason(reason) => {
            backend_error_reason_from_proto(reason).map(ZkErrorKind::Backend)
        }
        pb::__buffa::oneof::zk_error::Detail::TransportReason(reason) => {
            transport_error_reason_from_proto(reason).map(ZkErrorKind::Transport)
        }
    }
}

fn circuit_error_reason_from_proto(
    reason: EnumValue<pb::ZkCircuitErrorReason>,
) -> Result<ZkCircuitErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkCircuitErrorReason::ZK_CIRCUIT_ERROR_REASON_UNKNOWN_CIRCUIT) => {
            Ok(ZkCircuitErrorReason::UnknownCircuit)
        }
        Some(pb::ZkCircuitErrorReason::ZK_CIRCUIT_ERROR_REASON_UNSUPPORTED_CIRCUIT) => {
            Ok(ZkCircuitErrorReason::UnsupportedCircuit)
        }
        Some(pb::ZkCircuitErrorReason::ZK_CIRCUIT_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn input_error_reason_from_proto(
    reason: EnumValue<pb::ZkInputErrorReason>,
) -> Result<ZkInputErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_EMPTY_INPUT) => {
            Ok(ZkInputErrorReason::EmptyInput)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_PROOF_TOO_LARGE) => {
            Ok(ZkInputErrorReason::ProofTooLarge)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE) => {
            Ok(ZkInputErrorReason::PublicInputsTooLarge)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_WITNESS_TOO_LARGE) => {
            Ok(ZkInputErrorReason::WitnessTooLarge)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME) => {
            Ok(ZkInputErrorReason::InvalidPublicInputName)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_PUBLIC_KEY_TOO_LARGE) => {
            Ok(ZkInputErrorReason::PublicKeyTooLarge)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE) => {
            Ok(ZkInputErrorReason::ClaimPayloadTooLarge)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_LENGTH_OVERFLOW) => {
            Ok(ZkInputErrorReason::LengthOverflow)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_RESOURCE_EXHAUSTED) => {
            Ok(ZkInputErrorReason::ResourceExhausted)
        }
        Some(pb::ZkInputErrorReason::ZK_INPUT_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn proof_error_reason_from_proto(
    reason: EnumValue<pb::ZkProofErrorReason>,
) -> Result<ZkProofErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_INVALID_PROOF_ENCODING) => {
            Ok(ZkProofErrorReason::InvalidProofEncoding)
        }
        Some(pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_INVALID_PROOF) => {
            Ok(ZkProofErrorReason::InvalidProof)
        }
        Some(pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_UNSUPPORTED_PROOF_SUITE) => {
            Ok(ZkProofErrorReason::UnsupportedProofSuite)
        }
        Some(pb::ZkProofErrorReason::ZK_PROOF_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn bundle_error_reason_from_proto(
    reason: EnumValue<pb::ZkClaimProofBundleErrorReason>,
) -> Result<ZkClaimProofBundleErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_INVALID_PROOF_BUNDLE) => {
            Ok(ZkClaimProofBundleErrorReason::InvalidClaimProofBundle)
        }
        Some(pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_DUPLICATE_STAGE) => {
            Ok(ZkClaimProofBundleErrorReason::DuplicateStage)
        }
        Some(pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_MISSING_STAGE) => {
            Ok(ZkClaimProofBundleErrorReason::MissingStage)
        }
        Some(pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_STAGE_MISMATCH) => {
            Ok(ZkClaimProofBundleErrorReason::StageMismatch)
        }
        Some(pb::ZkClaimProofBundleErrorReason::ZK_CLAIM_PROOF_BUNDLE_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn binding_error_reason_from_proto(
    reason: EnumValue<pb::ZkBindingErrorReason>,
) -> Result<ZkBindingErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_BINDING_MISMATCH) => {
            Ok(ZkBindingErrorReason::BindingMismatch)
        }
        Some(pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_UNTRUSTED_ISSUER) => {
            Ok(ZkBindingErrorReason::UntrustedIssuer)
        }
        Some(pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_PRESENTATION_EXPIRED) => {
            Ok(ZkBindingErrorReason::PresentationExpired)
        }
        Some(pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR) => {
            Ok(ZkBindingErrorReason::PresentationExpiryTooFar)
        }
        Some(pb::ZkBindingErrorReason::ZK_BINDING_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn artifact_error_reason_from_proto(
    reason: EnumValue<pb::ZkArtifactErrorReason>,
) -> Result<ZkArtifactErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_ARTIFACT_MISMATCH) => {
            Ok(ZkArtifactErrorReason::ArtifactMismatch)
        }
        Some(pb::ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_ARTIFACT_TOO_LARGE) => {
            Ok(ZkArtifactErrorReason::ArtifactTooLarge)
        }
        Some(pb::ZkArtifactErrorReason::ZK_ARTIFACT_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn backend_error_reason_from_proto(
    reason: EnumValue<pb::ZkBackendErrorReason>,
) -> Result<ZkBackendErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_BACKEND_UNAVAILABLE) => {
            Ok(ZkBackendErrorReason::BackendUnavailable)
        }
        Some(pb::ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_BACKEND_FAILURE) => {
            Ok(ZkBackendErrorReason::BackendFailure)
        }
        Some(pb::ZkBackendErrorReason::ZK_BACKEND_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn transport_error_reason_from_proto(
    reason: EnumValue<pb::ZkTransportErrorReason>,
) -> Result<ZkTransportErrorReason, ZkError> {
    match reason.as_known() {
        Some(pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MALFORMED_PROTOBUF) => {
            Ok(ZkTransportErrorReason::MalformedProtobuf)
        }
        Some(pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MALFORMED_JSON) => {
            Ok(ZkTransportErrorReason::MalformedJson)
        }
        Some(pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MISSING_OPERATION) => {
            Ok(ZkTransportErrorReason::MissingOperation)
        }
        Some(pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_UNSUPPORTED_TRANSPORT) => {
            Ok(ZkTransportErrorReason::UnsupportedTransport)
        }
        Some(pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_MESSAGE_TOO_LARGE) => {
            Ok(ZkTransportErrorReason::MessageTooLarge)
        }
        Some(pb::ZkTransportErrorReason::ZK_TRANSPORT_ERROR_REASON_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

#[cfg(test)]
mod tests;
