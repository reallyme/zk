// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{
    ZkArtifactErrorReason, ZkBackendErrorReason, ZkBindingErrorReason, ZkCircuitErrorReason,
    ZkClaimProofBundleErrorReason, ZkError, ZkErrorKind, ZkInputErrorReason, ZkProofErrorReason,
    ZkTransportErrorReason,
};

/// Protobuf default value for `reallyme.zk.v1.ZkErrorReason`.
pub const ZK_ERROR_REASON_UNSPECIFIED_CODE: u32 = 0;

const ZK_ERROR_REASON_UNKNOWN_CIRCUIT_CODE: u32 = 1;
const ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT_CODE: u32 = 2;
const ZK_ERROR_REASON_EMPTY_INPUT_CODE: u32 = 3;
const ZK_ERROR_REASON_PROOF_TOO_LARGE_CODE: u32 = 4;
const ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE_CODE: u32 = 5;
const ZK_ERROR_REASON_LENGTH_OVERFLOW_CODE: u32 = 6;
const ZK_ERROR_REASON_INVALID_PROOF_ENCODING_CODE: u32 = 7;
const ZK_ERROR_REASON_INVALID_PROOF_CODE: u32 = 8;
const ZK_ERROR_REASON_BINDING_MISMATCH_CODE: u32 = 9;
const ZK_ERROR_REASON_ARTIFACT_MISMATCH_CODE: u32 = 10;
const ZK_ERROR_REASON_BACKEND_UNAVAILABLE_CODE: u32 = 11;
const ZK_ERROR_REASON_BACKEND_FAILURE_CODE: u32 = 12;
const ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME_CODE: u32 = 13;
const ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE_CODE: u32 = 14;
const ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE_CODE: u32 = 15;
const ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE_CODE: u32 = 16;
const ZK_ERROR_REASON_DUPLICATE_STAGE_CODE: u32 = 17;
const ZK_ERROR_REASON_MISSING_STAGE_CODE: u32 = 18;
const ZK_ERROR_REASON_STAGE_MISMATCH_CODE: u32 = 19;
const ZK_ERROR_REASON_WITNESS_TOO_LARGE_CODE: u32 = 20;
const ZK_ERROR_REASON_MALFORMED_PROTOBUF_CODE: u32 = 21;
const ZK_ERROR_REASON_MALFORMED_JSON_CODE: u32 = 22;
const ZK_ERROR_REASON_MISSING_OPERATION_CODE: u32 = 23;
const ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT_CODE: u32 = 24;
const ZK_ERROR_REASON_MESSAGE_TOO_LARGE_CODE: u32 = 25;
const ZK_ERROR_REASON_ARTIFACT_TOO_LARGE_CODE: u32 = 26;
const ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE_CODE: u32 = 27;
const ZK_ERROR_REASON_UNTRUSTED_ISSUER_CODE: u32 = 28;
const ZK_ERROR_REASON_PRESENTATION_EXPIRED_CODE: u32 = 29;
const ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR_CODE: u32 = 30;
const ZK_ERROR_REASON_RESOURCE_EXHAUSTED_CODE: u32 = 31;

/// Specific, non-sensitive reason a ZK operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkErrorReason {
    /// The circuit identifier is not known to the registry.
    UnknownCircuit,
    /// The selected backend does not support this registered circuit.
    UnsupportedCircuit,
    /// The proof or public input buffer was empty where bytes are required.
    EmptyInput,
    /// A proof exceeded the API-level maximum accepted size.
    ProofTooLarge,
    /// Public inputs exceeded the API-level maximum accepted size.
    PublicInputsTooLarge,
    /// Secret witness material exceeded the API-level maximum accepted size.
    WitnessTooLarge,
    /// A public-input name was empty or exceeded the API-level maximum.
    InvalidPublicInputName,
    /// A public key or verification key identifier exceeded the API-level maximum.
    PublicKeyTooLarge,
    /// A VC claim payload exceeded the API-level maximum.
    ClaimPayloadTooLarge,
    /// A staged proof bundle was structurally invalid.
    InvalidClaimProofBundle,
    /// A staged proof bundle repeated a stage.
    DuplicateStage,
    /// A staged proof bundle omitted a required production stage.
    MissingStage,
    /// A proof's exact source circuit did not match the requested circuit family and stage.
    StageMismatch,
    /// A buffer length or offset calculation overflowed.
    LengthOverflow,
    /// A bounded allocation could not be satisfied.
    ResourceExhausted,
    /// The proof bytes were malformed for the selected backend.
    InvalidProofEncoding,
    /// The proof did not verify.
    InvalidProof,
    /// Public inputs did not bind to the active verifier session.
    BindingMismatch,
    /// The required artifact was missing or did not match its pinned hash.
    ArtifactMismatch,
    /// An artifact exceeded the kind-specific maximum accepted size.
    ArtifactTooLarge,
    /// A concrete backend was not configured.
    BackendUnavailable,
    /// A backend failed without exposing details safe for audit logs.
    BackendFailure,
    /// Binary protobuf input was malformed or violated strict decoder limits.
    MalformedProtobuf,
    /// ProtoJSON input was malformed or violated the canonical request shape.
    MalformedJson,
    /// The canonical operation oneof was not set.
    MissingOperation,
    /// The selected operation is forbidden on the requested transport.
    UnsupportedTransport,
    /// The encoded request exceeded the canonical operation byte limit.
    MessageTooLarge,
    /// The proof suite is known but not approved or supported by this provider.
    UnsupportedProofSuite,
    /// The proved issuer key was absent from verifier trust policy.
    UntrustedIssuer,
    /// The presentation expiry is before the verifier's trusted clock.
    PresentationExpired,
    /// The presentation expiry exceeds the configured short-lived window.
    PresentationExpiryTooFar,
}

impl ZkErrorReason {
    /// Returns the structured Rust error kind for this public reason.
    #[must_use]
    pub const fn kind(self) -> ZkErrorKind {
        match self {
            ZkErrorReason::UnknownCircuit => {
                ZkErrorKind::Circuit(ZkCircuitErrorReason::UnknownCircuit)
            }
            ZkErrorReason::UnsupportedCircuit => {
                ZkErrorKind::Circuit(ZkCircuitErrorReason::UnsupportedCircuit)
            }
            ZkErrorReason::EmptyInput => ZkErrorKind::Input(ZkInputErrorReason::EmptyInput),
            ZkErrorReason::ProofTooLarge => ZkErrorKind::Input(ZkInputErrorReason::ProofTooLarge),
            ZkErrorReason::PublicInputsTooLarge => {
                ZkErrorKind::Input(ZkInputErrorReason::PublicInputsTooLarge)
            }
            ZkErrorReason::WitnessTooLarge => {
                ZkErrorKind::Input(ZkInputErrorReason::WitnessTooLarge)
            }
            ZkErrorReason::InvalidPublicInputName => {
                ZkErrorKind::Input(ZkInputErrorReason::InvalidPublicInputName)
            }
            ZkErrorReason::PublicKeyTooLarge => {
                ZkErrorKind::Input(ZkInputErrorReason::PublicKeyTooLarge)
            }
            ZkErrorReason::ClaimPayloadTooLarge => {
                ZkErrorKind::Input(ZkInputErrorReason::ClaimPayloadTooLarge)
            }
            ZkErrorReason::InvalidClaimProofBundle => {
                ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::InvalidClaimProofBundle)
            }
            ZkErrorReason::DuplicateStage => {
                ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::DuplicateStage)
            }
            ZkErrorReason::MissingStage => {
                ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::MissingStage)
            }
            ZkErrorReason::StageMismatch => {
                ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::StageMismatch)
            }
            ZkErrorReason::LengthOverflow => ZkErrorKind::Input(ZkInputErrorReason::LengthOverflow),
            ZkErrorReason::ResourceExhausted => {
                ZkErrorKind::Input(ZkInputErrorReason::ResourceExhausted)
            }
            ZkErrorReason::InvalidProofEncoding => {
                ZkErrorKind::Proof(ZkProofErrorReason::InvalidProofEncoding)
            }
            ZkErrorReason::InvalidProof => ZkErrorKind::Proof(ZkProofErrorReason::InvalidProof),
            ZkErrorReason::UnsupportedProofSuite => {
                ZkErrorKind::Proof(ZkProofErrorReason::UnsupportedProofSuite)
            }
            ZkErrorReason::BindingMismatch => {
                ZkErrorKind::Binding(ZkBindingErrorReason::BindingMismatch)
            }
            ZkErrorReason::UntrustedIssuer => {
                ZkErrorKind::Binding(ZkBindingErrorReason::UntrustedIssuer)
            }
            ZkErrorReason::PresentationExpired => {
                ZkErrorKind::Binding(ZkBindingErrorReason::PresentationExpired)
            }
            ZkErrorReason::PresentationExpiryTooFar => {
                ZkErrorKind::Binding(ZkBindingErrorReason::PresentationExpiryTooFar)
            }
            ZkErrorReason::ArtifactMismatch => {
                ZkErrorKind::Artifact(ZkArtifactErrorReason::ArtifactMismatch)
            }
            ZkErrorReason::ArtifactTooLarge => {
                ZkErrorKind::Artifact(ZkArtifactErrorReason::ArtifactTooLarge)
            }
            ZkErrorReason::BackendUnavailable => {
                ZkErrorKind::Backend(ZkBackendErrorReason::BackendUnavailable)
            }
            ZkErrorReason::BackendFailure => {
                ZkErrorKind::Backend(ZkBackendErrorReason::BackendFailure)
            }
            ZkErrorReason::MalformedProtobuf => {
                ZkErrorKind::Transport(ZkTransportErrorReason::MalformedProtobuf)
            }
            ZkErrorReason::MalformedJson => {
                ZkErrorKind::Transport(ZkTransportErrorReason::MalformedJson)
            }
            ZkErrorReason::MissingOperation => {
                ZkErrorKind::Transport(ZkTransportErrorReason::MissingOperation)
            }
            ZkErrorReason::UnsupportedTransport => {
                ZkErrorKind::Transport(ZkTransportErrorReason::UnsupportedTransport)
            }
            ZkErrorReason::MessageTooLarge => {
                ZkErrorKind::Transport(ZkTransportErrorReason::MessageTooLarge)
            }
        }
    }

    /// Returns the stable `reallyme.zk.v1.ZkErrorReason` numeric value.
    #[must_use]
    pub const fn reason_code(self) -> u32 {
        match self {
            ZkErrorReason::UnknownCircuit => ZK_ERROR_REASON_UNKNOWN_CIRCUIT_CODE,
            ZkErrorReason::UnsupportedCircuit => ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT_CODE,
            ZkErrorReason::EmptyInput => ZK_ERROR_REASON_EMPTY_INPUT_CODE,
            ZkErrorReason::ProofTooLarge => ZK_ERROR_REASON_PROOF_TOO_LARGE_CODE,
            ZkErrorReason::PublicInputsTooLarge => ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE_CODE,
            ZkErrorReason::WitnessTooLarge => ZK_ERROR_REASON_WITNESS_TOO_LARGE_CODE,
            ZkErrorReason::InvalidPublicInputName => ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME_CODE,
            ZkErrorReason::PublicKeyTooLarge => ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE_CODE,
            ZkErrorReason::ClaimPayloadTooLarge => ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE_CODE,
            ZkErrorReason::InvalidClaimProofBundle => {
                ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE_CODE
            }
            ZkErrorReason::DuplicateStage => ZK_ERROR_REASON_DUPLICATE_STAGE_CODE,
            ZkErrorReason::MissingStage => ZK_ERROR_REASON_MISSING_STAGE_CODE,
            ZkErrorReason::StageMismatch => ZK_ERROR_REASON_STAGE_MISMATCH_CODE,
            ZkErrorReason::LengthOverflow => ZK_ERROR_REASON_LENGTH_OVERFLOW_CODE,
            ZkErrorReason::InvalidProofEncoding => ZK_ERROR_REASON_INVALID_PROOF_ENCODING_CODE,
            ZkErrorReason::InvalidProof => ZK_ERROR_REASON_INVALID_PROOF_CODE,
            ZkErrorReason::BindingMismatch => ZK_ERROR_REASON_BINDING_MISMATCH_CODE,
            ZkErrorReason::ArtifactMismatch => ZK_ERROR_REASON_ARTIFACT_MISMATCH_CODE,
            ZkErrorReason::ArtifactTooLarge => ZK_ERROR_REASON_ARTIFACT_TOO_LARGE_CODE,
            ZkErrorReason::BackendUnavailable => ZK_ERROR_REASON_BACKEND_UNAVAILABLE_CODE,
            ZkErrorReason::BackendFailure => ZK_ERROR_REASON_BACKEND_FAILURE_CODE,
            ZkErrorReason::MalformedProtobuf => ZK_ERROR_REASON_MALFORMED_PROTOBUF_CODE,
            ZkErrorReason::MalformedJson => ZK_ERROR_REASON_MALFORMED_JSON_CODE,
            ZkErrorReason::MissingOperation => ZK_ERROR_REASON_MISSING_OPERATION_CODE,
            ZkErrorReason::UnsupportedTransport => ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT_CODE,
            ZkErrorReason::MessageTooLarge => ZK_ERROR_REASON_MESSAGE_TOO_LARGE_CODE,
            ZkErrorReason::UnsupportedProofSuite => ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE_CODE,
            ZkErrorReason::UntrustedIssuer => ZK_ERROR_REASON_UNTRUSTED_ISSUER_CODE,
            ZkErrorReason::PresentationExpired => ZK_ERROR_REASON_PRESENTATION_EXPIRED_CODE,
            ZkErrorReason::PresentationExpiryTooFar => {
                ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR_CODE
            }
            ZkErrorReason::ResourceExhausted => ZK_ERROR_REASON_RESOURCE_EXHAUSTED_CODE,
        }
    }

    /// Returns the stable `reallyme.zk.v1.ZkErrorReason` protobuf enum name.
    #[must_use]
    pub const fn proto_name(self) -> &'static str {
        match self {
            ZkErrorReason::UnknownCircuit => "ZK_ERROR_REASON_UNKNOWN_CIRCUIT",
            ZkErrorReason::UnsupportedCircuit => "ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT",
            ZkErrorReason::EmptyInput => "ZK_ERROR_REASON_EMPTY_INPUT",
            ZkErrorReason::ProofTooLarge => "ZK_ERROR_REASON_PROOF_TOO_LARGE",
            ZkErrorReason::PublicInputsTooLarge => "ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE",
            ZkErrorReason::WitnessTooLarge => "ZK_ERROR_REASON_WITNESS_TOO_LARGE",
            ZkErrorReason::InvalidPublicInputName => "ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME",
            ZkErrorReason::PublicKeyTooLarge => "ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE",
            ZkErrorReason::ClaimPayloadTooLarge => "ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE",
            ZkErrorReason::InvalidClaimProofBundle => "ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE",
            ZkErrorReason::DuplicateStage => "ZK_ERROR_REASON_DUPLICATE_STAGE",
            ZkErrorReason::MissingStage => "ZK_ERROR_REASON_MISSING_STAGE",
            ZkErrorReason::StageMismatch => "ZK_ERROR_REASON_STAGE_MISMATCH",
            ZkErrorReason::LengthOverflow => "ZK_ERROR_REASON_LENGTH_OVERFLOW",
            ZkErrorReason::InvalidProofEncoding => "ZK_ERROR_REASON_INVALID_PROOF_ENCODING",
            ZkErrorReason::InvalidProof => "ZK_ERROR_REASON_INVALID_PROOF",
            ZkErrorReason::BindingMismatch => "ZK_ERROR_REASON_BINDING_MISMATCH",
            ZkErrorReason::ArtifactMismatch => "ZK_ERROR_REASON_ARTIFACT_MISMATCH",
            ZkErrorReason::ArtifactTooLarge => "ZK_ERROR_REASON_ARTIFACT_TOO_LARGE",
            ZkErrorReason::BackendUnavailable => "ZK_ERROR_REASON_BACKEND_UNAVAILABLE",
            ZkErrorReason::BackendFailure => "ZK_ERROR_REASON_BACKEND_FAILURE",
            ZkErrorReason::MalformedProtobuf => "ZK_ERROR_REASON_MALFORMED_PROTOBUF",
            ZkErrorReason::MalformedJson => "ZK_ERROR_REASON_MALFORMED_JSON",
            ZkErrorReason::MissingOperation => "ZK_ERROR_REASON_MISSING_OPERATION",
            ZkErrorReason::UnsupportedTransport => "ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT",
            ZkErrorReason::MessageTooLarge => "ZK_ERROR_REASON_MESSAGE_TOO_LARGE",
            ZkErrorReason::UnsupportedProofSuite => "ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE",
            ZkErrorReason::UntrustedIssuer => "ZK_ERROR_REASON_UNTRUSTED_ISSUER",
            ZkErrorReason::PresentationExpired => "ZK_ERROR_REASON_PRESENTATION_EXPIRED",
            ZkErrorReason::PresentationExpiryTooFar => {
                "ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR"
            }
            ZkErrorReason::ResourceExhausted => "ZK_ERROR_REASON_RESOURCE_EXHAUSTED",
        }
    }

    /// Converts a public proto reason code back into the Rust domain reason.
    ///
    /// The protobuf default and unknown open-enum values fail closed as a
    /// malformed transport value. Adapters must not surface raw unknown numeric
    /// values across FFI, RPC, telemetry, or audit-log boundaries.
    pub const fn from_reason_code(reason_code: u32) -> Result<Self, ZkError> {
        match reason_code {
            ZK_ERROR_REASON_UNKNOWN_CIRCUIT_CODE => Ok(ZkErrorReason::UnknownCircuit),
            ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT_CODE => Ok(ZkErrorReason::UnsupportedCircuit),
            ZK_ERROR_REASON_EMPTY_INPUT_CODE => Ok(ZkErrorReason::EmptyInput),
            ZK_ERROR_REASON_PROOF_TOO_LARGE_CODE => Ok(ZkErrorReason::ProofTooLarge),
            ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE_CODE => Ok(ZkErrorReason::PublicInputsTooLarge),
            ZK_ERROR_REASON_WITNESS_TOO_LARGE_CODE => Ok(ZkErrorReason::WitnessTooLarge),
            ZK_ERROR_REASON_LENGTH_OVERFLOW_CODE => Ok(ZkErrorReason::LengthOverflow),
            ZK_ERROR_REASON_INVALID_PROOF_ENCODING_CODE => Ok(ZkErrorReason::InvalidProofEncoding),
            ZK_ERROR_REASON_INVALID_PROOF_CODE => Ok(ZkErrorReason::InvalidProof),
            ZK_ERROR_REASON_BINDING_MISMATCH_CODE => Ok(ZkErrorReason::BindingMismatch),
            ZK_ERROR_REASON_ARTIFACT_MISMATCH_CODE => Ok(ZkErrorReason::ArtifactMismatch),
            ZK_ERROR_REASON_ARTIFACT_TOO_LARGE_CODE => Ok(ZkErrorReason::ArtifactTooLarge),
            ZK_ERROR_REASON_BACKEND_UNAVAILABLE_CODE => Ok(ZkErrorReason::BackendUnavailable),
            ZK_ERROR_REASON_BACKEND_FAILURE_CODE => Ok(ZkErrorReason::BackendFailure),
            ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME_CODE => {
                Ok(ZkErrorReason::InvalidPublicInputName)
            }
            ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE_CODE => Ok(ZkErrorReason::PublicKeyTooLarge),
            ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE_CODE => Ok(ZkErrorReason::ClaimPayloadTooLarge),
            ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE_CODE => {
                Ok(ZkErrorReason::InvalidClaimProofBundle)
            }
            ZK_ERROR_REASON_DUPLICATE_STAGE_CODE => Ok(ZkErrorReason::DuplicateStage),
            ZK_ERROR_REASON_MISSING_STAGE_CODE => Ok(ZkErrorReason::MissingStage),
            ZK_ERROR_REASON_STAGE_MISMATCH_CODE => Ok(ZkErrorReason::StageMismatch),
            ZK_ERROR_REASON_MALFORMED_PROTOBUF_CODE => Ok(ZkErrorReason::MalformedProtobuf),
            ZK_ERROR_REASON_MALFORMED_JSON_CODE => Ok(ZkErrorReason::MalformedJson),
            ZK_ERROR_REASON_MISSING_OPERATION_CODE => Ok(ZkErrorReason::MissingOperation),
            ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT_CODE => Ok(ZkErrorReason::UnsupportedTransport),
            ZK_ERROR_REASON_MESSAGE_TOO_LARGE_CODE => Ok(ZkErrorReason::MessageTooLarge),
            ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE_CODE => {
                Ok(ZkErrorReason::UnsupportedProofSuite)
            }
            ZK_ERROR_REASON_UNTRUSTED_ISSUER_CODE => Ok(ZkErrorReason::UntrustedIssuer),
            ZK_ERROR_REASON_PRESENTATION_EXPIRED_CODE => Ok(ZkErrorReason::PresentationExpired),
            ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR_CODE => {
                Ok(ZkErrorReason::PresentationExpiryTooFar)
            }
            ZK_ERROR_REASON_RESOURCE_EXHAUSTED_CODE => Ok(ZkErrorReason::ResourceExhausted),
            ZK_ERROR_REASON_UNSPECIFIED_CODE => Err(ZkError::new(ZkErrorReason::MalformedProtobuf)),
            _ => Err(ZkError::new(ZkErrorReason::MalformedProtobuf)),
        }
    }
}

impl core::fmt::Display for ZkErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            ZkErrorReason::UnknownCircuit => "unknown circuit",
            ZkErrorReason::UnsupportedCircuit => "unsupported circuit",
            ZkErrorReason::EmptyInput => "empty input",
            ZkErrorReason::ProofTooLarge => "proof too large",
            ZkErrorReason::PublicInputsTooLarge => "public inputs too large",
            ZkErrorReason::WitnessTooLarge => "witness too large",
            ZkErrorReason::InvalidPublicInputName => "invalid public input name",
            ZkErrorReason::PublicKeyTooLarge => "public key too large",
            ZkErrorReason::ClaimPayloadTooLarge => "claim payload too large",
            ZkErrorReason::InvalidClaimProofBundle => "invalid proof bundle",
            ZkErrorReason::DuplicateStage => "duplicate proof stage",
            ZkErrorReason::MissingStage => "missing proof stage",
            ZkErrorReason::StageMismatch => "proof stage mismatch",
            ZkErrorReason::LengthOverflow => "length overflow",
            ZkErrorReason::InvalidProofEncoding => "invalid proof encoding",
            ZkErrorReason::InvalidProof => "invalid proof",
            ZkErrorReason::BindingMismatch => "binding mismatch",
            ZkErrorReason::ArtifactMismatch => "artifact mismatch",
            ZkErrorReason::ArtifactTooLarge => "artifact too large",
            ZkErrorReason::BackendUnavailable => "backend unavailable",
            ZkErrorReason::BackendFailure => "backend failure",
            ZkErrorReason::MalformedProtobuf => "malformed protobuf",
            ZkErrorReason::MalformedJson => "malformed JSON",
            ZkErrorReason::MissingOperation => "missing operation",
            ZkErrorReason::UnsupportedTransport => "unsupported transport",
            ZkErrorReason::MessageTooLarge => "message too large",
            ZkErrorReason::UnsupportedProofSuite => "unsupported proof suite",
            ZkErrorReason::UntrustedIssuer => "untrusted issuer",
            ZkErrorReason::PresentationExpired => "presentation expired",
            ZkErrorReason::PresentationExpiryTooFar => "presentation expiry too far",
            ZkErrorReason::ResourceExhausted => "resource exhausted",
        };
        f.write_str(detail)
    }
}
