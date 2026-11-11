// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use crate::error_reason::ZkErrorReason;

/// `reallyme.identity.common.v1.IdentityStackErrorDomain` value for ZK.
///
/// This crate deliberately avoids depending on the identity common generated
/// crate so `reallyme-zk-api` can remain the tiny cross-stack ZK dependency.
/// Boundary adapters must place this value in `IdentityStackError.domain` and
/// `ZkError::reason_code()` in `IdentityStackError.reason_code`.
pub const IDENTITY_STACK_ERROR_DOMAIN_ZK_CODE: u32 = 9;

/// Granular circuit registry and selection failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkCircuitErrorReason {
    /// The circuit identifier is not known to the registry.
    UnknownCircuit,
    /// The selected backend does not support this registered circuit.
    UnsupportedCircuit,
}

/// Granular input validation and bounded-buffer failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkInputErrorReason {
    /// Required proof, witness, or public-input bytes were empty.
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
    /// A buffer length or offset calculation overflowed.
    LengthOverflow,
    /// A bounded allocation could not be satisfied.
    ResourceExhausted,
}

/// Granular proof encoding and verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProofErrorReason {
    /// The proof bytes were malformed for the selected backend.
    InvalidProofEncoding,
    /// The proof did not verify.
    InvalidProof,
    /// The proof suite is known but not approved or supported by this provider.
    UnsupportedProofSuite,
}

/// Granular staged proof bundle failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkClaimProofBundleErrorReason {
    /// A staged proof bundle was structurally invalid.
    InvalidClaimProofBundle,
    /// A staged proof bundle repeated a stage.
    DuplicateStage,
    /// A staged proof bundle omitted a required production stage.
    MissingStage,
    /// A proof's exact source circuit did not match the requested circuit family and stage.
    StageMismatch,
}

/// Granular presentation-session binding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkBindingErrorReason {
    /// Public inputs did not bind to the active verifier session.
    BindingMismatch,
    /// The proved issuer key was absent from verifier trust policy.
    UntrustedIssuer,
    /// The presentation expiry is before the verifier's trusted clock.
    PresentationExpired,
    /// The presentation expiry exceeds the configured short-lived window.
    PresentationExpiryTooFar,
}

/// Granular artifact and manifest failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkArtifactErrorReason {
    /// The required artifact was missing or did not match its pinned hash.
    ArtifactMismatch,
    /// An artifact exceeded the kind-specific maximum accepted size.
    ArtifactTooLarge,
}

/// Granular backend availability and execution failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkBackendErrorReason {
    /// A concrete backend was not configured.
    BackendUnavailable,
    /// A backend failed without exposing details safe for audit logs.
    BackendFailure,
}

/// Granular transport decoding and operation-envelope failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkTransportErrorReason {
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
}

/// Structured ZK failure kind.
///
/// This is the Rust corollary of the proto `ZkError` oneof. It preserves the
/// narrow component that failed while still normalizing deterministically to the
/// stable public `ZkErrorReason` code used by identity-common envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkErrorKind {
    /// Circuit registry or selection failure.
    Circuit(ZkCircuitErrorReason),
    /// Input validation or bounded-buffer failure.
    Input(ZkInputErrorReason),
    /// Proof encoding or verification failure.
    Proof(ZkProofErrorReason),
    /// Staged proof bundle failure.
    Bundle(ZkClaimProofBundleErrorReason),
    /// Presentation-session binding failure.
    Binding(ZkBindingErrorReason),
    /// Artifact or manifest failure.
    Artifact(ZkArtifactErrorReason),
    /// Backend availability or execution failure.
    Backend(ZkBackendErrorReason),
    /// Transport decoding or operation-envelope failure.
    Transport(ZkTransportErrorReason),
}

impl ZkErrorKind {
    /// Returns the stable top-level public reason for this structured failure.
    #[must_use]
    pub const fn reason(self) -> ZkErrorReason {
        match self {
            ZkErrorKind::Circuit(ZkCircuitErrorReason::UnknownCircuit) => {
                ZkErrorReason::UnknownCircuit
            }
            ZkErrorKind::Circuit(ZkCircuitErrorReason::UnsupportedCircuit) => {
                ZkErrorReason::UnsupportedCircuit
            }
            ZkErrorKind::Input(ZkInputErrorReason::EmptyInput) => ZkErrorReason::EmptyInput,
            ZkErrorKind::Input(ZkInputErrorReason::ProofTooLarge) => ZkErrorReason::ProofTooLarge,
            ZkErrorKind::Input(ZkInputErrorReason::PublicInputsTooLarge) => {
                ZkErrorReason::PublicInputsTooLarge
            }
            ZkErrorKind::Input(ZkInputErrorReason::WitnessTooLarge) => {
                ZkErrorReason::WitnessTooLarge
            }
            ZkErrorKind::Input(ZkInputErrorReason::InvalidPublicInputName) => {
                ZkErrorReason::InvalidPublicInputName
            }
            ZkErrorKind::Input(ZkInputErrorReason::PublicKeyTooLarge) => {
                ZkErrorReason::PublicKeyTooLarge
            }
            ZkErrorKind::Input(ZkInputErrorReason::ClaimPayloadTooLarge) => {
                ZkErrorReason::ClaimPayloadTooLarge
            }
            ZkErrorKind::Input(ZkInputErrorReason::LengthOverflow) => ZkErrorReason::LengthOverflow,
            ZkErrorKind::Input(ZkInputErrorReason::ResourceExhausted) => {
                ZkErrorReason::ResourceExhausted
            }
            ZkErrorKind::Proof(ZkProofErrorReason::InvalidProofEncoding) => {
                ZkErrorReason::InvalidProofEncoding
            }
            ZkErrorKind::Proof(ZkProofErrorReason::InvalidProof) => ZkErrorReason::InvalidProof,
            ZkErrorKind::Proof(ZkProofErrorReason::UnsupportedProofSuite) => {
                ZkErrorReason::UnsupportedProofSuite
            }
            ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::InvalidClaimProofBundle) => {
                ZkErrorReason::InvalidClaimProofBundle
            }
            ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::DuplicateStage) => {
                ZkErrorReason::DuplicateStage
            }
            ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::MissingStage) => {
                ZkErrorReason::MissingStage
            }
            ZkErrorKind::Bundle(ZkClaimProofBundleErrorReason::StageMismatch) => {
                ZkErrorReason::StageMismatch
            }
            ZkErrorKind::Binding(ZkBindingErrorReason::BindingMismatch) => {
                ZkErrorReason::BindingMismatch
            }
            ZkErrorKind::Binding(ZkBindingErrorReason::UntrustedIssuer) => {
                ZkErrorReason::UntrustedIssuer
            }
            ZkErrorKind::Binding(ZkBindingErrorReason::PresentationExpired) => {
                ZkErrorReason::PresentationExpired
            }
            ZkErrorKind::Binding(ZkBindingErrorReason::PresentationExpiryTooFar) => {
                ZkErrorReason::PresentationExpiryTooFar
            }
            ZkErrorKind::Artifact(ZkArtifactErrorReason::ArtifactMismatch) => {
                ZkErrorReason::ArtifactMismatch
            }
            ZkErrorKind::Artifact(ZkArtifactErrorReason::ArtifactTooLarge) => {
                ZkErrorReason::ArtifactTooLarge
            }
            ZkErrorKind::Backend(ZkBackendErrorReason::BackendUnavailable) => {
                ZkErrorReason::BackendUnavailable
            }
            ZkErrorKind::Backend(ZkBackendErrorReason::BackendFailure) => {
                ZkErrorReason::BackendFailure
            }
            ZkErrorKind::Transport(ZkTransportErrorReason::MalformedProtobuf) => {
                ZkErrorReason::MalformedProtobuf
            }
            ZkErrorKind::Transport(ZkTransportErrorReason::MalformedJson) => {
                ZkErrorReason::MalformedJson
            }
            ZkErrorKind::Transport(ZkTransportErrorReason::MissingOperation) => {
                ZkErrorReason::MissingOperation
            }
            ZkErrorKind::Transport(ZkTransportErrorReason::UnsupportedTransport) => {
                ZkErrorReason::UnsupportedTransport
            }
            ZkErrorKind::Transport(ZkTransportErrorReason::MessageTooLarge) => {
                ZkErrorReason::MessageTooLarge
            }
        }
    }
}

impl core::fmt::Display for ZkErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.reason().fmt(f)
    }
}

impl From<ZkErrorReason> for ZkErrorKind {
    fn from(reason: ZkErrorReason) -> Self {
        reason.kind()
    }
}

impl From<ZkErrorKind> for ZkErrorReason {
    fn from(kind: ZkErrorKind) -> Self {
        kind.reason()
    }
}

impl From<ZkCircuitErrorReason> for ZkErrorKind {
    fn from(reason: ZkCircuitErrorReason) -> Self {
        ZkErrorKind::Circuit(reason)
    }
}

impl From<ZkInputErrorReason> for ZkErrorKind {
    fn from(reason: ZkInputErrorReason) -> Self {
        ZkErrorKind::Input(reason)
    }
}

impl From<ZkProofErrorReason> for ZkErrorKind {
    fn from(reason: ZkProofErrorReason) -> Self {
        ZkErrorKind::Proof(reason)
    }
}

impl From<ZkClaimProofBundleErrorReason> for ZkErrorKind {
    fn from(reason: ZkClaimProofBundleErrorReason) -> Self {
        ZkErrorKind::Bundle(reason)
    }
}

impl From<ZkBindingErrorReason> for ZkErrorKind {
    fn from(reason: ZkBindingErrorReason) -> Self {
        ZkErrorKind::Binding(reason)
    }
}

impl From<ZkArtifactErrorReason> for ZkErrorKind {
    fn from(reason: ZkArtifactErrorReason) -> Self {
        ZkErrorKind::Artifact(reason)
    }
}

impl From<ZkBackendErrorReason> for ZkErrorKind {
    fn from(reason: ZkBackendErrorReason) -> Self {
        ZkErrorKind::Backend(reason)
    }
}

impl From<ZkTransportErrorReason> for ZkErrorKind {
    fn from(reason: ZkTransportErrorReason) -> Self {
        ZkErrorKind::Transport(reason)
    }
}

/// Domain-specific ZK error.
///
/// The error carries only a stable reason enum. Raw proof bytes, witness data,
/// public inputs, verifier identifiers, and backend exception text must never
/// be embedded in this type.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("zk operation failed: {kind}")]
pub struct ZkError {
    kind: ZkErrorKind,
}

impl ZkError {
    /// Creates a ZK error with a stable, non-sensitive reason.
    #[must_use]
    pub const fn new(reason: ZkErrorReason) -> Self {
        Self {
            kind: reason.kind(),
        }
    }

    /// Creates a ZK error with a structured, non-sensitive failure kind.
    #[must_use]
    pub const fn from_kind(kind: ZkErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the structured, non-sensitive kind for this failure.
    #[must_use]
    pub const fn kind(&self) -> ZkErrorKind {
        self.kind
    }

    /// Returns the stable, non-sensitive reason for this failure.
    #[must_use]
    pub const fn reason(&self) -> ZkErrorReason {
        self.kind.reason()
    }

    /// Returns the identity common stack error domain code for this error.
    #[must_use]
    pub const fn identity_stack_error_domain_code(&self) -> u32 {
        IDENTITY_STACK_ERROR_DOMAIN_ZK_CODE
    }

    /// Returns the stable protobuf reason code for this error.
    #[must_use]
    pub const fn reason_code(&self) -> u32 {
        self.kind.reason().reason_code()
    }
}

#[cfg(test)]
mod tests;
