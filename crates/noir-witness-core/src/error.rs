// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::{Display, Formatter};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessErrorReason {
    ArtifactEmpty,
    ArtifactTooLarge,
    ArtifactUtf8Invalid,
    ArtifactJsonInvalid,
    ArtifactAbiMismatch,
    ClaimBundleCountOutOfRange,
    ClaimValueLengthOutOfRange,
    CommonCredentialRootStatusPathLengthOutOfRange,
    PreparedStatusInputOutOfRange,
    PreparedClaimInputOutOfRange,
    MerklePathLengthOutOfRange,
    AbiEncodingFailed,
    CircuitExecutionFailed,
    ForeignCallResolutionFailed,
    RequiredFixtureRootMissing,
    WitnessSerializationFailed,
}

impl Display for WitnessErrorReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            Self::ArtifactEmpty => "compiled program artifact is empty",
            Self::ArtifactTooLarge => "compiled program artifact exceeds the supported size",
            Self::ArtifactUtf8Invalid => "artifact JSON is not valid UTF-8",
            Self::ArtifactJsonInvalid => "artifact JSON could not be parsed",
            Self::ArtifactAbiMismatch => {
                "artifact ABI does not match the expected credential circuit schema"
            }
            Self::ClaimBundleCountOutOfRange => {
                "claim bundle count exceeds the fixed circuit capacity"
            }
            Self::ClaimValueLengthOutOfRange => {
                "claim value length exceeds the fixed circuit capacity"
            }
            Self::CommonCredentialRootStatusPathLengthOutOfRange => {
                "common-credential-root status path length exceeds the fixed circuit capacity"
            }
            Self::PreparedStatusInputOutOfRange => {
                "prepared status input is outside the circuit bounds"
            }
            Self::PreparedClaimInputOutOfRange => {
                "prepared claim input is outside the circuit bounds"
            }
            Self::MerklePathLengthOutOfRange => {
                "claim merkle path length does not equal the fixed claim tree depth"
            }
            Self::AbiEncodingFailed => "typed inputs could not be encoded into the initial witness",
            Self::CircuitExecutionFailed => "circuit execution failed",
            Self::ForeignCallResolutionFailed => {
                "circuit requires unsupported foreign call resolution"
            }
            Self::RequiredFixtureRootMissing => "required all-circuits fixture root is missing",
            Self::WitnessSerializationFailed => "witness stack serialization failed",
        };

        formatter.write_str(description)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{reason}")]
pub struct WitnessError {
    pub reason: WitnessErrorReason,
}

impl WitnessError {
    pub const fn new(reason: WitnessErrorReason) -> Self {
        Self { reason }
    }
}
