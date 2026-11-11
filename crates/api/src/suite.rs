// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact proof-suite policy shared by artifacts, providers, and adapters.

use crate::errors::ZkError;

/// Fiat-Shamir transcript hash used by a proof suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkTranscriptHash {
    /// Keccak transcript supported by Barretenberg's ZK UltraHonk flavor.
    Keccak,
    /// Poseidon2 transcript used by Barretenberg's UltraHonk flavor.
    Poseidon2,
}

/// Fully specified proving and verification suite.
///
/// An enum deliberately prevents partially specified or contradictory
/// combinations from reaching a backend. New combinations require an additive
/// protocol value and a separate security review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkProofSuite {
    /// Approved production suite: Keccak transcript, ZK enabled, no IPA.
    BarretenbergUltraHonkKeccakZkNoIpa,
    /// Poseidon2 transcript, ZK masking enabled, no IPA accumulation.
    BarretenbergUltraHonkPoseidon2ZkNoIpa,
    /// Keccak transcript, without ZK masking, no IPA accumulation.
    ///
    /// This compatibility lane proves statement validity but does not provide
    /// the witness-hiding guarantee of a zero-knowledge proof.
    BarretenbergUltraHonkKeccakUnmaskedNoIpa,
    /// Poseidon2 transcript, without ZK masking, no IPA accumulation.
    ///
    /// This is the resource-constrained iOS compatibility lane. It must never
    /// be silently selected when a caller requested a ZK-masked suite.
    BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
}

impl ZkProofSuite {
    /// The only suite approved for production proof construction.
    pub const PRODUCTION: Self = Self::BarretenbergUltraHonkKeccakZkNoIpa;

    /// Every suite represented by the stable API contract.
    pub const ALL: &'static [Self] = &[
        Self::BarretenbergUltraHonkKeccakZkNoIpa,
        Self::BarretenbergUltraHonkPoseidon2ZkNoIpa,
        Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa,
        Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
    ];

    /// Stable configuration and manifest name for this exact suite.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BarretenbergUltraHonkKeccakZkNoIpa => "barretenberg_ultra_honk_keccak_zk_no_ipa",
            Self::BarretenbergUltraHonkPoseidon2ZkNoIpa => {
                "barretenberg_ultra_honk_poseidon2_zk_no_ipa"
            }
            Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa => {
                "barretenberg_ultra_honk_keccak_unmasked_no_ipa"
            }
            Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => {
                "barretenberg_ultra_honk_poseidon2_unmasked_no_ipa"
            }
        }
    }

    /// Parses an exact stable suite name without inheriting backend defaults.
    pub fn try_from_stable_name(value: &str) -> Result<Self, ZkError> {
        match value {
            "barretenberg_ultra_honk_keccak_zk_no_ipa" => {
                Ok(Self::BarretenbergUltraHonkKeccakZkNoIpa)
            }
            "barretenberg_ultra_honk_poseidon2_zk_no_ipa" => {
                Ok(Self::BarretenbergUltraHonkPoseidon2ZkNoIpa)
            }
            "barretenberg_ultra_honk_keccak_unmasked_no_ipa" => {
                Ok(Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa)
            }
            "barretenberg_ultra_honk_poseidon2_unmasked_no_ipa" => {
                Ok(Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa)
            }
            _ => Err(ZkError::new(
                crate::errors::ZkErrorReason::UnsupportedProofSuite,
            )),
        }
    }

    /// Transcript hash selected by this suite.
    #[must_use]
    pub const fn transcript_hash(self) -> ZkTranscriptHash {
        match self {
            Self::BarretenbergUltraHonkKeccakZkNoIpa
            | Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa => ZkTranscriptHash::Keccak,
            Self::BarretenbergUltraHonkPoseidon2ZkNoIpa
            | Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => ZkTranscriptHash::Poseidon2,
        }
    }

    /// Whether the proving flavor enables zero-knowledge masking.
    #[must_use]
    pub const fn zero_knowledge(self) -> bool {
        match self {
            Self::BarretenbergUltraHonkKeccakZkNoIpa
            | Self::BarretenbergUltraHonkPoseidon2ZkNoIpa => true,
            Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa
            | Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => false,
        }
    }

    /// Whether the proof carries an IPA accumulation claim.
    #[must_use]
    pub const fn ipa_accumulation(self) -> bool {
        match self {
            Self::BarretenbergUltraHonkKeccakZkNoIpa
            | Self::BarretenbergUltraHonkPoseidon2ZkNoIpa
            | Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa
            | Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => false,
        }
    }

    /// Confirms that the suite is approved for production use.
    pub const fn require_production(self) -> Result<(), ZkError> {
        match self {
            Self::BarretenbergUltraHonkKeccakZkNoIpa => Ok(()),
            Self::BarretenbergUltraHonkPoseidon2ZkNoIpa
            | Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa
            | Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => Err(ZkError::new(
                crate::errors::ZkErrorReason::UnsupportedProofSuite,
            )),
        }
    }

    /// Requires a suite that provides Barretenberg ZK witness masking.
    pub const fn require_zero_knowledge(self) -> Result<(), ZkError> {
        match self {
            Self::BarretenbergUltraHonkKeccakZkNoIpa
            | Self::BarretenbergUltraHonkPoseidon2ZkNoIpa => Ok(()),
            Self::BarretenbergUltraHonkKeccakUnmaskedNoIpa
            | Self::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => Err(ZkError::new(
                crate::errors::ZkErrorReason::UnsupportedProofSuite,
            )),
        }
    }
}

#[cfg(test)]
mod tests;
