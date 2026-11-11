// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common credential root v1 persona_mode registry.
//!
//! `ZkCircuitRef` remains the only exact source-circuit identity used by
//! artifact manifests and providers. This module only names the ordered proof
//! slots that compose those canonical circuit references.

use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
};

/// Number of cryptographic proofs in a complete common-credential-root v1 presentation.
pub const COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT: usize = 9;

/// SSI claim-commitment transcript used by the common-credential-root v1 circuits.
///
/// This encoding hashes raw bounded claim bytes with a four-byte big-endian
/// length and a SHA-256 claim-name digest. It is distinct from SSI's generic
/// JCS commitment transcript and must be declared on every issued envelope.
pub const COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING: &str = "RM-CV-ZK-COMMON-CREDENTIAL-ROOT-V1";

mod raw_public_inputs;

pub use raw_public_inputs::{
    ZkCommonCredentialRootRawPublicInputs, COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES,
};

/// Common-credential-root source stages owned by the canonical `common_credential_root_v1` family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootSourceStage {
    /// ReallyMe root attestation statement.
    RootAttestation,
    /// Exact-instance active status statement.
    RootStatus,
    /// Issuer-specific lineage commitment statement.
    Lineage,
    /// Signed credential validity and current private status statement.
    IssuerCredentialStatus,
    /// Private persona selected-claim statement.
    PrivatePersonaClaim,
    /// Public persona selected-claim statement.
    PublicPersonaClaim,
    /// Public presenting-persona session statement.
    PublicSession,
}

impl ZkCommonCredentialRootSourceStage {
    /// Every common-credential-root source stage required by the persona_mode.
    pub const ALL: &'static [Self] = &[
        Self::RootAttestation,
        Self::RootStatus,
        Self::Lineage,
        Self::IssuerCredentialStatus,
        Self::PrivatePersonaClaim,
        Self::PublicPersonaClaim,
        Self::PublicSession,
    ];

    /// Stable protocol string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootAttestation => "root_attestation",
            Self::RootStatus => "root_status",
            Self::Lineage => "lineage",
            Self::IssuerCredentialStatus => "issuer_credential_status",
            Self::PrivatePersonaClaim => "private_persona_claim",
            Self::PublicPersonaClaim => "public_persona_claim",
            Self::PublicSession => "public_session",
        }
    }

    /// Canonical circuit stage used by `ZkCircuitRef`.
    #[must_use]
    pub const fn circuit_stage(self) -> ZkCircuitStage {
        match self {
            Self::RootAttestation => ZkCircuitStage::RootAttestation,
            Self::RootStatus => ZkCircuitStage::RootStatus,
            Self::Lineage => ZkCircuitStage::Lineage,
            Self::IssuerCredentialStatus => ZkCircuitStage::IssuerCredentialStatus,
            Self::PrivatePersonaClaim => ZkCircuitStage::PrivatePersonaClaim,
            Self::PublicPersonaClaim => ZkCircuitStage::PublicPersonaClaim,
            Self::PublicSession => ZkCircuitStage::PublicSession,
        }
    }
}

impl core::fmt::Display for ZkCommonCredentialRootSourceStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Ordered proof slot in a complete common-credential-root v1 presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkCommonCredentialRootProofSlot {
    /// ReallyMe root attestation proof.
    RootAttestation,
    /// Active status proof for the exact attestation instance.
    RootStatus,
    /// First requested credential-role lineage proof.
    Lineage0,
    /// Second requested credential-role lineage proof.
    Lineage1,
    /// First requested selected-claim proof.
    SelectedClaim0,
    /// Second requested selected-claim proof.
    SelectedClaim1,
    /// Presenting persona session proof.
    Session,
    /// First issuer credential's signed validity and current status proof.
    IssuerCredentialStatus0,
    /// Second issuer credential's signed validity and current status proof.
    IssuerCredentialStatus1,
}

impl ZkCommonCredentialRootProofSlot {
    /// Complete proof-slot order consumed by join verification.
    pub const ALL: &'static [Self] = &[
        Self::RootAttestation,
        Self::RootStatus,
        Self::Lineage0,
        Self::Lineage1,
        Self::SelectedClaim0,
        Self::SelectedClaim1,
        Self::Session,
        Self::IssuerCredentialStatus0,
        Self::IssuerCredentialStatus1,
    ];

    /// Stable slot identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootAttestation => "root_attestation",
            Self::RootStatus => "root_status",
            Self::Lineage0 => "lineage_0",
            Self::Lineage1 => "lineage_1",
            Self::SelectedClaim0 => "selected_claim_0",
            Self::SelectedClaim1 => "selected_claim_1",
            Self::Session => "session",
            Self::IssuerCredentialStatus0 => "issuer_credential_status_0",
            Self::IssuerCredentialStatus1 => "issuer_credential_status_1",
        }
    }

    /// Stable zero-based slot index used by fixed adapter arrays.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::RootAttestation => 0,
            Self::RootStatus => 1,
            Self::Lineage0 => 2,
            Self::Lineage1 => 3,
            Self::SelectedClaim0 => 4,
            Self::SelectedClaim1 => 5,
            Self::Session => 6,
            Self::IssuerCredentialStatus0 => 7,
            Self::IssuerCredentialStatus1 => 8,
        }
    }
}

/// Persona mode for the complete common-credential-root v1 persona_mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZkCommonCredentialRootPersonaMode {
    /// Two private-persona selected claims plus a private persona session.
    PrivatePersona,
    /// Two public-persona selected claims plus a public persona session.
    PublicPersona,
}

impl ZkCommonCredentialRootPersonaMode {
    /// Every common-credential-root persona_mode exposed by platform providers.
    pub const ALL: &'static [Self] = &[Self::PrivatePersona, Self::PublicPersona];

    /// Stable persona_mode identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivatePersona => "common_credential_root_v1_private_persona",
            Self::PublicPersona => "common_credential_root_v1_public_persona",
        }
    }

    /// Exact source circuit for a proof slot in this persona_mode.
    #[must_use]
    pub const fn source_ref(
        self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        slot: ZkCommonCredentialRootProofSlot,
    ) -> ZkCircuitRef {
        match slot {
            ZkCommonCredentialRootProofSlot::RootAttestation => ZkCircuitRef::new(
                credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::RootAttestation,
            ),
            ZkCommonCredentialRootProofSlot::RootStatus => ZkCircuitRef::new(
                credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::RootStatus,
            ),
            ZkCommonCredentialRootProofSlot::Lineage0
            | ZkCommonCredentialRootProofSlot::Lineage1 => ZkCircuitRef::new(
                credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::Lineage,
            ),
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0
            | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => ZkCircuitRef::new(
                credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::IssuerCredentialStatus,
            ),
            ZkCommonCredentialRootProofSlot::SelectedClaim0
            | ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
                let stage = match self {
                    Self::PrivatePersona => ZkCircuitStage::PrivatePersonaClaim,
                    Self::PublicPersona => ZkCircuitStage::PublicPersonaClaim,
                };
                ZkCircuitRef::new(
                    credential_hash_algorithm,
                    ZkCircuitFamily::CommonCredentialRootV1,
                    stage,
                )
            }
            ZkCommonCredentialRootProofSlot::Session => {
                let (family, stage) = match self {
                    Self::PrivatePersona => (
                        ZkCircuitFamily::PrivatePersonaClaimV1,
                        ZkCircuitStage::Session,
                    ),
                    Self::PublicPersona => (
                        ZkCircuitFamily::CommonCredentialRootV1,
                        ZkCircuitStage::PublicSession,
                    ),
                };
                ZkCircuitRef::new(credential_hash_algorithm, family, stage)
            }
        }
    }

    /// Exact Nargo package for one proof slot.
    pub fn nargo_package_name(
        self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        slot: ZkCommonCredentialRootProofSlot,
    ) -> Result<&'static str, ZkError> {
        match (
            credential_hash_algorithm,
            self.source_ref(credential_hash_algorithm, slot),
        ) {
            (
                ZkCredentialHashAlgorithm::Sha256,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::RootAttestation,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_attestation_sha256"),
            (
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::RootAttestation,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_attestation_poseidon2"),
            (
                ZkCredentialHashAlgorithm::Sha256,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::RootStatus,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_status_sha256"),
            (
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::RootStatus,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_status_poseidon2"),
            (
                ZkCredentialHashAlgorithm::Sha256,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::Lineage,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_lineage_sha256"),
            (
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::Lineage,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_lineage_poseidon2"),
            (
                ZkCredentialHashAlgorithm::Sha256,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::IssuerCredentialStatus,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_issuer_credential_status_sha256"),
            (
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::IssuerCredentialStatus,
                    ..
                },
            ) => Ok("credential_common_credential_root_v1_issuer_credential_status_poseidon2"),
            (
                ZkCredentialHashAlgorithm::Sha256,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::PrivatePersonaClaim,
                    ..
                },
            ) => Ok("common_credential_root_v1_sha256_private_persona_claim"),
            (
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::PrivatePersonaClaim,
                    ..
                },
            ) => Ok("common_credential_root_v1_poseidon2_private_persona_claim"),
            (
                ZkCredentialHashAlgorithm::Sha256,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::PublicPersonaClaim,
                    ..
                },
            ) => Ok("common_credential_root_v1_sha256_public_persona_claim"),
            (
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::PublicPersonaClaim,
                    ..
                },
            ) => Ok("common_credential_root_v1_poseidon2_public_persona_claim"),
            (
                _,
                ZkCircuitRef {
                    family: ZkCircuitFamily::PrivatePersonaClaimV1,
                    stage: ZkCircuitStage::Session,
                    ..
                },
            ) => Ok("credential_private_persona_claim_v1_session"),
            (
                _,
                ZkCircuitRef {
                    family: ZkCircuitFamily::CommonCredentialRootV1,
                    stage: ZkCircuitStage::PublicSession,
                    ..
                },
            ) => match credential_hash_algorithm {
                ZkCredentialHashAlgorithm::Sha256 => {
                    Ok("credential_common_credential_root_v1_public_session_sha256")
                }
                ZkCredentialHashAlgorithm::Poseidon2 => {
                    Ok("credential_common_credential_root_v1_public_session_poseidon2")
                }
            },
            _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        }
    }
}

#[cfg(test)]
mod tests;
