// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Canonical ZK circuit identifiers supported by ReallyMe.
///
/// These identifiers are stable protocol values and appear in proof formats,
/// artifact manifests, policy decisions, and test vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkCircuitId {
    /// A selected claim presented by its hidden credential subject.
    CredentialSubjectClaimV1,
    /// A selected claim presented through a hidden private persona.
    PrivatePersonaClaimV1,
    /// Common-credential-root multi-credential composition circuit family.
    CommonCredentialRootV1,
    /// Issuer-authenticated persona evidence and current-status proofs.
    PersonaCredentialEvidenceV1,
}

impl ZkCircuitId {
    /// Returns every registered circuit in stable order.
    pub const ALL: &'static [Self] = &[
        Self::CredentialSubjectClaimV1,
        Self::PrivatePersonaClaimV1,
        Self::CommonCredentialRootV1,
        Self::PersonaCredentialEvidenceV1,
    ];

    /// Canonical string identifier as it appears in proofs and manifests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialSubjectClaimV1 => "rm-zk-credential-subject-claim-v1",
            Self::PrivatePersonaClaimV1 => "rm-zk-private-persona-claim-v1",
            Self::CommonCredentialRootV1 => "rm-zk-common-credential-root-v1",
            Self::PersonaCredentialEvidenceV1 => "rm-zk-persona-credential-evidence-v1",
        }
    }
}

/// Hash strategy used by a concrete Noir circuit lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkCredentialHashAlgorithm {
    /// SHA-256 based credential commitments.
    Sha256,
    /// Poseidon2 based credential commitments.
    Poseidon2,
}

impl ZkCredentialHashAlgorithm {
    /// Every imported credential hash algorithm in stable manifest order.
    pub const ALL: &'static [Self] = &[Self::Sha256, Self::Poseidon2];

    /// Stable protocol string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Poseidon2 => "poseidon2",
        }
    }

    /// Directory name under `circuits/`.
    #[must_use]
    pub const fn source_dir(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Poseidon2 => "poseidon2",
        }
    }
}

impl core::fmt::Display for ZkCredentialHashAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// VC circuit family owned by this repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkCircuitFamily {
    /// Selected claim presented by the credential's hidden subject.
    CredentialSubjectClaimV1,
    /// Selected claim bound to a hidden private persona.
    PrivatePersonaClaimV1,
    /// Nine-proof common-credential-root composition family.
    CommonCredentialRootV1,
    /// Six source stages, with five proofs in each public or private persona mode.
    PersonaCredentialEvidenceV1,
}

impl ZkCircuitFamily {
    /// Every imported VC family in stable manifest order.
    pub const ALL: &'static [Self] = &[
        Self::CredentialSubjectClaimV1,
        Self::PrivatePersonaClaimV1,
        Self::CommonCredentialRootV1,
        Self::PersonaCredentialEvidenceV1,
    ];

    /// Stable protocol string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialSubjectClaimV1 => "credential_subject_claim_v1",
            Self::PrivatePersonaClaimV1 => "private_persona_claim_v1",
            Self::CommonCredentialRootV1 => "common_credential_root_v1",
            Self::PersonaCredentialEvidenceV1 => "persona_credential_evidence_v1",
        }
    }

    /// Directory name under `circuits/{hash}/families/`.
    #[must_use]
    pub const fn source_dir(self) -> &'static str {
        self.as_str()
    }

    /// Policy-level semantic circuit identifier for this family.
    #[must_use]
    pub const fn circuit_id(self) -> ZkCircuitId {
        match self {
            Self::CredentialSubjectClaimV1 => ZkCircuitId::CredentialSubjectClaimV1,
            Self::PrivatePersonaClaimV1 => ZkCircuitId::PrivatePersonaClaimV1,
            Self::CommonCredentialRootV1 => ZkCircuitId::CommonCredentialRootV1,
            Self::PersonaCredentialEvidenceV1 => ZkCircuitId::PersonaCredentialEvidenceV1,
        }
    }
}

impl core::fmt::Display for ZkCircuitFamily {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stage within a VC family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkCircuitStage {
    /// Session challenge and audience binding stage.
    Session,
    /// Credential-envelope commitment stage.
    ///
    /// This stage alone does not establish credential authenticity; that
    /// guarantee belongs to complete production-bundle verification.
    CredentialEnvelope,
    /// Credential root or commitment membership stage.
    CredentialRoot,
    /// Single-claim proof stage.
    Claim,
    /// Bounded four-claim bundle stage.
    ClaimBundle4,
    /// Common-credential-root root attestation stage.
    RootAttestation,
    /// Common-credential-root active status stage.
    RootStatus,
    /// Common-credential-root lineage stage.
    Lineage,
    /// Issuer-signed credential validity and current hidden status stage.
    IssuerCredentialStatus,
    /// Common-credential-root private-persona selected-claim stage.
    PrivatePersonaClaim,
    /// Common-credential-root public-persona selected-claim stage.
    PublicPersonaClaim,
    /// Common-credential-root public presenting-persona session stage.
    PublicSession,
    /// Prepared issuer-signed envelope and hidden-subject stage.
    EvidenceIssuerEnvelope,
    /// Prepared issuer-signed envelope-to-claim-root stage.
    EvidenceClaimRoot,
    /// Prepared issuer-signed credential-validity stage.
    EvidenceSignedValidity,
    /// Prepared public-persona selected-claim stage.
    EvidencePublicClaim,
    /// Prepared private-persona selected-claim stage.
    EvidencePrivateClaim,
    /// Prepared hidden-credential validity and current-status stage.
    EvidenceCurrentState,
}

impl ZkCircuitStage {
    /// Every imported stage in stable manifest order.
    pub const ALL: &'static [Self] = &[
        Self::Session,
        Self::CredentialEnvelope,
        Self::CredentialRoot,
        Self::Claim,
        Self::ClaimBundle4,
        Self::RootAttestation,
        Self::RootStatus,
        Self::Lineage,
        Self::IssuerCredentialStatus,
        Self::PrivatePersonaClaim,
        Self::PublicPersonaClaim,
        Self::PublicSession,
        Self::EvidenceIssuerEnvelope,
        Self::EvidenceClaimRoot,
        Self::EvidenceSignedValidity,
        Self::EvidencePublicClaim,
        Self::EvidencePrivateClaim,
        Self::EvidenceCurrentState,
    ];

    /// Stable protocol string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::CredentialEnvelope => "credential_envelope",
            Self::CredentialRoot => "credential_root",
            Self::Claim => "claim",
            Self::ClaimBundle4 => "claim_bundle_4",
            Self::RootAttestation => "root_attestation",
            Self::RootStatus => "root_status",
            Self::Lineage => "lineage",
            Self::IssuerCredentialStatus => "issuer_credential_status",
            Self::PrivatePersonaClaim => "private_persona_claim",
            Self::PublicPersonaClaim => "public_persona_claim",
            Self::PublicSession => "public_session",
            Self::EvidenceIssuerEnvelope => "issuer_envelope",
            Self::EvidenceClaimRoot => "claim_root",
            Self::EvidenceSignedValidity => "signed_validity",
            Self::EvidencePublicClaim => "public_claim",
            Self::EvidencePrivateClaim => "private_claim",
            Self::EvidenceCurrentState => "current_state",
        }
    }

    /// Directory name under `circuits/{hash}/families/{family}/`.
    #[must_use]
    pub const fn source_dir(self) -> &'static str {
        self.as_str()
    }
}

impl core::fmt::Display for ZkCircuitStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exact source circuit selected for artifacts, vectors, and providers.
///
/// `ZkCircuitId` remains the semantic registry key used by identity policy and
/// OpenID4VP. `ZkCircuitRef` names the concrete imported Noir program whose
/// bytecode, verification key, vectors, and manifest must be versioned together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkCircuitRef {
    /// Hash lane used by this circuit.
    pub credential_hash_algorithm: ZkCredentialHashAlgorithm,
    /// VC family.
    pub family: ZkCircuitFamily,
    /// Stage within the family.
    pub stage: ZkCircuitStage,
    /// Monotonic semantic circuit version.
    pub revision: u32,
}

impl ZkCircuitRef {
    /// Current source version for repository-owned circuits.
    pub const CURRENT_REVISION: u32 = 1;
    /// Every imported source circuit currently present under `circuits/`.
    pub const ALL: &'static [Self] = crate::circuit_registry::CIRCUIT_REFS;

    /// Builds a reference to the current version of an imported circuit.
    #[must_use]
    pub const fn new(
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        family: ZkCircuitFamily,
        stage: ZkCircuitStage,
    ) -> Self {
        Self {
            credential_hash_algorithm,
            family,
            stage,
            revision: Self::CURRENT_REVISION,
        }
    }

    /// Policy-level semantic circuit identifier for this exact source circuit.
    #[must_use]
    pub const fn circuit_id(self) -> ZkCircuitId {
        self.family.circuit_id()
    }

    /// Parses the canonical release-tool coordinate
    /// `{hash}:{family}:{stage}:v1`.
    pub fn try_from_stable_name(value: &str) -> Result<Self, crate::errors::ZkError> {
        let mut components = value.split(':');
        let credential_hash_algorithm = match components.next() {
            Some("sha256") => ZkCredentialHashAlgorithm::Sha256,
            Some("poseidon2") => ZkCredentialHashAlgorithm::Poseidon2,
            _ => {
                return Err(crate::errors::ZkError::new(
                    crate::errors::ZkErrorReason::UnsupportedCircuit,
                ))
            }
        };
        let family = match components.next() {
            Some("credential_subject_claim_v1") => ZkCircuitFamily::CredentialSubjectClaimV1,
            Some("private_persona_claim_v1") => ZkCircuitFamily::PrivatePersonaClaimV1,
            Some("common_credential_root_v1") => ZkCircuitFamily::CommonCredentialRootV1,
            Some("persona_credential_evidence_v1") => ZkCircuitFamily::PersonaCredentialEvidenceV1,
            _ => {
                return Err(crate::errors::ZkError::new(
                    crate::errors::ZkErrorReason::UnsupportedCircuit,
                ))
            }
        };
        let stage = match components.next() {
            Some("session") => ZkCircuitStage::Session,
            Some("credential_envelope") => ZkCircuitStage::CredentialEnvelope,
            Some("credential_root") => ZkCircuitStage::CredentialRoot,
            Some("claim") => ZkCircuitStage::Claim,
            Some("claim_bundle_4") => ZkCircuitStage::ClaimBundle4,
            Some("root_attestation") => ZkCircuitStage::RootAttestation,
            Some("root_status") => ZkCircuitStage::RootStatus,
            Some("lineage") => ZkCircuitStage::Lineage,
            Some("issuer_credential_status") => ZkCircuitStage::IssuerCredentialStatus,
            Some("private_persona_claim") => ZkCircuitStage::PrivatePersonaClaim,
            Some("public_persona_claim") => ZkCircuitStage::PublicPersonaClaim,
            Some("public_session") => ZkCircuitStage::PublicSession,
            Some("issuer_envelope") => ZkCircuitStage::EvidenceIssuerEnvelope,
            Some("claim_root") => ZkCircuitStage::EvidenceClaimRoot,
            Some("signed_validity") => ZkCircuitStage::EvidenceSignedValidity,
            Some("public_claim") => ZkCircuitStage::EvidencePublicClaim,
            Some("private_claim") => ZkCircuitStage::EvidencePrivateClaim,
            Some("current_state") => ZkCircuitStage::EvidenceCurrentState,
            _ => {
                return Err(crate::errors::ZkError::new(
                    crate::errors::ZkErrorReason::UnsupportedCircuit,
                ))
            }
        };
        if components.next() != Some("v1") || components.next().is_some() {
            return Err(crate::errors::ZkError::new(
                crate::errors::ZkErrorReason::UnsupportedCircuit,
            ));
        }
        let circuit_ref = Self::new(credential_hash_algorithm, family, stage);
        if Self::ALL.contains(&circuit_ref) {
            Ok(circuit_ref)
        } else {
            Err(crate::errors::ZkError::new(
                crate::errors::ZkErrorReason::UnsupportedCircuit,
            ))
        }
    }
}

impl core::fmt::Display for ZkCircuitId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown circuit identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseZkCircuitIdError;

impl core::fmt::Display for ParseZkCircuitIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unknown zk circuit identifier")
    }
}

impl core::error::Error for ParseZkCircuitIdError {}

impl core::str::FromStr for ZkCircuitId {
    type Err = ParseZkCircuitIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "rm-zk-credential-subject-claim-v1" => Ok(Self::CredentialSubjectClaimV1),
            "rm-zk-private-persona-claim-v1" => Ok(Self::PrivatePersonaClaimV1),
            "rm-zk-common-credential-root-v1" => Ok(Self::CommonCredentialRootV1),
            "rm-zk-persona-credential-evidence-v1" => Ok(Self::PersonaCredentialEvidenceV1),
            _ => Err(ParseZkCircuitIdError),
        }
    }
}

#[cfg(test)]
mod tests;
