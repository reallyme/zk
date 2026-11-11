// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    circuits::{
        ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProofSuite, ZkSessionBinding, ZkWitness},
};

mod prove_request;
pub use prove_request::{ZkClaimProofBundleProveRequest, ZkCompatibilitySuiteAcknowledgement};

/// Claim-bundle kind exposed by platform providers.
///
/// This is the stable bridge contract used by iOS, Kotlin/Android, WASM, and
/// services. It intentionally reflects the working mobile proof product rather
/// than every imported source circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkClaimProofBundleKind {
    /// Claim presented by its hidden credential subject; the selected claim is disclosed.
    CredentialSubjectClaimV1,
    /// Claim presented through a subject-authorized hidden persona; correlation remains possible.
    PrivatePersonaClaimV1,
}

impl ZkClaimProofBundleKind {
    /// Every production bundle_kind in stable provider order.
    pub const ALL: &'static [Self] = &[Self::CredentialSubjectClaimV1, Self::PrivatePersonaClaimV1];

    /// Stable bundle_kind identifier used in manifests and protobuf messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialSubjectClaimV1 => "credential_subject_claim_v1",
            Self::PrivatePersonaClaimV1 => "private_persona_claim_v1",
        }
    }

    /// Imported source family for this production bundle_kind.
    #[must_use]
    pub const fn family(self) -> ZkCircuitFamily {
        match self {
            Self::CredentialSubjectClaimV1 => ZkCircuitFamily::CredentialSubjectClaimV1,
            Self::PrivatePersonaClaimV1 => ZkCircuitFamily::PrivatePersonaClaimV1,
        }
    }

    /// Policy-level semantic circuit identifier for this bundle_kind.
    #[must_use]
    pub const fn circuit_id(self) -> ZkCircuitId {
        self.family().circuit_id()
    }

    /// Exact source circuit selected for a production provider stage.
    #[must_use]
    pub const fn source_ref(
        self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        stage: ZkClaimProofBundleStage,
    ) -> ZkCircuitRef {
        ZkCircuitRef::new(
            credential_hash_algorithm,
            self.family(),
            stage.source_stage(),
        )
    }

    /// Exact Nargo package name for one production stage.
    ///
    /// Release tooling uses this closed registry instead of parsing package
    /// names from TOML or reconstructing them with string formatting.
    #[must_use]
    pub const fn nargo_package_name(self, stage: ZkClaimProofBundleStage) -> &'static str {
        match (self, stage) {
            (Self::CredentialSubjectClaimV1, ZkClaimProofBundleStage::Session) => {
                "credential_credential_subject_claim_v1_session"
            }
            (Self::CredentialSubjectClaimV1, ZkClaimProofBundleStage::CredentialEnvelope) => {
                "credential_credential_subject_claim_v1_credential_envelope"
            }
            (Self::CredentialSubjectClaimV1, ZkClaimProofBundleStage::CredentialRoot) => {
                "credential_credential_subject_claim_v1_credential_root"
            }
            (Self::CredentialSubjectClaimV1, ZkClaimProofBundleStage::Claim) => {
                "credential_credential_subject_claim_v1_claim"
            }
            (Self::PrivatePersonaClaimV1, ZkClaimProofBundleStage::Session) => {
                "credential_private_persona_claim_v1_session"
            }
            (Self::PrivatePersonaClaimV1, ZkClaimProofBundleStage::CredentialEnvelope) => {
                "credential_private_persona_claim_v1_credential_envelope"
            }
            (Self::PrivatePersonaClaimV1, ZkClaimProofBundleStage::CredentialRoot) => {
                "credential_private_persona_claim_v1_credential_root"
            }
            (Self::PrivatePersonaClaimV1, ZkClaimProofBundleStage::Claim) => {
                "credential_private_persona_claim_v1_claim"
            }
        }
    }
}

impl core::fmt::Display for ZkClaimProofBundleKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Production stage emitted by the bridge proof bundle.
///
/// The current audited provider contract is the iOS-shaped four-stage flow.
/// `claim_bundle_4` remains an imported experimental source stage until every
/// production provider can emit and verify it through this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkClaimProofBundleStage {
    /// Session challenge and holder authorization stage.
    Session,
    /// Credential-envelope commitment stage without standalone authenticity.
    CredentialEnvelope,
    /// Credential root/commitment binding stage.
    CredentialRoot,
    /// Single-claim proof stage.
    Claim,
}

impl ZkClaimProofBundleStage {
    /// Every required production stage in stable bundle order.
    pub const ALL: &'static [Self] = &[
        Self::Session,
        Self::CredentialEnvelope,
        Self::CredentialRoot,
        Self::Claim,
    ];

    const REQUIRED_MASK: u8 = 0b0000_1111;

    /// Stable stage identifier used in manifests and protobuf messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::CredentialEnvelope => "credential_envelope",
            Self::CredentialRoot => "credential_root",
            Self::Claim => "claim",
        }
    }

    /// Imported source stage for this production stage.
    #[must_use]
    pub const fn source_stage(self) -> ZkCircuitStage {
        match self {
            Self::Session => ZkCircuitStage::Session,
            Self::CredentialEnvelope => ZkCircuitStage::CredentialEnvelope,
            Self::CredentialRoot => ZkCircuitStage::CredentialRoot,
            Self::Claim => ZkCircuitStage::Claim,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Session => 0b0000_0001,
            Self::CredentialEnvelope => 0b0000_0010,
            Self::CredentialRoot => 0b0000_0100,
            Self::Claim => 0b0000_1000,
        }
    }

    /// Stable zero-based stage index used by fixed-size adapter tables.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Session => 0,
            Self::CredentialEnvelope => 1,
            Self::CredentialRoot => 2,
            Self::Claim => 3,
        }
    }
}

impl core::fmt::Display for ZkClaimProofBundleStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One stage proof inside a production bridge proof bundle.
#[derive(Debug, PartialEq, Eq)]
pub struct ZkClaimProofBundleStageProof {
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    proof: ZkProof,
}

impl ZkClaimProofBundleStageProof {
    /// Validates the proof identity and stores one production stage proof.
    pub fn try_from_parts(
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        proof: ZkProof,
    ) -> Result<Self, ZkError> {
        if proof.circuit_id() != bundle_kind.circuit_id() {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }

        let circuit_ref = proof.circuit_ref();
        if circuit_ref.family != bundle_kind.family() || circuit_ref.stage != stage.source_stage() {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }

        Ok(Self {
            bundle_kind,
            stage,
            proof,
        })
    }

    /// Production bundle_kind for this stage.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Stage represented by this proof.
    #[must_use]
    pub const fn stage(&self) -> ZkClaimProofBundleStage {
        self.stage
    }

    /// Underlying proof bytes and public inputs.
    #[must_use]
    pub const fn proof(&self) -> &ZkProof {
        &self.proof
    }

    /// Consumes this wrapper and returns the underlying proof.
    #[must_use]
    pub fn into_proof(self) -> ZkProof {
        self.proof
    }
}

/// Production bridge proof bundle emitted by a platform provider.
#[derive(Debug, PartialEq, Eq)]
pub struct ZkClaimProofBundle {
    bundle_kind: ZkClaimProofBundleKind,
    proof_suite: ZkProofSuite,
    session_binding: ZkSessionBinding,
    stage_proofs: Vec<ZkClaimProofBundleStageProof>,
}

impl ZkClaimProofBundle {
    /// Validates and stores a complete production proof bundle.
    pub fn try_from_stage_proofs(
        bundle_kind: ZkClaimProofBundleKind,
        session_binding: ZkSessionBinding,
        stage_proofs: Vec<ZkClaimProofBundleStageProof>,
    ) -> Result<Self, ZkError> {
        if stage_proofs.len() < ZkClaimProofBundleStage::ALL.len() {
            return Err(ZkError::new(ZkErrorReason::MissingStage));
        }
        if stage_proofs.len() > ZkClaimProofBundleStage::ALL.len() {
            return Err(ZkError::new(ZkErrorReason::DuplicateStage));
        }

        let mut seen = 0_u8;
        let mut expiry_unix = None;
        let mut proof_suite = None;
        let mut session_commitment = None;
        let mut envelope_commitment = None;
        let mut credential_commitment = None;
        let mut credential_hash_algorithm = None;
        for stage_proof in &stage_proofs {
            if stage_proof.bundle_kind() != bundle_kind {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            let stage_suite = stage_proof.proof().proof_suite();
            if let Some(existing_suite) = proof_suite {
                if existing_suite != stage_suite {
                    return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
                }
            } else {
                proof_suite = Some(stage_suite);
            }

            let bit = stage_proof.stage().bit();
            if seen & bit != 0 {
                return Err(ZkError::new(ZkErrorReason::DuplicateStage));
            }
            seen |= bit;

            let circuit_ref = stage_proof.proof().circuit_ref();
            if let Some(existing_credential_hash_algorithm) = credential_hash_algorithm {
                if existing_credential_hash_algorithm != circuit_ref.credential_hash_algorithm {
                    return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
                }
            } else {
                credential_hash_algorithm = Some(circuit_ref.credential_hash_algorithm);
            }
            let decoded = session_binding
                .decode_and_validate(circuit_ref, stage_proof.proof().public_inputs())?;
            require_consistent(&mut expiry_unix, decoded.expiry_unix())?;
            require_optional_consistent(&mut session_commitment, decoded.session_binding())?;
            require_optional_consistent(&mut envelope_commitment, decoded.envelope_binding())?;
            require_optional_consistent(&mut credential_commitment, decoded.credential_binding())?;
        }

        if seen != ZkClaimProofBundleStage::REQUIRED_MASK {
            return Err(ZkError::new(ZkErrorReason::MissingStage));
        }
        require_canonical_stage_order(stage_proofs.as_slice())?;

        let proof_suite = proof_suite.ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        let bundle = Self {
            bundle_kind,
            proof_suite,
            session_binding,
            stage_proofs,
        };
        // Bundle construction is the earliest point at which every stage is
        // available. Enforce statement consistency here so no caller can hold
        // a structurally complete but semantically split bundle.
        let _statement = bundle.decode_claimed_statement()?;
        Ok(bundle)
    }

    /// Production bundle_kind proven by this bundle.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Exact suite shared by every stage proof.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Binding expected across all stage public inputs.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }

    /// Stage proofs in canonical production order.
    #[must_use]
    pub fn stage_proofs(&self) -> &[ZkClaimProofBundleStageProof] {
        self.stage_proofs.as_slice()
    }

    /// Consumes this wrapper and returns the owned stage proofs.
    #[must_use]
    pub fn into_stage_proofs(self) -> Vec<ZkClaimProofBundleStageProof> {
        self.stage_proofs
    }
}

fn require_canonical_stage_order(
    stage_proofs: &[ZkClaimProofBundleStageProof],
) -> Result<(), ZkError> {
    for (expected_stage, stage_proof) in ZkClaimProofBundleStage::ALL.iter().zip(stage_proofs) {
        if stage_proof.stage() != *expected_stage {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
    }
    Ok(())
}

fn require_consistent<T: Copy + Eq>(slot: &mut Option<T>, value: T) -> Result<(), ZkError> {
    if let Some(existing) = slot {
        if *existing != value {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
    } else {
        *slot = Some(value);
    }
    Ok(())
}

fn require_optional_consistent<T: Copy + Eq>(
    slot: &mut Option<T>,
    value: Option<T>,
) -> Result<(), ZkError> {
    if let Some(value) = value {
        require_consistent(slot, value)?;
    }
    Ok(())
}

/// Ordered serialized witness stacks for one production proof bundle.
///
/// Witness generation remains provider-internal and is implemented by the
/// typed witness-input layer. This owner prevents one serialized stack from
/// being reused across circuit ABIs by binding every stack to its exact source
/// circuit and requiring complete production-stage order.
pub struct ZkClaimProofBundleWitness {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage_witnesses: Vec<ZkWitness>,
}

impl ZkClaimProofBundleWitness {
    /// Validates a complete ordered set of exact stage witnesses.
    pub fn try_from_stage_witnesses(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        stage_witnesses: Vec<ZkWitness>,
    ) -> Result<Self, ZkError> {
        if stage_witnesses.len() < ZkClaimProofBundleStage::ALL.len() {
            return Err(ZkError::new(ZkErrorReason::MissingStage));
        }
        if stage_witnesses.len() > ZkClaimProofBundleStage::ALL.len() {
            return Err(ZkError::new(ZkErrorReason::DuplicateStage));
        }
        for (stage, witness) in ZkClaimProofBundleStage::ALL.iter().zip(&stage_witnesses) {
            if witness.circuit_ref() != bundle_kind.source_ref(credential_hash_algorithm, *stage) {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
        }
        Ok(Self {
            bundle_kind,
            credential_hash_algorithm,
            stage_witnesses,
        })
    }

    /// Production bundle_kind shared by every exact stage witness.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Hash lane shared by every exact stage witness.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Returns the witness stack for one exact production stage.
    pub fn stage_witness(&self, stage: ZkClaimProofBundleStage) -> Result<&ZkWitness, ZkError> {
        let index = usize::from(stage.index());
        let witness = self
            .stage_witnesses
            .get(index)
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        if witness.circuit_ref()
            != self
                .bundle_kind
                .source_ref(self.credential_hash_algorithm, stage)
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Ok(witness)
    }

    /// Exact stage witnesses in canonical production order.
    #[must_use]
    pub fn stage_witnesses(&self) -> &[ZkWitness] {
        self.stage_witnesses.as_slice()
    }

    /// Consumes the bundle without copying secret witness stacks.
    #[must_use]
    pub fn into_stage_witnesses(self) -> Vec<ZkWitness> {
        self.stage_witnesses
    }
}

#[cfg(test)]
mod tests;
