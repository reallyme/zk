// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conversions from generated protobuf messages into audited domain types.
//!
//! These helpers keep transport defaults, open enum values, and optional
//! protobuf messages from leaking into provider code as unchecked assumptions.

use buffa::EnumValue;
use reallyme_zk_api::{
    capabilities::{
        circuit_ref_capabilities, PersonaBinding, SubjectBinding, ZkDisclosureMode,
        ZkPredicateType, ZkSemanticGuarantee,
    },
    circuits::{
        ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
    },
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

/// Composition-envelope version, independent of each circuit revision.
pub(crate) const CLAIM_PROOF_BUNDLE_FORMAT_VERSION: u32 = 1;

pub(crate) fn bundle_kind_from_family(
    family: ZkCircuitFamily,
) -> Result<ZkClaimProofBundleKind, ZkError> {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => {
            Ok(ZkClaimProofBundleKind::CredentialSubjectClaimV1)
        }
        ZkCircuitFamily::PrivatePersonaClaimV1 => Ok(ZkClaimProofBundleKind::PrivatePersonaClaimV1),
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

pub(crate) fn bundle_kind_from_proto(
    bundle_kind: EnumValue<pb::ZkClaimProofBundleKind>,
) -> Result<ZkClaimProofBundleKind, ZkError> {
    match bundle_kind.as_known() {
        Some(
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ) => Ok(ZkClaimProofBundleKind::CredentialSubjectClaimV1),
        Some(pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1) => {
            Ok(ZkClaimProofBundleKind::PrivatePersonaClaimV1)
        }
        Some(pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

pub(crate) fn digest_from_proto_message(
    mut digest: buffa::MessageField<pb::Digest, impl buffa::ProtoBox<pb::Digest>>,
) -> Result<Digest32, ZkError> {
    digest_from_proto(
        digest
            .take()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?,
    )
}

fn digest_from_proto(digest: pb::Digest) -> Result<Digest32, ZkError> {
    let bytes: [u8; 32] = digest
        .value
        .as_slice()
        .try_into()
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    Ok(Digest32::from_bytes(bytes))
}

pub(crate) fn digest_vec_from_proto(digests: Vec<pb::Digest>) -> Result<Vec<Digest32>, ZkError> {
    if digests.is_empty() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    let mut converted = Vec::new();
    converted
        .try_reserve_exact(digests.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for digest in digests {
        converted.push(digest_from_proto(digest)?);
    }
    Ok(converted)
}

pub(crate) fn circuit_ref_from_proto_message(
    mut circuit_ref: buffa::MessageField<pb::ZkCircuitRef, impl buffa::ProtoBox<pb::ZkCircuitRef>>,
) -> Result<ZkCircuitRef, ZkError> {
    let circuit_ref = circuit_ref
        .take()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    if circuit_ref.circuit_revision != ZkCircuitRef::CURRENT_REVISION {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }

    let circuit_ref = ZkCircuitRef::new(
        credential_hash_algorithm_from_proto(circuit_ref.credential_hash_algorithm)?,
        circuit_family_from_proto(circuit_ref.family)?,
        circuit_stage_from_proto(circuit_ref.stage)?,
    );
    if !ZkCircuitRef::ALL.contains(&circuit_ref) {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    Ok(circuit_ref)
}

pub(crate) fn circuit_id_from_proto(
    id: EnumValue<pb::ZkCircuitId>,
) -> Result<ZkCircuitId, ZkError> {
    match id.as_known() {
        Some(pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1) => {
            Ok(ZkCircuitId::CredentialSubjectClaimV1)
        }
        Some(pb::ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1) => {
            Ok(ZkCircuitId::PrivatePersonaClaimV1)
        }
        Some(pb::ZkCircuitId::ZK_CIRCUIT_ID_COMMON_CREDENTIAL_ROOT_V1) => {
            Ok(ZkCircuitId::CommonCredentialRootV1)
        }
        Some(pb::ZkCircuitId::ZK_CIRCUIT_ID_PERSONA_CREDENTIAL_EVIDENCE_V1) => {
            Ok(ZkCircuitId::PersonaCredentialEvidenceV1)
        }
        Some(pb::ZkCircuitId::ZK_CIRCUIT_ID_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::UnknownCircuit))
        }
    }
}

pub(crate) fn credential_hash_algorithm_from_proto(
    credential_hash_algorithm: EnumValue<pb::ZkCredentialHashAlgorithm>,
) -> Result<ZkCredentialHashAlgorithm, ZkError> {
    match credential_hash_algorithm.as_known() {
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256) => {
            Ok(ZkCredentialHashAlgorithm::Sha256)
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2) => {
            Ok(ZkCredentialHashAlgorithm::Poseidon2)
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

fn circuit_family_from_proto(
    family: EnumValue<pb::ZkCircuitFamily>,
) -> Result<ZkCircuitFamily, ZkError> {
    match family.as_known() {
        Some(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1) => {
            Ok(ZkCircuitFamily::CredentialSubjectClaimV1)
        }
        Some(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1) => {
            Ok(ZkCircuitFamily::PrivatePersonaClaimV1)
        }
        Some(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1) => {
            Ok(ZkCircuitFamily::CommonCredentialRootV1)
        }
        Some(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1) => {
            Ok(ZkCircuitFamily::PersonaCredentialEvidenceV1)
        }
        Some(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::UnknownCircuit))
        }
    }
}

fn circuit_stage_from_proto(
    stage: EnumValue<pb::ZkCircuitStage>,
) -> Result<ZkCircuitStage, ZkError> {
    match stage.as_known() {
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION) => Ok(ZkCircuitStage::Session),
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE) => {
            Ok(ZkCircuitStage::CredentialEnvelope)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT) => {
            Ok(ZkCircuitStage::CredentialRoot)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM) => Ok(ZkCircuitStage::Claim),
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4) => {
            Ok(ZkCircuitStage::ClaimBundle4)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ROOT_ATTESTATION) => {
            Ok(ZkCircuitStage::RootAttestation)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ROOT_STATUS) => Ok(ZkCircuitStage::RootStatus),
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_LINEAGE) => Ok(ZkCircuitStage::Lineage),
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS) => {
            Ok(ZkCircuitStage::IssuerCredentialStatus)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_PRIVATE_PERSONA_CLAIM) => {
            Ok(ZkCircuitStage::PrivatePersonaClaim)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_PERSONA_CLAIM) => {
            Ok(ZkCircuitStage::PublicPersonaClaim)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_SESSION) => {
            Ok(ZkCircuitStage::PublicSession)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM) => {
            Ok(ZkCircuitStage::EvidencePublicClaim)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM) => {
            Ok(ZkCircuitStage::EvidencePrivateClaim)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE) => {
            Ok(ZkCircuitStage::EvidenceCurrentState)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE) => {
            Ok(ZkCircuitStage::EvidenceIssuerEnvelope)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT) => {
            Ok(ZkCircuitStage::EvidenceClaimRoot)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY) => {
            Ok(ZkCircuitStage::EvidenceSignedValidity)
        }
        Some(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

pub(crate) fn production_stage_from_circuit_stage(
    stage: ZkCircuitStage,
) -> Result<ZkClaimProofBundleStage, ZkError> {
    match stage {
        ZkCircuitStage::Session => Ok(ZkClaimProofBundleStage::Session),
        ZkCircuitStage::CredentialEnvelope => Ok(ZkClaimProofBundleStage::CredentialEnvelope),
        ZkCircuitStage::CredentialRoot => Ok(ZkClaimProofBundleStage::CredentialRoot),
        ZkCircuitStage::Claim => Ok(ZkClaimProofBundleStage::Claim),
        ZkCircuitStage::ClaimBundle4 => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

pub(crate) fn production_stage_from_proto(
    stage: EnumValue<pb::ZkClaimProofBundleStage>,
) -> Result<ZkClaimProofBundleStage, ZkError> {
    match stage.as_known() {
        Some(pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION) => {
            Ok(ZkClaimProofBundleStage::Session)
        }
        Some(pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE) => {
            Ok(ZkClaimProofBundleStage::CredentialEnvelope)
        }
        Some(pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT) => {
            Ok(ZkClaimProofBundleStage::CredentialRoot)
        }
        Some(pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM) => {
            Ok(ZkClaimProofBundleStage::Claim)
        }
        Some(pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        }
    }
}

pub(crate) fn proof_suite_from_proto(
    proof_suite: EnumValue<pb::ZkProofSuite>,
) -> Result<ZkProofSuite, ZkError> {
    match proof_suite.as_known() {
        Some(pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA) => {
            Ok(ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa)
        }
        Some(pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA) => {
            Ok(ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa)
        }
        Some(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA,
        ) => Ok(ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa),
        Some(pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_UNMASKED_NO_IPA) => {
            Ok(ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa)
        }
        Some(pb::ZkProofSuite::ZK_PROOF_SUITE_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite))
        }
    }
}

pub(crate) fn capabilities_from_proto(
    capabilities: pb::ZkCircuitCapabilities,
    circuit_ref: ZkCircuitRef,
) -> Result<reallyme_zk_api::capabilities::ZkCircuitCapabilities, ZkError> {
    let expected = circuit_ref_capabilities(circuit_ref)?;
    if subject_binding_from_proto(capabilities.subject_binding)? != expected.subject_binding
        || persona_binding_from_proto(capabilities.persona_binding)? != expected.persona_binding
        || capabilities.may_be_correlated != expected.may_be_correlated
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    // Capability metadata is untrusted. Compare bounded sequences in place so
    // rejecting an overclaim never allocates another attacker-sized vector.
    if capabilities.disclosure_modes.len() != expected.disclosure_modes.len()
        || capabilities.predicate_types.len() != expected.predicate_types.len()
        || capabilities.semantic_guarantees.len() != expected.semantic_guarantees.len()
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    for (actual, expected) in capabilities
        .disclosure_modes
        .iter()
        .zip(expected.disclosure_modes)
    {
        if disclosure_mode_from_proto(*actual)? != *expected {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    }
    for (actual, expected) in capabilities
        .predicate_types
        .iter()
        .zip(expected.predicate_types)
    {
        if predicate_type_from_proto(*actual)? != *expected {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    }
    for (actual, expected) in capabilities
        .semantic_guarantees
        .iter()
        .zip(expected.semantic_guarantees)
    {
        if semantic_guarantee_from_proto(*actual)? != *expected {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    }

    Ok(expected)
}

fn subject_binding_from_proto(
    subject_binding: EnumValue<pb::ZkSubjectBinding>,
) -> Result<SubjectBinding, ZkError> {
    match subject_binding.as_known() {
        Some(pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_REQUIRED) => Ok(SubjectBinding::Required),
        Some(pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_FORBIDDEN) => Ok(SubjectBinding::Forbidden),
        Some(pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_OPTIONAL) => Ok(SubjectBinding::Optional),
        Some(pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

fn persona_binding_from_proto(
    persona_binding: EnumValue<pb::ZkPersonaBinding>,
) -> Result<PersonaBinding, ZkError> {
    match persona_binding.as_known() {
        Some(pb::ZkPersonaBinding::ZK_PERSONA_BINDING_REQUIRED) => Ok(PersonaBinding::Required),
        Some(pb::ZkPersonaBinding::ZK_PERSONA_BINDING_FORBIDDEN) => Ok(PersonaBinding::Forbidden),
        Some(pb::ZkPersonaBinding::ZK_PERSONA_BINDING_OPTIONAL) => Ok(PersonaBinding::Optional),
        Some(pb::ZkPersonaBinding::ZK_PERSONA_BINDING_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

fn disclosure_mode_from_proto(
    disclosure_mode: EnumValue<pb::ZkDisclosureMode>,
) -> Result<ZkDisclosureMode, ZkError> {
    match disclosure_mode.as_known() {
        Some(pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_HIDDEN) => Ok(ZkDisclosureMode::Hidden),
        Some(pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_REVEAL) => Ok(ZkDisclosureMode::Reveal),
        Some(pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

fn semantic_guarantee_from_proto(
    guarantee: EnumValue<pb::ZkSemanticGuarantee>,
) -> Result<ZkSemanticGuarantee, ZkError> {
    match guarantee.as_known() {
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_SESSION_BOUND) => {
            Ok(ZkSemanticGuarantee::SessionBound)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_AUDIENCE_BOUND) => {
            Ok(ZkSemanticGuarantee::AudienceBound)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_TRANSACTION_DATA_BOUND) => {
            Ok(ZkSemanticGuarantee::TransactionDataBound)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CREDENTIAL_AUTHENTICITY) => {
            Ok(ZkSemanticGuarantee::CredentialAuthenticity)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CLAIM_INTEGRITY) => {
            Ok(ZkSemanticGuarantee::ClaimIntegrity)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_LINKABLE_PERSONA_BINDING) => {
            Ok(ZkSemanticGuarantee::LinkablePersonaBinding)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_PRIVATE_PERSONA_BINDING) => {
            Ok(ZkSemanticGuarantee::PrivatePersonaBinding)
        }
        Some(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

fn predicate_type_from_proto(
    predicate: EnumValue<pb::ZkPredicateType>,
) -> Result<ZkPredicateType, ZkError> {
    match predicate.as_known() {
        Some(pb::ZkPredicateType::ZK_PREDICATE_TYPE_GREATER_THAN_OR_EQUAL) => {
            Ok(ZkPredicateType::GreaterThanOrEqual)
        }
        Some(pb::ZkPredicateType::ZK_PREDICATE_TYPE_LESS_THAN_OR_EQUAL) => {
            Ok(ZkPredicateType::LessThanOrEqual)
        }
        Some(pb::ZkPredicateType::ZK_PREDICATE_TYPE_RANGE) => Ok(ZkPredicateType::Range),
        Some(pb::ZkPredicateType::ZK_PREDICATE_TYPE_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
        }
    }
}

#[cfg(test)]
mod tests;
