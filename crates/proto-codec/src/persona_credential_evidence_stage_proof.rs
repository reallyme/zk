// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical prepared proof package admission at the protobuf boundary.
//!
//! A package's declared slot, embedded raw inputs, source circuit, suite, and
//! manifest identity must agree before any backend resolves a verification key.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRawPublicInputs,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageProof,
        PERSONA_CREDENTIAL_EVIDENCE_V1_MAX_RAW_PUBLIC_INPUT_BYTES,
    },
    proofs::{ZkProofBytes, ZkProofSuite, MAX_PROOF_BYTES},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::artifact::{circuit_ref_to_proto, proof_suite_to_proto};
use crate::domain::{circuit_ref_from_proto_message, proof_suite_from_proto};

/// Serialize a backend-verified prepared proof into the shared protobuf
/// package. This is transport data; verifier trust still requires its pinned
/// VK, the matching current-state proof, holder authentication, and policy.
pub fn persona_credential_evidence_stage_proof_to_proto(
    proof: &ZkPersonaCredentialEvidenceStageProof,
) -> pb::ZkPersonaCredentialEvidenceStageProof {
    let mode = match proof.mode() {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    };
    let slot = match proof.public_inputs().stage() {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE
        }
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT
        }
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY
        }
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim
        | ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM
        }
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => {
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE
        }
    };
    let circuit_ref = proof.public_inputs().circuit_ref();
    pb::ZkPersonaCredentialEvidenceStageProof {
        mode: EnumValue::from(mode),
        proof_slot: EnumValue::from(slot),
        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
        proof: proof.proof_bytes().as_bytes().to_vec(),
        public_inputs: MessageField::some(pb::ZkPersonaCredentialEvidenceRawPublicInputs {
            mode: EnumValue::from(mode),
            proof_slot: EnumValue::from(slot),
            circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
            raw_fields: proof.public_inputs().as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_set_identity_sha256: MessageField::some(pb::ZkArtifactSetIdentity {
            value: proof.artifact_set_identity_sha256().as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    }
}

const PREPARED_PACKAGE_RECURSION_LIMIT: u32 = 6;
const PREPARED_PACKAGE_OVERHEAD_BYTES: usize = 16 * 1024;
const MAX_PREPARED_PACKAGE_BYTES: usize = MAX_PROOF_BYTES
    + PERSONA_CREDENTIAL_EVIDENCE_V1_MAX_RAW_PUBLIC_INPUT_BYTES
    + PREPARED_PACKAGE_OVERHEAD_BYTES;

/// Decode an exact canonical protobuf package and validate every nested
/// circuit/slot/mode assertion. The returned proof still needs a pinned
/// backend verification key and independent status/issuer policy.
pub fn decode_persona_credential_evidence_stage_proof(
    bytes: &[u8],
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    if bytes.len() > MAX_PREPARED_PACKAGE_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let package = DecodeOptions::new()
        .with_recursion_limit(PREPARED_PACKAGE_RECURSION_LIMIT)
        .with_unknown_field_limit(0)
        .with_element_memory_limit(MAX_PREPARED_PACKAGE_BYTES)
        .with_max_message_size(MAX_PREPARED_PACKAGE_BYTES)
        .decode_from_slice::<pb::ZkPersonaCredentialEvidenceStageProof>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    // Canonicality re-encoding contains proof bytes and token public inputs.
    if Zeroizing::new(package.encode_to_vec()).as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    persona_credential_evidence_stage_proof_from_proto(package)
}

/// Convert a generated Buffa message after checking the nested metadata.
pub(crate) fn persona_credential_evidence_stage_proof_from_proto(
    mut package: pb::ZkPersonaCredentialEvidenceStageProof,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let mode = profile_from_proto(package.mode)?;
    let slot = slot_from_proto(package.proof_slot)?;
    let circuit_ref = circuit_ref_from_proto_message(core::mem::take(&mut package.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(package.proof_suite)?;
    let manifest = crate::artifact_identity::artifact_set_identity_from_proto(core::mem::take(
        &mut package.artifact_set_identity_sha256,
    ))?;
    let mut nested = package
        .public_inputs
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    if profile_from_proto(nested.mode)? != mode
        || slot_from_proto(nested.proof_slot)? != slot
        || circuit_ref_from_proto_message(core::mem::take(&mut nested.circuit_ref))? != circuit_ref
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let stage = match (mode, slot) {
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE) => {
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        }
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT) => {
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
        }
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY) => {
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity
        }
        (
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
        ) => ZkPersonaCredentialEvidenceSourceStage::PublicClaim,
        (
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
        ) => ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE) => {
            ZkPersonaCredentialEvidenceSourceStage::CurrentState
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    };
    if stage.source_ref(circuit_ref.credential_hash_algorithm) != circuit_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        mode,
        proof_suite,
        manifest,
        ZkProofBytes::try_from_bytes(core::mem::take(&mut package.proof))?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            circuit_ref,
            core::mem::take(&mut nested.raw_fields),
        )?,
    )
}

pub(crate) fn profile_from_proto(
    mode: EnumValue<pb::ZkPersonaCredentialEvidenceMode>,
) -> Result<ZkPersonaCredentialEvidenceMode, ZkError> {
    match mode.as_known() {
        Some(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1) => {
            Ok(ZkPersonaCredentialEvidenceMode::PublicPersonaV1)
        }
        Some(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1) => {
            Ok(ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1)
        }
        _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    }
}

pub(crate) fn slot_from_proto(
    slot: EnumValue<pb::ZkPersonaCredentialEvidenceProofSlot>,
) -> Result<pb::ZkPersonaCredentialEvidenceProofSlot, ZkError> {
    match slot.as_known() {
        Some(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE) => {
            Ok(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE)
        }
        Some(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT) => {
            Ok(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT)
        }
        Some(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY) => {
            Ok(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY)
        }
        Some(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM) => {
            Ok(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM)
        }
        Some(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE) => {
            Ok(pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE)
        }
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

/// A provider success report remains transport data until joined with the
/// remaining stages and the live presentation authentication.
pub struct ZkPersonaCredentialEvidenceStageVerificationReport {
    /// Persona mode reported by the verified source proof.
    pub mode: ZkPersonaCredentialEvidenceMode,
    /// Exact prepared stage reported by the backend.
    pub stage: ZkPersonaCredentialEvidenceSourceStage,
    /// Exact source circuit resolved under the release index.
    pub circuit_ref: ZkCircuitRef,
    /// Pinned production proof suite.
    pub proof_suite: ZkProofSuite,
}

pub(crate) fn persona_credential_evidence_stage_verification_from_proto(
    mut value: pb::ZkPersonaCredentialEvidenceStageVerification,
) -> Result<ZkPersonaCredentialEvidenceStageVerificationReport, ZkError> {
    let mode = profile_from_proto(value.mode)?;
    let slot = slot_from_proto(value.proof_slot)?;
    let circuit_ref = circuit_ref_from_proto_message(core::mem::take(&mut value.circuit_ref))?;
    let proof_suite = proof_suite_from_proto(value.proof_suite)?;
    proof_suite.require_production()?;
    let stage = match (mode, slot) {
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE) => {
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        }
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT) => {
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot
        }
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY) => {
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity
        }
        (
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
        ) => ZkPersonaCredentialEvidenceSourceStage::PublicClaim,
        (
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
        ) => ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
        (_, pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE) => {
            ZkPersonaCredentialEvidenceSourceStage::CurrentState
        }
        _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
    };
    if stage.source_ref(circuit_ref.credential_hash_algorithm) != circuit_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    Ok(ZkPersonaCredentialEvidenceStageVerificationReport {
        mode,
        stage,
        circuit_ref,
        proof_suite,
    })
}

#[cfg(test)]
#[path = "persona_credential_evidence_stage_proof/tests.rs"]
mod tests;
