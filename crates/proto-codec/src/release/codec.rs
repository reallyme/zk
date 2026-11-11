// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical release-index protobuf codec and matrix validation.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{ArtifactToolchain, ArtifactVersion};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::{
    artifact::{
        circuit_ref_to_proto, credential_hash_algorithm_to_proto, digest_to_proto,
        proof_suite_to_proto, version_to_string,
    },
    domain::{
        bundle_kind_from_proto, circuit_ref_from_proto_message,
        credential_hash_algorithm_from_proto, digest_from_proto_message,
        production_stage_from_proto, proof_suite_from_proto,
    },
};

use super::{
    ReleaseArtifactPin, ReleaseCommonCredentialRootArtifactPin, ReleaseIndex,
    ReleasePersonaCredentialEvidenceArtifactPin, ReleaseVerificationVectorPin,
    COMMON_CREDENTIAL_ROOT_STAGES, MAX_ZK_RELEASE_INDEX_BYTES, PERSONA_CREDENTIAL_EVIDENCE_STAGES,
    RELEASE_ARTIFACT_MANIFEST_COUNT, RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT,
    RELEASE_ELEMENT_MEMORY_LIMIT, RELEASE_INDEX_FORMAT_VERSION,
    RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT, RELEASE_RECURSION_LIMIT,
    RELEASE_UNKNOWN_FIELD_LIMIT, RELEASE_VERIFICATION_VECTOR_SET_COUNT,
};

/// Decodes untrusted canonical binary release-index bytes.
pub fn decode_release_index(bytes: &[u8]) -> Result<ReleaseIndex, ZkError> {
    if bytes.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if bytes.len() > MAX_ZK_RELEASE_INDEX_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let index = DecodeOptions::new()
        .with_recursion_limit(RELEASE_RECURSION_LIMIT)
        .with_unknown_field_limit(RELEASE_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(RELEASE_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_RELEASE_INDEX_BYTES)
        .decode_from_slice::<pb::ZkReleaseIndex>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    if index.encode_to_vec().as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    release_index_from_proto(index)
}

/// Encodes one validated index into deterministic canonical protobuf bytes.
pub fn encode_release_index(index: &ReleaseIndex) -> Result<Vec<u8>, ZkError> {
    Ok(release_index_to_proto(index)?.encode_to_vec())
}

fn release_index_from_proto(index: pb::ZkReleaseIndex) -> Result<ReleaseIndex, ZkError> {
    if index.format_version != RELEASE_INDEX_FORMAT_VERSION {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let release_version = ArtifactVersion::try_from_token(index.release_version.as_str())?;
    let toolchain = ArtifactToolchain::try_from_versions(
        index.nargo_version.as_str(),
        index.barretenberg_version.as_str(),
    )?;
    let proof_suite = proof_suite_from_proto(index.proof_suite)?;
    let capability_registry_sha256 = digest_from_proto_message(index.capability_registry_sha256)?;

    let mut artifact_manifests = Vec::new();
    artifact_manifests
        .try_reserve_exact(index.artifact_manifests.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for pin in index.artifact_manifests {
        artifact_manifests.push(artifact_pin_from_proto(pin)?);
    }
    let mut verification_vectors = Vec::new();
    verification_vectors
        .try_reserve_exact(index.verification_vectors.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for pin in index.verification_vectors {
        verification_vectors.push(vector_pin_from_proto(pin)?);
    }

    let mut common_credential_root_artifacts = Vec::new();
    common_credential_root_artifacts
        .try_reserve_exact(index.common_credential_root_artifacts.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for pin in index.common_credential_root_artifacts {
        common_credential_root_artifacts.push(common_credential_root_pin_from_proto(pin)?);
    }

    let mut persona_credential_evidence_artifacts = Vec::new();
    persona_credential_evidence_artifacts
        .try_reserve_exact(index.persona_credential_evidence_artifacts.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for pin in index.persona_credential_evidence_artifacts {
        persona_credential_evidence_artifacts
            .push(persona_credential_evidence_pin_from_proto(pin)?);
    }

    ReleaseIndex::try_new_with_exact_sources(
        release_version,
        toolchain,
        proof_suite,
        capability_registry_sha256,
        artifact_manifests,
        verification_vectors,
        common_credential_root_artifacts,
        persona_credential_evidence_artifacts,
    )
}

fn persona_credential_evidence_pin_from_proto(
    pin: pb::ZkReleasePersonaCredentialEvidenceArtifactPin,
) -> Result<ReleasePersonaCredentialEvidenceArtifactPin, ZkError> {
    let identity = digest_from_proto_message(pin.artifact_identity_sha256)?;
    ReleasePersonaCredentialEvidenceArtifactPin::try_new(
        circuit_ref_from_proto_message(pin.circuit_ref)?,
        digest_from_proto_message(pin.source_lock_sha256)?,
        digest_from_proto_message(pin.source_closure_sha256)?,
        digest_from_proto_message(pin.bytecode_sha256)?,
        digest_from_proto_message(pin.verification_key_sha256)?,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(*identity.as_bytes()),
    )
}

fn common_credential_root_pin_from_proto(
    pin: pb::ZkReleaseCommonCredentialRootArtifactPin,
) -> Result<ReleaseCommonCredentialRootArtifactPin, ZkError> {
    let identity = digest_from_proto_message(pin.artifact_identity_sha256)?;
    ReleaseCommonCredentialRootArtifactPin::try_new(
        circuit_ref_from_proto_message(pin.circuit_ref)?,
        digest_from_proto_message(pin.source_lock_sha256)?,
        digest_from_proto_message(pin.source_closure_sha256)?,
        digest_from_proto_message(pin.bytecode_sha256)?,
        digest_from_proto_message(pin.verification_key_sha256)?,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(*identity.as_bytes()),
    )
}

pub(crate) fn artifact_pin_from_proto(
    pin: pb::ZkReleaseArtifactPin,
) -> Result<ReleaseArtifactPin, ZkError> {
    let bundle_kind = bundle_kind_from_proto(pin.bundle_kind)?;
    let stage = production_stage_from_proto(pin.stage)?;
    let circuit_ref = circuit_ref_from_proto_message(pin.circuit_ref)?;
    let manifest_digest =
        crate::artifact_identity::manifest_digest_from_proto(pin.artifact_manifest_sha256)?;
    ReleaseArtifactPin::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ZkArtifactManifestDigest::from_bytes(*manifest_digest.as_bytes()),
    )
}

fn vector_pin_from_proto(
    pin: pb::ZkReleaseVerificationVectorPin,
) -> Result<ReleaseVerificationVectorPin, ZkError> {
    ReleaseVerificationVectorPin::try_new(
        bundle_kind_from_proto(pin.bundle_kind)?,
        credential_hash_algorithm_from_proto(pin.credential_hash_algorithm)?,
        proof_suite_from_proto(pin.proof_suite)?,
        digest_from_proto_message(pin.vector_set_sha256)?,
        pin.vector_count,
    )
}

pub(super) fn validate_artifact_matrix(pins: &[ReleaseArtifactPin]) -> Result<(), ZkError> {
    if pins.len() != RELEASE_ARTIFACT_MANIFEST_COUNT {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut index = 0_usize;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                let pin = pins
                    .get(index)
                    .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
                if pin.bundle_kind != *bundle_kind
                    || pin.stage != *stage
                    || pin.circuit_ref != bundle_kind.source_ref(*credential_hash_algorithm, *stage)
                {
                    return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
                }
                index = index
                    .checked_add(1)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_vector_matrix(
    pins: &[ReleaseVerificationVectorPin],
    proof_suite: ZkProofSuite,
) -> Result<(), ZkError> {
    if pins.len() != RELEASE_VERIFICATION_VECTOR_SET_COUNT {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut index = 0_usize;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            let pin = pins
                .get(index)
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            if pin.bundle_kind != *bundle_kind
                || pin.credential_hash_algorithm != *credential_hash_algorithm
                || pin.proof_suite != proof_suite
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            index = index
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(())
}

pub(super) fn validate_common_credential_root_matrix(
    pins: &[ReleaseCommonCredentialRootArtifactPin],
) -> Result<(), ZkError> {
    if pins.is_empty() {
        return Ok(());
    }
    if pins.len() != RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut index = 0_usize;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for stage in COMMON_CREDENTIAL_ROOT_STAGES {
            let pin = pins
                .get(index)
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            if pin.circuit_ref
                != ZkCircuitRef::new(
                    *credential_hash_algorithm,
                    ZkCircuitFamily::CommonCredentialRootV1,
                    stage,
                )
                || pin.source_lock_sha256 != pins[0].source_lock_sha256
                || pins.iter().skip(index + 1).any(|candidate| {
                    candidate.artifact_identity_sha256 == pin.artifact_identity_sha256
                })
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            index = index
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(())
}

pub(super) fn validate_persona_credential_evidence_matrix(
    pins: &[ReleasePersonaCredentialEvidenceArtifactPin],
) -> Result<(), ZkError> {
    if pins.is_empty() {
        return Ok(());
    }
    if pins.len() != RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut index = 0_usize;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for stage in PERSONA_CREDENTIAL_EVIDENCE_STAGES {
            let pin = pins
                .get(index)
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            if pin.circuit_ref
                != ZkCircuitRef::new(
                    *credential_hash_algorithm,
                    ZkCircuitFamily::PersonaCredentialEvidenceV1,
                    stage,
                )
                || pin.source_lock_sha256 != pins[0].source_lock_sha256
                || pins.iter().skip(index + 1).any(|candidate| {
                    candidate.artifact_identity_sha256 == pin.artifact_identity_sha256
                })
            {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            index = index
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(())
}

pub(super) fn validate_unique_release_digests(
    artifact_manifests: &[ReleaseArtifactPin],
    verification_vectors: &[ReleaseVerificationVectorPin],
) -> Result<(), ZkError> {
    for (index, pin) in artifact_manifests.iter().enumerate() {
        let remaining_start = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if artifact_manifests
            .iter()
            .skip(remaining_start)
            .any(|candidate| candidate.manifest_sha256 == pin.manifest_sha256)
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    }
    for (index, pin) in verification_vectors.iter().enumerate() {
        let remaining_start = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if verification_vectors
            .iter()
            .skip(remaining_start)
            .any(|candidate| candidate.vector_set_sha256 == pin.vector_set_sha256)
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    }
    Ok(())
}

fn release_index_to_proto(index: &ReleaseIndex) -> Result<pb::ZkReleaseIndex, ZkError> {
    Ok(pb::ZkReleaseIndex {
        format_version: RELEASE_INDEX_FORMAT_VERSION,
        release_version: version_to_string(index.release_version)?,
        nargo_version: version_to_string(index.toolchain.nargo_version())?,
        barretenberg_version: version_to_string(index.toolchain.barretenberg_version())?,
        proof_suite: EnumValue::from(proof_suite_to_proto(index.proof_suite)),
        capability_registry_sha256: MessageField::some(digest_to_proto(
            index.capability_registry_sha256,
        )),
        artifact_manifests: index
            .artifact_manifests
            .iter()
            .copied()
            .map(artifact_pin_to_proto)
            .collect(),
        verification_vectors: index
            .verification_vectors
            .iter()
            .copied()
            .map(vector_pin_to_proto)
            .collect(),
        common_credential_root_artifacts: index
            .common_credential_root_artifacts
            .iter()
            .copied()
            .map(common_credential_root_pin_to_proto)
            .collect(),
        persona_credential_evidence_artifacts: index
            .persona_credential_evidence_artifacts
            .iter()
            .copied()
            .map(persona_credential_evidence_pin_to_proto)
            .collect(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn persona_credential_evidence_pin_to_proto(
    pin: ReleasePersonaCredentialEvidenceArtifactPin,
) -> pb::ZkReleasePersonaCredentialEvidenceArtifactPin {
    pb::ZkReleasePersonaCredentialEvidenceArtifactPin {
        circuit_ref: MessageField::some(circuit_ref_to_proto(pin.circuit_ref)),
        source_lock_sha256: MessageField::some(digest_to_proto(pin.source_lock_sha256)),
        source_closure_sha256: MessageField::some(digest_to_proto(pin.source_closure_sha256)),
        bytecode_sha256: MessageField::some(digest_to_proto(pin.bytecode_sha256)),
        verification_key_sha256: MessageField::some(digest_to_proto(pin.verification_key_sha256)),
        artifact_identity_sha256: MessageField::some(pb::Digest {
            value: pin.artifact_identity_sha256.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

fn common_credential_root_pin_to_proto(
    pin: ReleaseCommonCredentialRootArtifactPin,
) -> pb::ZkReleaseCommonCredentialRootArtifactPin {
    pb::ZkReleaseCommonCredentialRootArtifactPin {
        circuit_ref: MessageField::some(circuit_ref_to_proto(pin.circuit_ref)),
        source_lock_sha256: MessageField::some(digest_to_proto(pin.source_lock_sha256)),
        source_closure_sha256: MessageField::some(digest_to_proto(pin.source_closure_sha256)),
        bytecode_sha256: MessageField::some(digest_to_proto(pin.bytecode_sha256)),
        verification_key_sha256: MessageField::some(digest_to_proto(pin.verification_key_sha256)),
        artifact_identity_sha256: MessageField::some(pb::Digest {
            value: pin.artifact_identity_sha256.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) fn artifact_pin_to_proto(pin: ReleaseArtifactPin) -> pb::ZkReleaseArtifactPin {
    pb::ZkReleaseArtifactPin {
        bundle_kind: EnumValue::from(bundle_kind_to_proto(pin.bundle_kind)),
        stage: EnumValue::from(production_stage_to_proto(pin.stage)),
        circuit_ref: MessageField::some(circuit_ref_to_proto(pin.circuit_ref)),
        artifact_manifest_sha256: MessageField::some(pb::ZkArtifactManifestDigest {
            value: pin.manifest_sha256.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

fn vector_pin_to_proto(pin: ReleaseVerificationVectorPin) -> pb::ZkReleaseVerificationVectorPin {
    pb::ZkReleaseVerificationVectorPin {
        bundle_kind: EnumValue::from(bundle_kind_to_proto(pin.bundle_kind)),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            pin.credential_hash_algorithm,
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(pin.proof_suite)),
        vector_set_sha256: MessageField::some(digest_to_proto(pin.vector_set_sha256)),
        vector_count: pin.vector_count,
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) const fn bundle_kind_to_proto(
    bundle_kind: ZkClaimProofBundleKind,
) -> pb::ZkClaimProofBundleKind {
    match bundle_kind {
        ZkClaimProofBundleKind::CredentialSubjectClaimV1 => {
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkClaimProofBundleKind::PrivatePersonaClaimV1 => {
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1
        }
        _ => pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED,
    }
}

pub(crate) const fn production_stage_to_proto(
    stage: ZkClaimProofBundleStage,
) -> pb::ZkClaimProofBundleStage {
    match stage {
        ZkClaimProofBundleStage::Session => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION
        }
        ZkClaimProofBundleStage::CredentialEnvelope => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkClaimProofBundleStage::CredentialRoot => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT
        }
        ZkClaimProofBundleStage::Claim => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM
        }
        _ => pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED,
    }
}
