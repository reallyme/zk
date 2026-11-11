// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict artifact-manifest conversion.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::ZkCircuitCapabilities,
    circuits::{
        ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
    },
    claim_bundle::ZkCompatibilitySuiteAcknowledgement,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactManifestPin, ArtifactToolchain, ArtifactVersion, Digest32,
    ProductionArtifactManifest, ProductionArtifactManifestDraft,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::domain::{
    bundle_kind_from_family, capabilities_from_proto, circuit_id_from_proto,
    circuit_ref_from_proto_message, credential_hash_algorithm_from_proto,
    digest_from_proto_message, digest_vec_from_proto, production_stage_from_circuit_stage,
    proof_suite_from_proto,
};

mod capabilities;
pub(crate) use capabilities::capabilities_to_proto;

/// Maximum canonical binary artifact-manifest size.
pub const MAX_ZK_ARTIFACT_MANIFEST_BYTES: usize = 64 * 1024;

const ARTIFACT_MANIFEST_RECURSION_LIMIT: u32 = 16;
const ARTIFACT_MANIFEST_UNKNOWN_FIELD_LIMIT: usize = 0;
const ARTIFACT_MANIFEST_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_ARTIFACT_MANIFEST_BYTES;

/// Decodes untrusted canonical binary artifact-manifest bytes.
pub fn decode_artifact_manifest(bytes: &[u8]) -> Result<ProductionArtifactManifest, ZkError> {
    if bytes.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if bytes.len() > MAX_ZK_ARTIFACT_MANIFEST_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let manifest = DecodeOptions::new()
        .with_recursion_limit(ARTIFACT_MANIFEST_RECURSION_LIMIT)
        .with_unknown_field_limit(ARTIFACT_MANIFEST_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(ARTIFACT_MANIFEST_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_ARTIFACT_MANIFEST_BYTES)
        .decode_from_slice::<pb::ZkArtifactManifest>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    if manifest.encode_to_vec().as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    artifact_manifest_from_proto(manifest)
}

/// Encodes a validated artifact manifest as canonical binary protobuf bytes.
pub fn encode_artifact_manifest(manifest: &ProductionArtifactManifest) -> Result<Vec<u8>, ZkError> {
    let protobuf = artifact_manifest_to_proto(manifest)?;
    let encoded = protobuf.encode_to_vec();
    if encoded.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if encoded.len() > MAX_ZK_ARTIFACT_MANIFEST_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    Ok(encoded)
}

/// Converts a generated artifact manifest into the bounded artifact domain.
pub(crate) fn artifact_manifest_from_proto(
    manifest: pb::ZkArtifactManifest,
) -> Result<ProductionArtifactManifest, ZkError> {
    // Proof packages bind this exact deterministic protobuf representation.
    // Compute before moving fields into the semantic domain owner.
    let encoded_manifest = manifest.encode_to_vec();
    if encoded_manifest.len() > MAX_ZK_ARTIFACT_MANIFEST_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let manifest_digest = Digest32::sha256(encoded_manifest.as_slice());
    let manifest_sha256 = ZkArtifactManifestDigest::from_bytes(*manifest_digest.as_bytes());
    let circuit_ref = circuit_ref_from_proto_message(manifest.circuit_ref)?;
    let circuit_id = circuit_id_from_proto(manifest.circuit_id)?;
    if circuit_id != circuit_ref.circuit_id() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(manifest.credential_hash_algorithm)?;
    if credential_hash_algorithm != circuit_ref.credential_hash_algorithm {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    let proof_suite = proof_suite_from_proto(manifest.proof_suite)?;
    let toolchain = ArtifactToolchain::try_from_versions(
        manifest.nargo_version.as_str(),
        manifest.barretenberg_version.as_str(),
    )?;
    let capabilities = manifest
        .capabilities
        .into_option()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let capabilities = capabilities_from_proto(capabilities, circuit_ref)?;

    let domain = ProductionArtifactManifest::try_new(
        bundle_kind_from_family(circuit_ref.family)?,
        production_stage_from_circuit_stage(circuit_ref.stage)?,
        circuit_ref,
        ArtifactManifestPin::try_new(proof_suite, manifest_sha256)?,
        toolchain,
        capabilities,
        ArtifactDigests {
            noir_source_sha256: digest_from_proto_message(manifest.noir_source_sha256)?,
            bytecode_sha256: digest_from_proto_message(manifest.bytecode_sha256)?,
            verification_key_sha256: digest_from_proto_message(manifest.verification_key_sha256)?,
            capability_registry_sha256: digest_from_proto_message(
                manifest.capability_registry_sha256,
            )?,
            vector_set_sha256: digest_vec_from_proto(manifest.vector_set_sha256)?,
        },
    )?;
    // In-crate callers pass a generated DTO taken from an enclosing envelope
    // rather than from the strict manifest decoder. Require it to reconstruct
    // from admitted semantic fields so unknown fields cannot silently become
    // part of the proof-visible digest.
    let canonical = encode_manifest_content(
        domain.circuit_ref(),
        domain.proof_suite(),
        domain.toolchain(),
        domain.capabilities(),
        domain.digests(),
    )?;
    if canonical.encode_to_vec() != encoded_manifest {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    Ok(domain)
}

/// Canonical protobuf plus the validated domain manifest pinned to its hash.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedArtifactManifest {
    manifest: ProductionArtifactManifest,
    protobuf: pb::ZkArtifactManifest,
}

impl SealedArtifactManifest {
    /// Borrows the runtime domain manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ProductionArtifactManifest {
        &self.manifest
    }

    /// Borrows the canonical protobuf owner written to artifact packages.
    #[must_use]
    pub const fn protobuf(&self) -> &pb::ZkArtifactManifest {
        &self.protobuf
    }

    /// Consumes the sealed value without re-encoding either representation.
    #[must_use]
    pub fn into_parts(self) -> (ProductionArtifactManifest, pb::ZkArtifactManifest) {
        (self.manifest, self.protobuf)
    }
}

/// Seals validated artifact metadata into one canonical protobuf identity.
pub fn seal_artifact_manifest(
    draft: ProductionArtifactManifestDraft,
) -> Result<SealedArtifactManifest, ZkError> {
    let protobuf = encode_manifest_content(
        draft.circuit_ref(),
        draft.proof_suite(),
        draft.toolchain(),
        draft.capabilities(),
        draft.digests(),
    )?;
    let digest = Digest32::sha256(protobuf.encode_to_vec().as_slice());
    let manifest_sha256 = ZkArtifactManifestDigest::from_bytes(*digest.as_bytes());
    let manifest_pin = if draft.proof_suite() == ZkProofSuite::PRODUCTION {
        ArtifactManifestPin::try_new(draft.proof_suite(), manifest_sha256)?
    } else {
        ArtifactManifestPin::try_new_compatibility(
            draft.proof_suite(),
            manifest_sha256,
            ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )?
    };
    let manifest = if draft.proof_suite() == ZkProofSuite::PRODUCTION {
        ProductionArtifactManifest::try_new(
            draft.bundle_kind(),
            draft.stage(),
            draft.circuit_ref(),
            manifest_pin,
            draft.toolchain(),
            draft.capabilities(),
            draft.digests().clone(),
        )?
    } else {
        ProductionArtifactManifest::try_new_compatibility(
            draft.bundle_kind(),
            draft.stage(),
            draft.circuit_ref(),
            manifest_pin,
            draft.toolchain(),
            draft.capabilities(),
            draft.digests().clone(),
            ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )?
    };

    Ok(SealedArtifactManifest { manifest, protobuf })
}

/// Encodes a validated production manifest into its canonical protobuf owner.
///
/// The resulting deterministic binary encoding must hash to the identity
/// retained by the domain manifest. This prevents package generators from
/// changing a field without also rotating the proof-visible manifest pin.
pub fn artifact_manifest_to_proto(
    manifest: &ProductionArtifactManifest,
) -> Result<pb::ZkArtifactManifest, ZkError> {
    let encoded = encode_manifest_content(
        manifest.circuit_ref(),
        manifest.proof_suite(),
        manifest.toolchain(),
        manifest.capabilities(),
        manifest.digests(),
    )?;
    let canonical_digest = Digest32::sha256(encoded.encode_to_vec().as_slice());
    if canonical_digest.as_bytes() != manifest.manifest_sha256().as_bytes() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(encoded)
}

fn encode_manifest_content(
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    toolchain: ArtifactToolchain,
    capabilities: ZkCircuitCapabilities,
    digests: &ArtifactDigests,
) -> Result<pb::ZkArtifactManifest, ZkError> {
    Ok(pb::ZkArtifactManifest {
        circuit_id: EnumValue::from(circuit_id_to_proto(circuit_ref.circuit_id())),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            circuit_ref.credential_hash_algorithm,
        )),
        nargo_version: version_to_string(toolchain.nargo_version())?,
        barretenberg_version: version_to_string(toolchain.barretenberg_version())?,
        noir_source_sha256: MessageField::some(digest_to_proto(digests.noir_source_sha256)),
        bytecode_sha256: MessageField::some(digest_to_proto(digests.bytecode_sha256)),
        verification_key_sha256: MessageField::some(digest_to_proto(
            digests.verification_key_sha256,
        )),
        capability_registry_sha256: MessageField::some(digest_to_proto(
            digests.capability_registry_sha256,
        )),
        vector_set_sha256: digests
            .vector_set_sha256
            .iter()
            .copied()
            .map(digest_to_proto)
            .collect(),
        capabilities: MessageField::some(capabilities_to_proto(capabilities)),
        circuit_ref: MessageField::some(circuit_ref_to_proto(circuit_ref)),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof_suite)),
        __buffa_unknown_fields: Default::default(),
    })
}

pub(crate) fn version_to_string(version: ArtifactVersion) -> Result<String, ZkError> {
    core::str::from_utf8(version.as_bytes())
        .map(str::to_owned)
        .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))
}

pub(crate) fn digest_to_proto(digest: Digest32) -> pb::Digest {
    pb::Digest {
        value: digest.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) fn circuit_ref_to_proto(circuit_ref: ZkCircuitRef) -> pb::ZkCircuitRef {
    pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            circuit_ref.credential_hash_algorithm,
        )),
        family: EnumValue::from(circuit_family_to_proto(circuit_ref.family)),
        stage: EnumValue::from(circuit_stage_to_proto(circuit_ref.stage)),
        circuit_revision: circuit_ref.revision,
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) const fn circuit_id_to_proto(circuit_id: ZkCircuitId) -> pb::ZkCircuitId {
    match circuit_id {
        ZkCircuitId::CredentialSubjectClaimV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkCircuitId::PrivatePersonaClaimV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1
        }
        ZkCircuitId::CommonCredentialRootV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_COMMON_CREDENTIAL_ROOT_V1
        }
        ZkCircuitId::PersonaCredentialEvidenceV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_PERSONA_CREDENTIAL_EVIDENCE_V1
        }
        _ => pb::ZkCircuitId::ZK_CIRCUIT_ID_UNSPECIFIED,
    }
}

pub(crate) const fn credential_hash_algorithm_to_proto(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> pb::ZkCredentialHashAlgorithm {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        }
        _ => pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED,
    }
}

const fn circuit_family_to_proto(family: ZkCircuitFamily) -> pb::ZkCircuitFamily {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkCircuitFamily::PrivatePersonaClaimV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
        }
        ZkCircuitFamily::CommonCredentialRootV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1
        }
        ZkCircuitFamily::PersonaCredentialEvidenceV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1
        }
        _ => pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_UNSPECIFIED,
    }
}

const fn circuit_stage_to_proto(stage: ZkCircuitStage) -> pb::ZkCircuitStage {
    match stage {
        ZkCircuitStage::Session => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        ZkCircuitStage::CredentialEnvelope => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkCircuitStage::CredentialRoot => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT,
        ZkCircuitStage::Claim => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM,
        ZkCircuitStage::ClaimBundle4 => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4,
        ZkCircuitStage::RootAttestation => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ROOT_ATTESTATION,
        ZkCircuitStage::RootStatus => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ROOT_STATUS,
        ZkCircuitStage::Lineage => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_LINEAGE,
        ZkCircuitStage::IssuerCredentialStatus => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS
        }
        ZkCircuitStage::PrivatePersonaClaim => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_PRIVATE_PERSONA_CLAIM
        }
        ZkCircuitStage::PublicPersonaClaim => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_PERSONA_CLAIM
        }
        ZkCircuitStage::PublicSession => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_PUBLIC_SESSION,
        ZkCircuitStage::EvidencePublicClaim => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM
        }
        ZkCircuitStage::EvidencePrivateClaim => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM
        }
        ZkCircuitStage::EvidenceCurrentState => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE
        }
        ZkCircuitStage::EvidenceIssuerEnvelope => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE
        }
        ZkCircuitStage::EvidenceClaimRoot => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT
        }
        ZkCircuitStage::EvidenceSignedValidity => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY
        }
        _ => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED,
    }
}

pub(crate) const fn proof_suite_to_proto(proof_suite: ZkProofSuite) -> pb::ZkProofSuite {
    match proof_suite {
        ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA
        }
        ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_ZK_NO_IPA
        }
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA
        }
        ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa => {
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_UNMASKED_NO_IPA
        }
        _ => pb::ZkProofSuite::ZK_PROOF_SUITE_UNSPECIFIED,
    }
}

#[cfg(test)]
mod tests;
