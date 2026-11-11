// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

use super::{artifact_manifest_from_proto, decode_artifact_manifest, pb};

const UNKNOWN_FIELD_SUFFIX: [u8; 3] = [0xa0, 0x06, 0x01];
const UNKNOWN_FIELD_DECODE_LIMIT: usize = 3;

fn digest(value: u8) -> pb::Digest {
    pb::Digest {
        value: vec![value; 32],
        __buffa_unknown_fields: Default::default(),
    }
}

fn capabilities() -> pb::ZkCircuitCapabilities {
    pb::ZkCircuitCapabilities {
        subject_binding: EnumValue::from(pb::ZkSubjectBinding::ZK_SUBJECT_BINDING_REQUIRED),
        persona_binding: EnumValue::from(pb::ZkPersonaBinding::ZK_PERSONA_BINDING_REQUIRED),
        may_be_correlated: true,
        predicate_types: Vec::new(),
        disclosure_modes: vec![EnumValue::from(
            pb::ZkDisclosureMode::ZK_DISCLOSURE_MODE_REVEAL,
        )],
        semantic_guarantees: vec![
            EnumValue::from(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_SESSION_BOUND),
            EnumValue::from(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_AUDIENCE_BOUND),
            EnumValue::from(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_TRANSACTION_DATA_BOUND),
            EnumValue::from(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CLAIM_INTEGRITY),
            EnumValue::from(pb::ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_PRIVATE_PERSONA_BINDING),
        ],
        __buffa_unknown_fields: Default::default(),
    }
}

fn manifest() -> pb::ZkArtifactManifest {
    pb::ZkArtifactManifest {
        circuit_id: EnumValue::from(pb::ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1),
        credential_hash_algorithm: EnumValue::from(
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        nargo_version: "1.0.0".to_owned(),
        barretenberg_version: "1.0.0".to_owned(),
        noir_source_sha256: MessageField::some(digest(1)),
        bytecode_sha256: MessageField::some(digest(2)),
        verification_key_sha256: MessageField::some(digest(3)),
        capability_registry_sha256: MessageField::some(digest(4)),
        vector_set_sha256: vec![digest(5)],
        capabilities: MessageField::some(capabilities()),
        circuit_ref: MessageField::some(pb::ZkCircuitRef {
            credential_hash_algorithm: EnumValue::from(
                pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ),
            family: EnumValue::from(
                pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1,
            ),
            stage: EnumValue::from(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM),
            circuit_revision: 1,
            __buffa_unknown_fields: Default::default(),
        }),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn generated_manifest_conversion_matches_canonical_byte_admission() -> Result<(), ZkError> {
    let source = manifest();
    let decoded = decode_artifact_manifest(&source.encode_to_vec())?;

    assert_eq!(artifact_manifest_from_proto(source)?, decoded);
    Ok(())
}

#[test]
fn generated_manifest_conversion_rejects_unknown_fields() -> Result<(), ZkError> {
    let mut bytes = manifest().encode_to_vec();
    // Unknown field 100, wire type 0, value 1. The strict wire decoder also
    // rejects it; conversion of a generated message taken from an enclosing
    // envelope must enforce the same rule.
    bytes.extend_from_slice(&UNKNOWN_FIELD_SUFFIX);
    let decoded = DecodeOptions::new()
        .with_unknown_field_limit(UNKNOWN_FIELD_DECODE_LIMIT)
        .decode_from_slice::<pb::ZkArtifactManifest>(&bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let error = artifact_manifest_from_proto(decoded)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::MalformedProtobuf);
    Ok(())
}
