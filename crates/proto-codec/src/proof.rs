// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict conversion of exact proofs and production proof bundles.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleStage,
        ZkClaimProofBundleStageProof,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkPublicInputs, MAX_PROOF_BYTES, MAX_PUBLIC_INPUT_BYTES},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::artifact::{
    circuit_id_to_proto, circuit_ref_to_proto, credential_hash_algorithm_to_proto,
    proof_suite_to_proto,
};
use crate::binding::session_binding_from_proto_message;
use crate::domain::{
    bundle_kind_from_proto, circuit_id_from_proto, circuit_ref_from_proto_message,
    credential_hash_algorithm_from_proto, production_stage_from_proto, proof_suite_from_proto,
    CLAIM_PROOF_BUNDLE_FORMAT_VERSION,
};
use crate::release::{bundle_kind_to_proto, production_stage_to_proto};

const ZK_PROOF_PACKAGE_RECURSION_LIMIT: u32 = 16;
const ZK_PROOF_PACKAGE_UNKNOWN_FIELD_LIMIT: usize = 0;
const ZK_PROOF_PACKAGE_OVERHEAD_BYTES: usize = 16 * 1024;
const MAX_ZK_PROOF_PACKAGE_BYTES: usize =
    MAX_PROOF_BYTES + MAX_PUBLIC_INPUT_BYTES + ZK_PROOF_PACKAGE_OVERHEAD_BYTES;

/// Encodes one exact proof package into canonical binary protobuf bytes.
pub fn encode_exact_proof(proof: &ZkProof) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_canonical_proof(&proof_to_proto(proof)?)
}

/// Decodes one exact canonical proof package from an untrusted byte slice.
pub fn decode_exact_proof(bytes: &[u8]) -> Result<ZkProof, ZkError> {
    if bytes.len() > MAX_ZK_PROOF_PACKAGE_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let proof = DecodeOptions::new()
        .with_recursion_limit(ZK_PROOF_PACKAGE_RECURSION_LIMIT)
        .with_unknown_field_limit(ZK_PROOF_PACKAGE_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(MAX_ZK_PROOF_PACKAGE_BYTES)
        .with_max_message_size(MAX_ZK_PROOF_PACKAGE_BYTES)
        .decode_from_slice::<pb::ZkProofPackage>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let canonical = encode_canonical_proof(&proof)?;
    if canonical.as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }
    exact_proof_from_proto(proof)
}

fn encode_canonical_proof(proof: &pb::ZkProofPackage) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let maximum = u32::try_from(MAX_ZK_PROOF_PACKAGE_BYTES)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let encoded_len = proof
        .try_encoded_len()
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    if encoded_len > maximum {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let encoded_len =
        usize::try_from(encoded_len).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    proof
        .try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

pub(crate) fn proof_to_proto(proof: &ZkProof) -> Result<pb::ZkProofPackage, ZkError> {
    Ok(pb::ZkProofPackage {
        circuit_id: EnumValue::from(circuit_id_to_proto(proof.circuit_id())),
        circuit_id_string: proof.circuit_id().as_str().to_owned(),
        proof: proof.proof_bytes().to_vec(),
        public_inputs: MessageField::some(pb::ZkPublicInputs {
            encoded: proof.public_inputs().as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        }),
        artifact_identity: Some(crate::artifact_identity::proof_identity_to_proto(
            proof.artifact_identity(),
        )),
        named_public_inputs: Vec::new(),
        circuit_ref: MessageField::some(circuit_ref_to_proto(proof.circuit_ref())),
        proof_suite: EnumValue::from(proof_suite_to_proto(proof.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    })
}

pub(crate) fn claim_proof_bundle_to_proto(
    bundle: &ZkClaimProofBundle,
) -> Result<pb::ZkClaimProofBundle, ZkError> {
    let mut credential_hash_algorithm = None;
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(bundle.stage_proofs().len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;

    for stage_proof in bundle.stage_proofs() {
        let stage_credential_hash_algorithm =
            stage_proof.proof().circuit_ref().credential_hash_algorithm;
        if let Some(expected_credential_hash_algorithm) = credential_hash_algorithm {
            if expected_credential_hash_algorithm != stage_credential_hash_algorithm {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
        } else {
            credential_hash_algorithm = Some(stage_credential_hash_algorithm);
        }
        stages.push(pb::ZkClaimProofBundleStageProofPackage {
            bundle_kind: EnumValue::from(bundle_kind_to_proto(stage_proof.bundle_kind())),
            stage: EnumValue::from(production_stage_to_proto(stage_proof.stage())),
            proof: MessageField::some(proof_to_proto(stage_proof.proof())?),
            __buffa_unknown_fields: Default::default(),
        });
    }

    let credential_hash_algorithm =
        credential_hash_algorithm.ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    Ok(pb::ZkClaimProofBundle {
        bundle_kind: EnumValue::from(bundle_kind_to_proto(bundle.bundle_kind())),
        format_version: CLAIM_PROOF_BUNDLE_FORMAT_VERSION,
        stages,
        session_binding: MessageField::some(session_binding_to_proto(bundle.session_binding())),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            credential_hash_algorithm,
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(bundle.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    })
}

fn session_binding_to_proto(
    binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding
            .transaction_data_hash
            .map_or_else(Vec::new, |hash| hash.to_vec()),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Converts a generated production proof bundle into the API-domain type.
pub(crate) fn claim_proof_bundle_from_proto(
    bundle: pb::ZkClaimProofBundle,
) -> Result<ZkClaimProofBundle, ZkError> {
    if bundle.format_version != CLAIM_PROOF_BUNDLE_FORMAT_VERSION {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    let bundle_kind = bundle_kind_from_proto(bundle.bundle_kind)?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(bundle.credential_hash_algorithm)?;
    let proof_suite = proof_suite_from_proto(bundle.proof_suite)?;
    let session_binding = session_binding_from_proto_message(bundle.session_binding)?;
    if bundle.stages.len() < ZkClaimProofBundleStage::ALL.len() {
        return Err(ZkError::new(ZkErrorReason::MissingStage));
    }
    if bundle.stages.len() > ZkClaimProofBundleStage::ALL.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }
    let mut stage_proofs = Vec::new();
    stage_proofs
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;

    for stage in bundle.stages {
        let stage_proof = stage_proof_from_proto(stage, bundle_kind, credential_hash_algorithm)?;
        if stage_proof.proof().proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        stage_proofs.push(stage_proof);
    }

    ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, session_binding, stage_proofs)
}

fn stage_proof_from_proto(
    stage_package: pb::ZkClaimProofBundleStageProofPackage,
    expected_profile: ZkClaimProofBundleKind,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ZkClaimProofBundleStageProof, ZkError> {
    let bundle_kind = bundle_kind_from_proto(stage_package.bundle_kind)?;
    if bundle_kind != expected_profile {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    let stage = production_stage_from_proto(stage_package.stage)?;
    let proof_package = stage_package
        .proof
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
    let proof = proof_from_proto(
        proof_package,
        expected_profile,
        expected_credential_hash_algorithm,
        stage,
    )?;

    ZkClaimProofBundleStageProof::try_from_parts(bundle_kind, stage, proof)
}

fn proof_from_proto(
    proof_package: pb::ZkProofPackage,
    expected_profile: ZkClaimProofBundleKind,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    expected_stage: ZkClaimProofBundleStage,
) -> Result<ZkProof, ZkError> {
    let proof = exact_proof_from_proto(proof_package)?;
    if proof.circuit_id() != expected_profile.circuit_id() {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    let circuit_ref = proof.circuit_ref();
    if circuit_ref
        != expected_profile.source_ref(expected_credential_hash_algorithm, expected_stage)
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    Ok(proof)
}

pub(crate) fn exact_proof_from_proto(
    mut proof_package: pb::ZkProofPackage,
) -> Result<ZkProof, ZkError> {
    let circuit_id = circuit_id_from_proto(proof_package.circuit_id)?;
    if proof_package.circuit_id_string != circuit_id.as_str() {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    let circuit_ref =
        circuit_ref_from_proto_message(core::mem::take(&mut proof_package.circuit_ref))?;
    if circuit_ref.circuit_id() != circuit_id {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    let proof_suite = proof_suite_from_proto(proof_package.proof_suite)?;
    let artifact_identity = crate::artifact_identity::proof_identity_from_proto(
        proof_package.artifact_identity.take(),
    )?;
    // Named values are a separate semantic encoding. Until the compact ABI
    // has a canonical bidirectional mapping, accepting both would allow two
    // representations to disagree. Fail closed instead of ignoring one.
    if !proof_package.named_public_inputs.is_empty() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }

    let public_inputs = proof_package
        .public_inputs
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let mut public_inputs = public_inputs;
    let public_inputs =
        ZkPublicInputs::try_from_bytes(core::mem::take(&mut public_inputs.encoded))?;

    ZkProof::try_from_exact_parts(
        circuit_id,
        circuit_ref,
        proof_suite,
        artifact_identity,
        core::mem::take(&mut proof_package.proof),
        public_inputs,
    )
}
