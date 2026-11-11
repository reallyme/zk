// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)]

use std::{fs, io, path::Path};

use reallyme_zk_api::{
    artifacts::ZkArtifactSetIdentity,
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_artifacts::{ArtifactKind, Digest32, VerifiedArtifactBytes};
use reallyme_zk_backend_bb::{
    BbExactCircuitArtifacts, BbExactCircuitVerifyRequest, BARRETENBERG_FIELD_BYTES,
};

use super::{
    circuit_dir, retained_request_bound_circuit_refs, CircuitEvidence, MatrixError,
    NegativeOutcomes,
};

pub fn negative_outcomes(
    backend: &reallyme_zk_backend_bb::NativeBarretenbergBackend,
    root: &Path,
    evidence: &CircuitEvidence,
    proof: &ZkProof,
    binding: ZkSessionBinding,
) -> Result<NegativeOutcomes, MatrixError> {
    let wrong_nonce = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: flip_nonce(binding)?,
        }),
        ZkErrorReason::BindingMismatch,
    )?;
    let wrong_audience = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: flip_audience(binding)?,
        }),
        ZkErrorReason::BindingMismatch,
    )?;
    let wrong_transaction = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: flip_transaction(binding)?,
        }),
        ZkErrorReason::BindingMismatch,
    )?;
    let absent_transaction = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: remove_transaction(binding)?,
        }),
        ZkErrorReason::BindingMismatch,
    )?;
    let sentinel_transaction = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: use_absence_sentinel_as_transaction(binding),
        }),
        ZkErrorReason::BindingMismatch,
    )?;
    let wrong_circuit = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: alternate_circuit_ref(evidence.circuit_ref)?,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: binding,
        }),
        ZkErrorReason::StageMismatch,
    )?;
    let wrong_artifact_identity = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (alternate_artifact_identity(evidence.artifact_identity)).into(),
            artifacts: &evidence.artifacts,
            proof,
            expected_binding: binding,
        }),
        ZkErrorReason::ArtifactMismatch,
    )?;
    let wrong_vk_artifacts = wrong_verification_key_artifacts(root, evidence)?;
    let wrong_verification_key = expect_one_of(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &wrong_vk_artifacts,
            proof,
            expected_binding: binding,
        }),
        &[
            ZkErrorReason::InvalidProof,
            ZkErrorReason::InvalidProofEncoding,
            ZkErrorReason::BackendFailure,
        ],
    )?;
    let tampered_proof_same_length =
        expect_invalid_proof_for_same_length_tamper(backend, evidence, proof, binding)?;
    let tampered_proof_malformed_length = tamper_proof_malformed_length(evidence, proof)?;
    let tampered_proof_malformed_length = expect_one_of(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &tampered_proof_malformed_length,
            expected_binding: binding,
        }),
        &[
            ZkErrorReason::InvalidProof,
            ZkErrorReason::InvalidProofEncoding,
            ZkErrorReason::BackendFailure,
        ],
    )?;
    let tampered_public_inputs = tamper_public_inputs(evidence, proof)?;
    let tampered_public_inputs = expect_reason(
        backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &tampered_public_inputs,
            expected_binding: binding,
        }),
        ZkErrorReason::InvalidProof,
    )?;

    Ok(NegativeOutcomes {
        wrong_nonce,
        wrong_audience,
        wrong_transaction,
        absent_transaction,
        sentinel_transaction,
        wrong_circuit,
        wrong_artifact_identity,
        wrong_verification_key,
        tampered_proof_same_length,
        tampered_proof_malformed_length,
        tampered_public_inputs,
    })
}

fn wrong_verification_key_artifacts(
    root: &Path,
    evidence: &CircuitEvidence,
) -> Result<BbExactCircuitArtifacts, MatrixError> {
    let alternate = alternate_circuit_ref_with_existing_artifacts(root, evidence)?;
    let alternate_vk_path = circuit_dir(root, alternate)
        .join("target")
        .join("modern-run-01")
        .join("vk");
    let verification_key_bytes = fs::read(alternate_vk_path)?;
    let verification_key_digest = Digest32::sha256(verification_key_bytes.as_slice());
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key_bytes,
        verification_key_digest,
    )?;
    BbExactCircuitArtifacts::try_new(
        evidence.circuit_ref,
        evidence.artifact_identity,
        evidence.artifacts.bytecode().clone(),
        verification_key,
    )
    .map_err(MatrixError::from)
}

fn alternate_circuit_ref_with_existing_artifacts(
    root: &Path,
    evidence: &CircuitEvidence,
) -> Result<ZkCircuitRef, MatrixError> {
    let expected_len = evidence.proof.proof_bytes().len();
    let mut first_existing = None;
    for candidate in retained_request_bound_circuit_refs() {
        if *candidate == evidence.circuit_ref {
            continue;
        }
        let candidate_dir = circuit_dir(root, *candidate)
            .join("target")
            .join("modern-run-01");
        let Some((proof_len, vk_digest)) = candidate_artifact_summary(&candidate_dir)? else {
            continue;
        };
        if vk_digest == evidence.artifacts.verification_key().digest() {
            continue;
        }
        if first_existing.is_none() {
            first_existing = Some(*candidate);
        }
        if proof_len == expected_len {
            return Ok(*candidate);
        }
    }
    first_existing.ok_or(MatrixError::MissingField)
}

fn candidate_artifact_summary(
    candidate_dir: &Path,
) -> Result<Option<(usize, Digest32)>, MatrixError> {
    let proof_path = candidate_dir.join("proof");
    let metadata = match fs::metadata(proof_path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MatrixError::Io(error)),
    };
    let proof_len = usize::try_from(metadata.len()).map_err(|_| MatrixError::UnexpectedLength)?;
    let vk_bytes = match fs::read(candidate_dir.join("vk")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MatrixError::Io(error)),
    };
    let vk_digest = Digest32::sha256(vk_bytes.as_slice());
    Ok(Some((proof_len, vk_digest)))
}

fn flip_nonce(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    let Some(first) = binding.nonce_hash.first_mut() else {
        return Err(MatrixError::UnexpectedLength);
    };
    *first ^= 1;
    Ok(binding)
}

fn flip_audience(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    let Some(first) = binding.audience_hash.first_mut() else {
        return Err(MatrixError::UnexpectedLength);
    };
    *first ^= 1;
    Ok(binding)
}

fn flip_transaction(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    let transaction_data_hash = binding
        .transaction_data_hash
        .as_mut()
        .ok_or(MatrixError::MissingField)?;
    let Some(first) = transaction_data_hash.first_mut() else {
        return Err(MatrixError::UnexpectedLength);
    };
    *first ^= 1;
    Ok(binding)
}

fn remove_transaction(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    if binding.transaction_data_hash.is_none() {
        return Err(MatrixError::MissingField);
    }
    binding.transaction_data_hash = None;
    Ok(binding)
}

fn use_absence_sentinel_as_transaction(mut binding: ZkSessionBinding) -> ZkSessionBinding {
    binding.transaction_data_hash = Some(ABSENT_TRANSACTION_DATA_HASH);
    binding
}

fn expect_invalid_proof_for_same_length_tamper(
    backend: &reallyme_zk_backend_bb::NativeBarretenbergBackend,
    evidence: &CircuitEvidence,
    proof: &ZkProof,
    binding: ZkSessionBinding,
) -> Result<ZkErrorReason, MatrixError> {
    let proof_len = proof.proof_bytes().len();
    let mut last_reason = None;
    let mut offset = BARRETENBERG_FIELD_BYTES
        .checked_sub(1)
        .ok_or(MatrixError::UnexpectedLength)?;
    while offset < proof_len {
        let tampered = tamper_proof_same_length_at(evidence, proof, offset)?;
        match backend.verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref: evidence.circuit_ref,
            proof_suite: ZkProofSuite::PRODUCTION,
            artifact_identity: (evidence.artifact_identity).into(),
            artifacts: &evidence.artifacts,
            proof: &tampered,
            expected_binding: binding,
        }) {
            Ok(()) => {
                return Err(MatrixError::UnexpectedErrorReason {
                    expected: ZkErrorReason::InvalidProof,
                    actual: None,
                });
            }
            Err(error) if error.reason() == ZkErrorReason::InvalidProof => {
                return Ok(error.reason());
            }
            Err(error) => {
                last_reason = Some(error.reason());
            }
        }
        offset = offset
            .checked_add(BARRETENBERG_FIELD_BYTES)
            .ok_or(MatrixError::UnexpectedLength)?;
    }
    Err(MatrixError::UnexpectedErrorReason {
        expected: ZkErrorReason::InvalidProof,
        actual: last_reason,
    })
}

fn tamper_proof_same_length_at(
    evidence: &CircuitEvidence,
    proof: &ZkProof,
    offset: usize,
) -> Result<ZkProof, MatrixError> {
    let mut proof_bytes = proof.proof_bytes().to_vec();
    let byte = proof_bytes
        .get_mut(offset)
        .ok_or(MatrixError::UnexpectedLength)?;
    *byte ^= 1;
    ZkProof::try_from_exact_parts(
        evidence.circuit_ref.circuit_id(),
        evidence.circuit_ref,
        ZkProofSuite::PRODUCTION,
        evidence.artifact_identity,
        proof_bytes,
        ZkPublicInputs::try_copy_from_slice(evidence.public_inputs.as_bytes())?,
    )
    .map_err(MatrixError::from)
}

fn tamper_proof_malformed_length(
    evidence: &CircuitEvidence,
    proof: &ZkProof,
) -> Result<ZkProof, MatrixError> {
    let mut proof_bytes = proof.proof_bytes().to_vec();
    proof_bytes
        .try_reserve_exact(1)
        .map_err(|_| MatrixError::UnexpectedLength)?;
    proof_bytes.push(0);
    ZkProof::try_from_exact_parts(
        evidence.circuit_ref.circuit_id(),
        evidence.circuit_ref,
        ZkProofSuite::PRODUCTION,
        evidence.artifact_identity,
        proof_bytes,
        ZkPublicInputs::try_copy_from_slice(evidence.public_inputs.as_bytes())?,
    )
    .map_err(MatrixError::from)
}

fn tamper_public_inputs(
    evidence: &CircuitEvidence,
    proof: &ZkProof,
) -> Result<ZkProof, MatrixError> {
    let mut public_inputs = proof.public_inputs().as_bytes().to_vec();
    let expiry_range = ZkPublicInputDescriptor::for_circuit(evidence.circuit_ref)?
        .field_range(ZkPublicInputName::ExpiryUnix)?;
    let last = public_inputs
        .get_mut(expiry_range)
        .ok_or(MatrixError::UnexpectedLength)?
        .last_mut()
        .ok_or(MatrixError::UnexpectedLength)?;
    *last ^= 1;
    ZkProof::try_from_exact_parts(
        evidence.circuit_ref.circuit_id(),
        evidence.circuit_ref,
        ZkProofSuite::PRODUCTION,
        evidence.artifact_identity,
        proof.proof_bytes().to_vec(),
        ZkPublicInputs::try_from_bytes(public_inputs)?,
    )
    .map_err(MatrixError::from)
}

fn expect_reason(
    result: Result<(), ZkError>,
    expected: ZkErrorReason,
) -> Result<ZkErrorReason, MatrixError> {
    match result {
        Ok(()) => Err(MatrixError::UnexpectedErrorReason {
            expected,
            actual: None,
        }),
        Err(error) if error.reason() == expected => Ok(error.reason()),
        Err(error) => Err(MatrixError::UnexpectedErrorReason {
            expected,
            actual: Some(error.reason()),
        }),
    }
}

fn expect_one_of(
    result: Result<(), ZkError>,
    expected: &[ZkErrorReason],
) -> Result<ZkErrorReason, MatrixError> {
    match result {
        Ok(()) => Err(MatrixError::UnexpectedErrorReason {
            expected: expected.first().copied().ok_or(MatrixError::MissingField)?,
            actual: None,
        }),
        Err(error) if expected.contains(&error.reason()) => Ok(error.reason()),
        Err(error) => Err(MatrixError::UnexpectedErrorReason {
            expected: expected.first().copied().ok_or(MatrixError::MissingField)?,
            actual: Some(error.reason()),
        }),
    }
}

fn alternate_circuit_ref(circuit_ref: ZkCircuitRef) -> Result<ZkCircuitRef, MatrixError> {
    retained_request_bound_circuit_refs()
        .copied()
        .find(|candidate| *candidate != circuit_ref)
        .ok_or(MatrixError::MissingField)
}

fn alternate_artifact_identity(artifact_identity: ZkArtifactSetIdentity) -> ZkArtifactSetIdentity {
    let mut bytes = *artifact_identity.as_bytes();
    bytes[0] ^= 1;
    ZkArtifactSetIdentity::from_bytes(bytes)
}
