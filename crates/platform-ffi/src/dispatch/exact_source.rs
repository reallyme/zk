// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Diagnostic exact-source dispatch for imported `claim_bundle_4` circuits.

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProofSuite},
};
use reallyme_zk_backend_bb::{BbExactCircuitProveRequest, BbExactCircuitVerifyRequest};
use reallyme_zk_proto_codec::{
    operation::ZkStageWitnessSource,
    result::{encode_stage_proof_response, encode_stage_verification_response},
};
use zeroize::Zeroizing;

use crate::context::PlatformContext;

pub(super) fn prove_claim_bundle4_exact_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    circuit_ref: reallyme_zk_api::circuits::ZkCircuitRef,
    proof_suite: ZkProofSuite,
    witness_source: ZkStageWitnessSource,
    public_inputs: &reallyme_zk_api::proofs::ZkPublicInputs,
    session_binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let retained_witness;
    let witness = match witness_source {
        ZkStageWitnessSource::Raw(witness) => {
            retained_witness = witness;
            &retained_witness
        }
        ZkStageWitnessSource::NativeHandle(_) => {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
    };
    let artifacts = context.claim_bundle4_exact_artifacts(circuit_ref, proof_suite)?;
    let response = context
        .backend()
        .prove_exact_circuit(BbExactCircuitProveRequest {
            circuit_ref,
            proof_suite,
            artifact_identity: artifacts.artifact_identity(),
            artifacts: &artifacts,
            witness,
            session_binding,
        })?;
    if response.public_inputs().as_bytes() != public_inputs.as_bytes() {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let (proof_bytes, returned_public_inputs) = response.into_parts();
    let proof = ZkProof::try_from_exact_bounded_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        proof_suite,
        artifacts.artifact_identity(),
        proof_bytes,
        returned_public_inputs,
    )?;
    encode_stage_proof_response(request_bytes, &proof)
}

pub(super) fn verify_claim_bundle4_exact_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    proof: &ZkProof,
    expected_proof_suite: ZkProofSuite,
    expected_binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let circuit_ref = proof.circuit_ref();
    let artifacts = context.claim_bundle4_exact_artifacts(circuit_ref, expected_proof_suite)?;
    context
        .backend()
        .verify_exact_circuit(BbExactCircuitVerifyRequest {
            circuit_ref,
            proof_suite: expected_proof_suite,
            artifact_identity: artifacts.artifact_identity(),
            artifacts: &artifacts,
            proof,
            expected_binding,
        })?;
    encode_stage_verification_response(request_bytes, proof)
}
