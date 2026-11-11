// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Owned witness and proof operations for one request-bound circuit stage.

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProofSuite},
};
use reallyme_zk_backend_bb::{
    BarretenbergArtifactResolver, BbStageProveRequest, BbStageVerifyRequest,
    LinkedBarretenbergBackend,
};
use reallyme_zk_proto_codec::{
    operation::{ZkNativeStageWitnessHandle, ZkStageWitnessInputOwner, ZkStageWitnessSource},
    result::{
        encode_stage_proof_response, encode_stage_verification_response,
        encode_stage_witness_release_response, encode_stage_witness_response,
    },
};
use zeroize::Zeroizing;

use crate::context::{coordinates_for_circuit_ref, PlatformContext, PlatformCrsMode};
use crate::witness::generate_stage_witness;

#[cfg(feature = "diagnostic-exact-source")]
use super::exact_source;

pub(super) fn prove_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    circuit_ref: reallyme_zk_api::circuits::ZkCircuitRef,
    proof_suite: ZkProofSuite,
    witness_source: ZkStageWitnessSource,
    public_inputs: &reallyme_zk_api::proofs::ZkPublicInputs,
    session_binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let (profile, stage) = match coordinates_for_circuit_ref(circuit_ref) {
        Ok(coordinates) => coordinates,
        Err(error) => {
            #[cfg(feature = "diagnostic-exact-source")]
            {
                if error.reason() == ZkErrorReason::UnsupportedCircuit {
                    return exact_source::prove_claim_bundle4_exact_stage(
                        context,
                        request_bytes,
                        circuit_ref,
                        proof_suite,
                        witness_source,
                        public_inputs,
                        session_binding,
                    );
                }
            }
            return Err(error);
        }
    };
    let resolver = context.resolver(profile, circuit_ref.credential_hash_algorithm, proof_suite)?;
    let artifacts = resolver.resolve_stage_artifacts(profile, stage, circuit_ref, proof_suite)?;
    let retained_witness;
    let witness = match witness_source {
        ZkStageWitnessSource::Raw(witness) => {
            retained_witness = witness;
            &retained_witness
        }
        ZkStageWitnessSource::NativeHandle(handle) => {
            retained_witness = context.take_stage_witness(handle.native_handle_id, circuit_ref)?;
            &retained_witness
        }
    };
    let response = context.backend().prove_stage(BbStageProveRequest {
        bundle_kind: profile,
        stage,
        circuit_ref,
        proof_suite,
        artifacts: &artifacts,
        witness,
        session_binding,
    })?;
    if response.public_inputs().as_bytes() != public_inputs.as_bytes() {
        return Err(ZkError::new(ZkErrorReason::BindingMismatch));
    }
    let (proof_bytes, returned_public_inputs) = response.into_parts();
    let proof = ZkProof::try_from_exact_bounded_parts(
        profile.circuit_id(),
        circuit_ref,
        proof_suite,
        artifacts.manifest().manifest_sha256(),
        proof_bytes,
        returned_public_inputs,
    )?;
    encode_stage_proof_response(request_bytes, &proof)
}

pub(super) fn witness_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    circuit_ref: reallyme_zk_api::circuits::ZkCircuitRef,
    proof_suite: ZkProofSuite,
    input: ZkStageWitnessInputOwner,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let (profile, stage) = coordinates_for_circuit_ref(circuit_ref)?;
    let resolver = context.resolver(profile, circuit_ref.credential_hash_algorithm, proof_suite)?;
    let artifacts = resolver.resolve_stage_artifacts(profile, stage, circuit_ref, proof_suite)?;
    let generated = generate_stage_witness(circuit_ref, &artifacts, input)?;
    let session_binding = generated.session_binding;
    let public_inputs = generated.public_inputs;
    let handle_id = context.retain_stage_witness(circuit_ref, generated.witness)?;
    let response = encode_stage_witness_response(
        request_bytes,
        ZkNativeStageWitnessHandle {
            native_handle_id: handle_id,
            circuit_ref,
        },
        &public_inputs,
        session_binding,
    );
    if response.is_err() {
        let _released = context.release_stage_witness(handle_id, circuit_ref);
    }
    response
}

pub(super) fn release_stage_witness(
    context: &PlatformContext,
    request_bytes: &[u8],
    handle: ZkNativeStageWitnessHandle,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    context.release_stage_witness(handle.native_handle_id, handle.circuit_ref)?;
    encode_stage_witness_release_response(request_bytes, handle.circuit_ref)
}

pub(super) fn verify_stage(
    context: &PlatformContext,
    request_bytes: &[u8],
    proof: &ZkProof,
    expected_proof_suite: ZkProofSuite,
    expected_binding: reallyme_zk_api::proofs::ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let circuit_ref = proof.circuit_ref();
    let (profile, stage) = match coordinates_for_circuit_ref(circuit_ref) {
        Ok(coordinates) => coordinates,
        Err(error) => {
            #[cfg(feature = "diagnostic-exact-source")]
            {
                if error.reason() == ZkErrorReason::UnsupportedCircuit {
                    return exact_source::verify_claim_bundle4_exact_stage(
                        context,
                        request_bytes,
                        proof,
                        expected_proof_suite,
                        expected_binding,
                    );
                }
            }
            return Err(error);
        }
    };
    let resolver = context.resolver(
        profile,
        circuit_ref.credential_hash_algorithm,
        expected_proof_suite,
    )?;
    let artifacts = resolver.resolve_stage_verification_artifacts(
        profile,
        stage,
        circuit_ref,
        expected_proof_suite,
    )?;
    context.backend().verify_stage(BbStageVerifyRequest {
        bundle_kind: profile,
        stage,
        circuit_ref,
        proof_suite: expected_proof_suite,
        artifacts: &artifacts,
        proof,
        expected_binding,
    })?;
    encode_stage_verification_response(request_bytes, proof)
}
