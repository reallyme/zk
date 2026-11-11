// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical provider-operation decoding and strict domain conversion.

use buffa::{DecodeOptions, Message};
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkPublicInputs, ZkWitness, MAX_PROOF_BYTES, MAX_WITNESS_BYTES},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

use crate::binding::session_binding_from_proto_message;
use crate::common_credential_root::{
    common_credential_root_join_policy_from_proto, common_credential_root_presentation_from_proto,
};
use crate::domain::{circuit_ref_from_proto_message, proof_suite_from_proto};
use crate::proof::exact_proof_from_proto;
use crate::protojson::{zk_proto_from_json, ZkProtoJsonError};

pub use crate::protojson::MAX_ZK_PROTO_JSON_BYTES;

mod artifact;
mod bundle;
mod common_credential_root_prove;
mod common_credential_root_stage;
mod native_handle;
mod persona_credential_evidence;
mod provider_operation;
mod secret_cleanup;
mod witness_input;

use artifact::artifact_operation_from_proto;
pub use common_credential_root_prove::ZkCommonCredentialRootStageProveRequest;
pub use common_credential_root_stage::ZkCommonCredentialRootStageInputOwner;
pub use native_handle::{ZkNativeStageWitnessHandle, ZkStageWitnessSource};
use persona_credential_evidence::{
    assemble_persona_credential_evidence_presentation_from_proto,
    prepare_persona_credential_evidence_presentation_signing_from_proto,
    prove_persona_credential_evidence_claim_root_from_proto,
    prove_persona_credential_evidence_current_state_from_proto,
    prove_persona_credential_evidence_issuer_envelope_from_proto,
    prove_persona_credential_evidence_selected_claim_from_proto,
    prove_persona_credential_evidence_signed_validity_from_proto,
    prove_persona_credential_evidence_stage_from_proto,
    verify_persona_credential_evidence_stage_from_proto,
};
pub use persona_credential_evidence::{
    ZkPersonaCredentialEvidenceClaimRootProveRequest,
    ZkPersonaCredentialEvidenceCurrentStateProveRequest,
    ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest,
    ZkPersonaCredentialEvidencePresentationInput,
    ZkPersonaCredentialEvidenceSelectedClaimProveRequest,
    ZkPersonaCredentialEvidenceSignedValidityProveRequest,
};
pub use provider_operation::ZkProviderOperation;
/// Owns a generated provider request and clears nested private inputs on drop.
///
/// This owner is for adapters that must inspect or encode a generated request
/// before the normal decoder transfers it into domain-owned witness buffers.
/// Callers must also clear every encoded copy after dispatch.
pub struct ZkSensitiveProviderRequest {
    request: pb::ZkProviderOperationRequest,
}

impl ZkSensitiveProviderRequest {
    /// Takes ownership of a generated provider request.
    pub const fn new(request: pb::ZkProviderOperationRequest) -> Self {
        Self { request }
    }

    /// Borrows the generated request for encoding.
    #[must_use]
    pub const fn request(&self) -> &pb::ZkProviderOperationRequest {
        &self.request
    }

    /// Borrows the generated request while constructing a stage witness.
    pub fn request_mut(&mut self) -> &mut pb::ZkProviderOperationRequest {
        &mut self.request
    }
}

impl Drop for ZkSensitiveProviderRequest {
    fn drop(&mut self) {
        secret_cleanup::zeroize_operation_request_proto(&mut self.request);
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) fn zeroize_common_credential_root_presentation_prove_operation_proto(
    operation: &mut pb::ZkCommonCredentialRootPresentationProveOperation,
) {
    secret_cleanup::zeroize_common_credential_root_presentation_prove_operation_proto(operation);
}

#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) fn zeroize_common_credential_root_stage_prove_operation_proto(
    operation: &mut pb::ZkCommonCredentialRootStageProveOperation,
) {
    secret_cleanup::zeroize_common_credential_root_stage_prove_operation_proto(operation);
}

/// Encode a generated provider request into canonical binary protobuf bytes.
///
/// SDK adapters use this after constructing a typed Buffa operation envelope
/// and before handing it to a concrete native, WASM, or platform transport.
/// Remote dispatch of private witness bytes requires a separate explicit trust
/// and consent policy. The request owner is consumed so nested private fields are wiped
/// after encoding; callers must also wipe the returned bytes immediately after
/// dispatch.
pub fn encode_sensitive_operation_request(
    request: ZkSensitiveProviderRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    encode_canonical_operation(request.request())
}

use bundle::{
    prove_claim_proof_bundle_from_proto, prove_retained_claim_proof_bundle_from_proto,
    verify_claim_proof_bundle_from_proto, verify_status_qualified_claim_proof_bundle_from_proto,
};
use common_credential_root_prove::{
    prove_common_credential_root_presentation_from_proto,
    prove_common_credential_root_stage_from_proto,
};
use native_handle::{stage_witness_handle_from_proto, stage_witness_handle_from_proto_unbound};
use secret_cleanup::{
    CommonCredentialRootVerifyOperationGuard, OperationRequestGuard, StageProveOperationGuard,
    StageWitnessOperationGuard, WitnessGuard,
};
pub use witness_input::ZkStageWitnessInputOwner;

const ZK_PROTO_RECURSION_LIMIT: u32 = 32;
const ZK_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
const ZK_CLAIM_PROOF_BUNDLE_STAGE_COUNT: usize = 4;
const ZK_PROTO_ENVELOPE_OVERHEAD_BYTES: usize = 3 * 1024 * 1024;

/// Maximum binary canonical operation size.
///
/// A verification request can contain four maximum-size proofs. The remaining
/// allowance covers public inputs and protobuf framing without making the
/// executable boundary unbounded.
pub const MAX_ZK_PROTO_OPERATION_BYTES: usize = (MAX_PROOF_BYTES
    * ZK_CLAIM_PROOF_BUNDLE_STAGE_COUNT)
    + (MAX_WITNESS_BYTES * ZK_CLAIM_PROOF_BUNDLE_STAGE_COUNT)
    + ZK_PROTO_ENVELOPE_OVERHEAD_BYTES;

const ZK_PROTO_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_PROTO_OPERATION_BYTES;

/// Decodes and converts an untrusted binary canonical operation request.
///
/// Neither the operation envelope converter nor the converters for the
/// payload messages it carries are public, so a caller cannot hand a provider
/// an operation, presentation, or join policy that skipped the size,
/// unknown-field, and canonical-encoding checks applied here:
///
/// ```compile_fail
/// let _ = reallyme_zk_proto_codec::operation::operation_from_proto;
/// ```
///
/// ```compile_fail
/// let _ = reallyme_zk_proto_codec::common_credential_root::common_credential_root_join_policy_from_proto;
/// ```
///
/// The only generated-value conversions that remain public take a single
/// open-enum scalar and admit no message content:
/// `issuer_status::purpose_from_proto` and, with the `stack-error` feature,
/// `stack_error::zk_stack_error_from_proto_reason`.
pub fn decode_operation_request(bytes: &[u8]) -> Result<ZkProviderOperation, ZkError> {
    if bytes.len() > MAX_ZK_PROTO_OPERATION_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }

    let request = DecodeOptions::new()
        .with_recursion_limit(ZK_PROTO_RECURSION_LIMIT)
        .with_unknown_field_limit(ZK_PROTO_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(ZK_PROTO_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_PROTO_OPERATION_BYTES)
        .decode_from_slice::<pb::ZkProviderOperationRequest>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let request = OperationRequestGuard::new(request);
    let canonical = encode_canonical_operation(request.as_ref())?;
    if canonical.as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }

    operation_from_proto(request.into_inner())
}

/// Decodes and converts an untrusted ProtoJSON canonical operation request.
///
/// Proving operations are rejected before deserialization so JSON unescaping
/// cannot create an unmanaged temporary copy of witness material.
pub fn decode_operation_request_json(bytes: &[u8]) -> Result<ZkProviderOperation, ZkError> {
    let request: pb::ZkProviderOperationRequest =
        zk_proto_from_json(bytes).map_err(|error| match error {
            ZkProtoJsonError::JsonTooLarge | ZkProtoJsonError::ProtobufTooLarge => {
                ZkError::new(ZkErrorReason::MessageTooLarge)
            }
            ZkProtoJsonError::JsonDeserialize | ZkProtoJsonError::JsonSerialize => {
                ZkError::new(ZkErrorReason::MalformedJson)
            }
            ZkProtoJsonError::SecretOperationUnsupported => {
                ZkError::new(ZkErrorReason::UnsupportedTransport)
            }
        })?;
    let _canonical = encode_canonical_operation(&request)?;
    operation_from_proto(request)
}

fn encode_canonical_operation(
    request: &pb::ZkProviderOperationRequest,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let maximum = u32::try_from(MAX_ZK_PROTO_OPERATION_BYTES)
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    let encoded_len = request
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
    request
        .try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

/// Converts a generated canonical request after its enclosing boundary has
/// established canonical bytes.
pub(crate) fn operation_from_proto(
    request: pb::ZkProviderOperationRequest,
) -> Result<ZkProviderOperation, ZkError> {
    use pb::zk_provider_operation_request::Operation;

    let mut request = OperationRequestGuard::new(request);
    match request
        .take_operation()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    {
        Operation::ProveClaimProofBundle(operation) => {
            prove_claim_proof_bundle_from_proto(*operation)
        }
        Operation::ProveRetainedClaimProofBundle(operation) => {
            prove_retained_claim_proof_bundle_from_proto(*operation)
        }
        Operation::VerifyClaimProofBundle(operation) => {
            verify_claim_proof_bundle_from_proto(*operation)
        }
        Operation::VerifyStatusQualifiedClaimProofBundle(operation) => {
            verify_status_qualified_claim_proof_bundle_from_proto(*operation)
        }
        Operation::ProveStage(operation) => prove_stage_from_proto(*operation),
        Operation::VerifyStage(operation) => verify_stage_from_proto(*operation),
        Operation::GetArtifactManifest(operation) => artifact_operation_from_proto(*operation),
        Operation::WitnessStage(operation) => witness_stage_from_proto(*operation),
        Operation::ReleaseStageWitness(operation) => release_stage_witness_from_proto(*operation),
        Operation::VerifyCommonCredentialRoot(operation) => {
            verify_common_credential_root_from_proto(*operation)
        }
        Operation::ProveCommonCredentialRootStage(operation) => {
            prove_common_credential_root_stage_from_proto(*operation)
        }
        Operation::ProveCommonCredentialRootPresentation(operation) => {
            prove_common_credential_root_presentation_from_proto(*operation)
        }
        Operation::VerifyPersonaCredentialEvidenceStage(operation) => {
            verify_persona_credential_evidence_stage_from_proto(*operation)
        }
        Operation::ProvePersonaCredentialEvidenceStage(operation) => {
            prove_persona_credential_evidence_stage_from_proto(*operation)
        }
        Operation::ProvePersonaCredentialEvidenceCurrentState(operation) => {
            prove_persona_credential_evidence_current_state_from_proto(*operation)
        }
        Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(operation) => {
            prove_persona_credential_evidence_issuer_envelope_from_proto(*operation)
        }
        Operation::ProvePersonaCredentialEvidenceClaimRoot(operation) => {
            prove_persona_credential_evidence_claim_root_from_proto(*operation)
        }
        Operation::ProvePersonaCredentialEvidenceSignedValidity(operation) => {
            prove_persona_credential_evidence_signed_validity_from_proto(*operation)
        }
        Operation::ProvePersonaCredentialEvidenceSelectedClaim(operation) => {
            prove_persona_credential_evidence_selected_claim_from_proto(*operation)
        }
        Operation::PreparePersonaCredentialEvidencePresentationSigning(operation) => {
            prepare_persona_credential_evidence_presentation_signing_from_proto(*operation)
        }
        Operation::AssemblePersonaCredentialEvidencePresentation(operation) => {
            assemble_persona_credential_evidence_presentation_from_proto(*operation)
        }
    }
}

fn prove_stage_from_proto(
    operation: pb::ZkStageProveOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = StageProveOperationGuard::new(operation);
    let circuit_ref = circuit_ref_from_proto_message(operation.take_circuit_ref())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    let witness = operation.take_witness();
    let mut witness_handle = operation.take_witness_handle();
    let witness_source = match (witness, witness_handle.take()) {
        (Some(witness), None) => {
            ZkStageWitnessSource::Raw(witness_from_proto(witness, circuit_ref)?)
        }
        (None, Some(handle)) => ZkStageWitnessSource::NativeHandle(
            stage_witness_handle_from_proto(handle, circuit_ref)?,
        ),
        (Some(_), Some(_)) => return Err(ZkError::new(ZkErrorReason::MalformedProtobuf)),
        (None, None) => return Err(ZkError::new(ZkErrorReason::EmptyInput)),
    };
    let public_inputs = operation
        .take_public_inputs()
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let mut public_inputs = public_inputs;
    let public_inputs =
        ZkPublicInputs::try_from_bytes(core::mem::take(&mut public_inputs.encoded))?;
    let session_binding = session_binding_from_proto_message(operation.take_session_binding())?;
    session_binding.decode_and_validate(circuit_ref, &public_inputs)?;

    Ok(ZkProviderOperation::ProveStage {
        circuit_ref,
        proof_suite,
        witness_source,
        public_inputs,
        session_binding,
    })
}

fn witness_from_proto(
    witness: pb::ZkWitness,
    expected_ref: ZkCircuitRef,
) -> Result<ZkWitness, ZkError> {
    let mut witness = WitnessGuard::new(witness);
    let circuit_ref = circuit_ref_from_proto_message(witness.take_circuit_ref())?;
    if circuit_ref != expected_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    match witness.encoding().as_known() {
        Some(pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1) => {
            ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
                circuit_ref,
                witness.take_encoded_zeroizing(),
            )
        }
        Some(pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_UNSPECIFIED) | None => {
            Err(ZkError::new(ZkErrorReason::MalformedProtobuf))
        }
    }
}

fn verify_stage_from_proto(
    mut operation: pb::ZkStageVerifyOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let proof = operation
        .proof
        .take()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let proof = exact_proof_from_proto(proof)?;
    let expected_proof_suite = proof_suite_from_proto(operation.expected_proof_suite)?;
    if proof.proof_suite() != expected_proof_suite {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    let expected_binding = session_binding_from_proto_message(operation.expected_binding)?;
    let circuit_ref = proof.circuit_ref();
    expected_binding.decode_and_validate(circuit_ref, proof.public_inputs())?;

    Ok(ZkProviderOperation::VerifyStage {
        proof,
        expected_proof_suite,
        expected_binding,
    })
}

fn witness_stage_from_proto(
    operation: pb::ZkStageWitnessOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = StageWitnessOperationGuard::new(operation);
    let circuit_ref = circuit_ref_from_proto_message(operation.take_circuit_ref())?;
    let proof_suite = proof_suite_from_proto(operation.proof_suite())?;
    let input = operation
        .take_input()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkProviderOperation::WitnessStage {
        circuit_ref,
        proof_suite,
        input: ZkStageWitnessInputOwner::try_new(circuit_ref, input)?,
    })
}

fn release_stage_witness_from_proto(
    mut operation: pb::ZkStageWitnessReleaseOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let handle = operation
        .witness_handle
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(ZkProviderOperation::ReleaseStageWitness {
        witness_handle: stage_witness_handle_from_proto_unbound(handle)?,
    })
}

fn verify_common_credential_root_from_proto(
    operation: pb::ZkCommonCredentialRootVerifyOperation,
) -> Result<ZkProviderOperation, ZkError> {
    let mut operation = CommonCredentialRootVerifyOperationGuard::new(operation);
    let presentation = operation
        .take_presentation()
        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))
        .and_then(common_credential_root_presentation_from_proto)?;
    let expected_proof_suite = proof_suite_from_proto(operation.expected_proof_suite())?;
    if presentation.proof_suite() != expected_proof_suite {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    let join_policy = operation
        .take_join_policy()
        .ok_or(ZkError::new(ZkErrorReason::BindingMismatch))
        .and_then(common_credential_root_join_policy_from_proto)?;
    Ok(ZkProviderOperation::VerifyCommonCredentialRoot {
        presentation: Box::new(presentation),
        join_policy: Box::new(join_policy),
        expected_proof_suite,
    })
}

#[cfg(test)]
mod tests;
