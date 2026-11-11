// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{Message, MessageField};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::{Zeroize, Zeroizing};

mod common_credential_root;
mod persona_credential_evidence;
mod request;
mod stage_witness_input;

use common_credential_root::zeroize_common_credential_root_verify_operation_proto;
pub(crate) use common_credential_root::{
    zeroize_common_credential_root_presentation_prove_operation_proto,
    zeroize_common_credential_root_stage_prove_operation_proto,
};
pub(super) use common_credential_root::{
    CommonCredentialRootPresentationProveOperationGuard,
    CommonCredentialRootStageProveOperationGuard, CommonCredentialRootVerifyOperationGuard,
};
pub(super) use persona_credential_evidence::zeroize_prepared_claim_root_prove_operation_proto;
use persona_credential_evidence::zeroize_prepared_current_state_prove_operation_proto;
pub(super) use persona_credential_evidence::zeroize_prepared_issuer_envelope_prove_operation_proto;
pub(super) use persona_credential_evidence::zeroize_prepared_selected_claim_prove_operation_proto;
pub(super) use persona_credential_evidence::zeroize_prepared_signed_validity_prove_operation_proto;
use persona_credential_evidence::{
    zeroize_prepared_assemble_operation_proto, zeroize_prepared_signing_operation_proto,
};
pub(super) use persona_credential_evidence::{
    zeroize_prepared_current_state_credential_proto, zeroize_prepared_current_status_proto,
    PersonaCredentialEvidenceCurrentStateProveOperationGuard,
};
pub(super) use request::zeroize_operation_request_proto;
pub(super) use stage_witness_input::zeroize_stage_witness_input_proto;

pub(super) struct OperationRequestGuard {
    request: pb::ZkProviderOperationRequest,
}

impl OperationRequestGuard {
    pub(super) const fn new(request: pb::ZkProviderOperationRequest) -> Self {
        Self { request }
    }

    pub(super) const fn as_ref(&self) -> &pb::ZkProviderOperationRequest {
        &self.request
    }

    pub(super) fn into_inner(mut self) -> pb::ZkProviderOperationRequest {
        core::mem::take(&mut self.request)
    }

    pub(super) fn take_operation(
        &mut self,
    ) -> Option<pb::zk_provider_operation_request::Operation> {
        self.request.operation.take()
    }
}

impl Drop for OperationRequestGuard {
    fn drop(&mut self) {
        zeroize_operation_request_proto(&mut self.request);
    }
}

pub(super) struct BundleProveOperationGuard {
    operation: pb::ZkClaimProofBundleProveOperation,
}

impl BundleProveOperationGuard {
    pub(super) const fn new(operation: pb::ZkClaimProofBundleProveOperation) -> Self {
        Self { operation }
    }

    pub(super) fn bundle_kind(&self) -> buffa::EnumValue<pb::ZkClaimProofBundleKind> {
        self.operation.bundle_kind
    }

    pub(super) fn credential_hash_algorithm(
        &self,
    ) -> buffa::EnumValue<pb::ZkCredentialHashAlgorithm> {
        self.operation.credential_hash_algorithm
    }

    pub(super) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(super) fn take_witness_bundle(&mut self) -> Option<pb::ZkClaimProofBundleWitness> {
        self.operation.witness_bundle.take()
    }

    pub(super) fn take_session_binding(
        &mut self,
    ) -> buffa::MessageField<pb::ZkSessionBinding, buffa::Inline<pb::ZkSessionBinding>> {
        core::mem::take(&mut self.operation.session_binding)
    }
}

impl Drop for BundleProveOperationGuard {
    fn drop(&mut self) {
        zeroize_claim_proof_bundle_prove_operation_proto(&mut self.operation);
    }
}

pub(super) struct RetainedClaimProofBundleProveOperationGuard {
    operation: pb::ZkRetainedClaimProofBundleProveOperation,
}

impl RetainedClaimProofBundleProveOperationGuard {
    pub(super) const fn new(operation: pb::ZkRetainedClaimProofBundleProveOperation) -> Self {
        Self { operation }
    }

    pub(super) fn bundle_kind(&self) -> buffa::EnumValue<pb::ZkClaimProofBundleKind> {
        self.operation.bundle_kind
    }

    pub(super) fn credential_hash_algorithm(
        &self,
    ) -> buffa::EnumValue<pb::ZkCredentialHashAlgorithm> {
        self.operation.credential_hash_algorithm
    }

    pub(super) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(super) fn take_witness_bundle(&mut self) -> Option<pb::ZkRetainedClaimProofBundleWitness> {
        self.operation.witness_bundle.take()
    }

    pub(super) fn take_session_binding(
        &mut self,
    ) -> buffa::MessageField<pb::ZkSessionBinding, buffa::Inline<pb::ZkSessionBinding>> {
        core::mem::take(&mut self.operation.session_binding)
    }
}

impl Drop for RetainedClaimProofBundleProveOperationGuard {
    fn drop(&mut self) {
        zeroize_retained_claim_proof_bundle_prove_operation_proto(&mut self.operation);
    }
}

pub(super) struct StageProveOperationGuard {
    operation: pb::ZkStageProveOperation,
}

pub(super) struct PersonaCredentialEvidenceStageProveOperationGuard {
    operation: pb::ZkPersonaCredentialEvidenceStageProveOperation,
}

impl PersonaCredentialEvidenceStageProveOperationGuard {
    pub(super) const fn new(operation: pb::ZkPersonaCredentialEvidenceStageProveOperation) -> Self {
        Self { operation }
    }

    pub(super) fn mode(&self) -> buffa::EnumValue<pb::ZkPersonaCredentialEvidenceMode> {
        self.operation.mode
    }

    pub(super) fn take_circuit_ref(
        &mut self,
    ) -> buffa::MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.operation.circuit_ref)
    }

    pub(super) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(super) fn take_witness(&mut self) -> Option<pb::ZkWitness> {
        self.operation.witness.take()
    }
}

impl Drop for PersonaCredentialEvidenceStageProveOperationGuard {
    fn drop(&mut self) {
        if let Some(mut witness) = self.operation.witness.take() {
            zeroize_witness_proto(&mut witness);
        }
    }
}

/// Keeps generated witness input under cleanup even when circuit or suite
/// validation fails before the dedicated input owner can take it.
pub(super) struct StageWitnessOperationGuard {
    operation: pb::ZkStageWitnessOperation,
}

impl StageWitnessOperationGuard {
    pub(super) const fn new(operation: pb::ZkStageWitnessOperation) -> Self {
        Self { operation }
    }

    pub(super) fn take_circuit_ref(
        &mut self,
    ) -> buffa::MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.operation.circuit_ref)
    }

    pub(super) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(super) fn take_input(&mut self) -> Option<pb::ZkStageWitnessInput> {
        self.operation.input.take()
    }
}

impl Drop for StageWitnessOperationGuard {
    fn drop(&mut self) {
        zeroize_stage_witness_operation_proto(&mut self.operation);
    }
}

impl StageProveOperationGuard {
    pub(super) const fn new(operation: pb::ZkStageProveOperation) -> Self {
        Self { operation }
    }

    pub(super) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(super) fn take_circuit_ref(
        &mut self,
    ) -> buffa::MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.operation.circuit_ref)
    }

    pub(super) fn take_witness(&mut self) -> Option<pb::ZkWitness> {
        self.operation.witness.take()
    }

    pub(super) fn take_witness_handle(
        &mut self,
    ) -> buffa::MessageField<pb::ZkStageWitnessHandle, buffa::Inline<pb::ZkStageWitnessHandle>>
    {
        core::mem::take(&mut self.operation.witness_handle)
    }

    pub(super) fn take_public_inputs(
        &mut self,
    ) -> buffa::MessageField<pb::ZkPublicInputs, buffa::Inline<pb::ZkPublicInputs>> {
        core::mem::take(&mut self.operation.public_inputs)
    }

    pub(super) fn take_session_binding(
        &mut self,
    ) -> buffa::MessageField<pb::ZkSessionBinding, buffa::Inline<pb::ZkSessionBinding>> {
        core::mem::take(&mut self.operation.session_binding)
    }
}

impl Drop for StageProveOperationGuard {
    fn drop(&mut self) {
        zeroize_stage_prove_operation_proto(&mut self.operation);
    }
}

pub(super) struct ClaimProofBundleWitnessGuard {
    witness_bundle: pb::ZkClaimProofBundleWitness,
}

impl ClaimProofBundleWitnessGuard {
    pub(super) const fn new(witness_bundle: pb::ZkClaimProofBundleWitness) -> Self {
        Self { witness_bundle }
    }

    pub(super) fn bundle_kind(&self) -> buffa::EnumValue<pb::ZkClaimProofBundleKind> {
        self.witness_bundle.bundle_kind
    }

    pub(super) fn credential_hash_algorithm(
        &self,
    ) -> buffa::EnumValue<pb::ZkCredentialHashAlgorithm> {
        self.witness_bundle.credential_hash_algorithm
    }

    pub(super) fn stage_witness_count(&self) -> usize {
        self.witness_bundle.stage_witnesses.len()
    }

    pub(super) fn take_stage_witnesses(&mut self) -> Vec<pb::ZkWitness> {
        core::mem::take(&mut self.witness_bundle.stage_witnesses)
    }
}

impl Drop for ClaimProofBundleWitnessGuard {
    fn drop(&mut self) {
        zeroize_witness_bundle_proto(&mut self.witness_bundle);
    }
}

pub(super) struct RetainedClaimProofBundleWitnessGuard {
    witness_bundle: pb::ZkRetainedClaimProofBundleWitness,
}

impl RetainedClaimProofBundleWitnessGuard {
    pub(super) const fn new(witness_bundle: pb::ZkRetainedClaimProofBundleWitness) -> Self {
        Self { witness_bundle }
    }

    pub(super) fn bundle_kind(&self) -> buffa::EnumValue<pb::ZkClaimProofBundleKind> {
        self.witness_bundle.bundle_kind
    }

    pub(super) fn credential_hash_algorithm(
        &self,
    ) -> buffa::EnumValue<pb::ZkCredentialHashAlgorithm> {
        self.witness_bundle.credential_hash_algorithm
    }

    pub(super) fn stage_witness_handle_count(&self) -> usize {
        self.witness_bundle.stage_witness_handles.len()
    }

    pub(super) fn take_stage_witness_handles(&mut self) -> Vec<pb::ZkStageWitnessHandle> {
        core::mem::take(&mut self.witness_bundle.stage_witness_handles)
    }
}

impl Drop for RetainedClaimProofBundleWitnessGuard {
    fn drop(&mut self) {
        self.witness_bundle.clear();
    }
}

pub(super) struct StageWitnessesGuard {
    witnesses: Vec<pb::ZkWitness>,
}

impl StageWitnessesGuard {
    pub(super) const fn new(witnesses: Vec<pb::ZkWitness>) -> Self {
        Self { witnesses }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    pub(super) fn take_next(&mut self) -> Option<pb::ZkWitness> {
        if self.witnesses.is_empty() {
            None
        } else {
            Some(self.witnesses.remove(0))
        }
    }
}

impl Drop for StageWitnessesGuard {
    fn drop(&mut self) {
        for witness in &mut self.witnesses {
            zeroize_witness_proto(witness);
        }
    }
}

pub(super) struct StageWitnessHandlesGuard {
    handles: Vec<pb::ZkStageWitnessHandle>,
}

impl StageWitnessHandlesGuard {
    pub(super) const fn new(handles: Vec<pb::ZkStageWitnessHandle>) -> Self {
        Self { handles }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub(super) fn take_next(&mut self) -> Option<pb::ZkStageWitnessHandle> {
        if self.handles.is_empty() {
            None
        } else {
            Some(self.handles.remove(0))
        }
    }
}

impl Drop for StageWitnessHandlesGuard {
    fn drop(&mut self) {
        for handle in &mut self.handles {
            handle.clear();
        }
    }
}

pub(super) struct WitnessGuard {
    witness: pb::ZkWitness,
}

impl WitnessGuard {
    pub(super) const fn new(witness: pb::ZkWitness) -> Self {
        Self { witness }
    }

    pub(super) fn take_circuit_ref(
        &mut self,
    ) -> buffa::MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.witness.circuit_ref)
    }

    pub(super) fn encoding(&self) -> buffa::EnumValue<pb::ZkWitnessEncoding> {
        self.witness.encoding
    }

    pub(super) fn take_encoded_zeroizing(&mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut self.witness.encoded))
    }
}

impl Drop for WitnessGuard {
    fn drop(&mut self) {
        zeroize_witness_proto(&mut self.witness);
    }
}

pub(super) fn zeroize_claim_proof_bundle_prove_operation_proto(
    operation: &mut pb::ZkClaimProofBundleProveOperation,
) {
    if let Some(mut witness_bundle) = operation.witness_bundle.take() {
        zeroize_witness_bundle_proto(&mut witness_bundle);
    }
}

pub(super) fn zeroize_retained_claim_proof_bundle_prove_operation_proto(
    operation: &mut pb::ZkRetainedClaimProofBundleProveOperation,
) {
    operation.clear();
}

pub(super) fn zeroize_stage_prove_operation_proto(operation: &mut pb::ZkStageProveOperation) {
    if let Some(mut witness) = operation.witness.take() {
        zeroize_witness_proto(&mut witness);
    }
}

pub(super) fn zeroize_stage_witness_operation_proto(operation: &mut pb::ZkStageWitnessOperation) {
    if let Some(mut input) = operation.input.take() {
        zeroize_stage_witness_input_proto(&mut input);
        operation.input = MessageField::some(input);
    }
}

fn zeroize_witness_bundle_proto(witness_bundle: &mut pb::ZkClaimProofBundleWitness) {
    for witness in &mut witness_bundle.stage_witnesses {
        zeroize_witness_proto(witness);
    }
}

fn zeroize_witness_proto(witness: &mut pb::ZkWitness) {
    witness.encoded.zeroize();
}

#[cfg(test)]
mod tests;
