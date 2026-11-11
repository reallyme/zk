// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroize;

use crate::common_credential_root::zeroize_common_credential_root_join_policy_proto;

use super::super::common_credential_root_stage::zeroize_common_credential_root_stage_input_proto;

/// Keeps typed common-credential-root proving input under cleanup while request metadata
/// is validated before the dedicated input owner can take it.
pub(in crate::operation) struct CommonCredentialRootStageProveOperationGuard {
    operation: pb::ZkCommonCredentialRootStageProveOperation,
}

/// Keeps the fixed-slot common-credential-root presentation proving request under
/// cleanup until every nested stage input reaches its dedicated owner.
pub(in crate::operation) struct CommonCredentialRootPresentationProveOperationGuard {
    operation: pb::ZkCommonCredentialRootPresentationProveOperation,
}

/// Retains verifier claim values until both the presentation and policy have
/// entered their dedicated domain owners, including on early decode errors.
pub(in crate::operation) struct CommonCredentialRootVerifyOperationGuard {
    operation: pb::ZkCommonCredentialRootVerifyOperation,
}

impl CommonCredentialRootVerifyOperationGuard {
    pub(in crate::operation) const fn new(
        operation: pb::ZkCommonCredentialRootVerifyOperation,
    ) -> Self {
        Self { operation }
    }

    pub(in crate::operation) fn take_presentation(
        &mut self,
    ) -> Option<pb::ZkCommonCredentialRootPresentation> {
        self.operation.presentation.take()
    }

    pub(in crate::operation) fn take_join_policy(
        &mut self,
    ) -> Option<pb::ZkCommonCredentialRootJoinPolicy> {
        self.operation.join_policy.take()
    }

    pub(in crate::operation) fn expected_proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.expected_proof_suite
    }
}

impl Drop for CommonCredentialRootVerifyOperationGuard {
    fn drop(&mut self) {
        zeroize_common_credential_root_verify_operation_proto(&mut self.operation);
    }
}

impl CommonCredentialRootStageProveOperationGuard {
    pub(in crate::operation) const fn new(
        operation: pb::ZkCommonCredentialRootStageProveOperation,
    ) -> Self {
        Self { operation }
    }

    pub(in crate::operation) fn persona_mode(
        &self,
    ) -> buffa::EnumValue<pb::ZkCommonCredentialRootPersonaMode> {
        self.operation.persona_mode
    }

    pub(in crate::operation) fn slot(
        &self,
    ) -> buffa::EnumValue<pb::ZkCommonCredentialRootProofSlot> {
        self.operation.slot
    }

    pub(in crate::operation) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(in crate::operation) fn take_circuit_ref(
        &mut self,
    ) -> buffa::MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.operation.circuit_ref)
    }

    pub(in crate::operation) fn take_expected_binding(
        &mut self,
    ) -> buffa::MessageField<pb::ZkSessionBinding, buffa::Inline<pb::ZkSessionBinding>> {
        core::mem::take(&mut self.operation.expected_binding)
    }

    pub(in crate::operation) fn take_input(
        &mut self,
    ) -> Option<pb::zk_common_credential_root_stage_prove_operation::Input> {
        self.operation.input.take()
    }
}

impl Drop for CommonCredentialRootStageProveOperationGuard {
    fn drop(&mut self) {
        zeroize_common_credential_root_stage_prove_operation_proto(&mut self.operation);
    }
}

impl CommonCredentialRootPresentationProveOperationGuard {
    pub(in crate::operation) const fn new(
        operation: pb::ZkCommonCredentialRootPresentationProveOperation,
    ) -> Self {
        Self { operation }
    }

    pub(in crate::operation) fn persona_mode(
        &self,
    ) -> buffa::EnumValue<pb::ZkCommonCredentialRootPersonaMode> {
        self.operation.persona_mode
    }

    pub(in crate::operation) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(in crate::operation) fn take_expected_binding(
        &mut self,
    ) -> buffa::MessageField<pb::ZkSessionBinding, buffa::Inline<pb::ZkSessionBinding>> {
        core::mem::take(&mut self.operation.expected_binding)
    }

    pub(in crate::operation) fn take_stage(
        &mut self,
        slot: reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot,
    ) -> Option<pb::ZkCommonCredentialRootStageProveOperation> {
        match slot {
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::RootAttestation => {
                self.operation.root_attestation.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::RootStatus => {
                self.operation.root_status.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::Lineage0 => {
                self.operation.lineage_0.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::Lineage1 => {
                self.operation.lineage_1.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::SelectedClaim0 => {
                self.operation.selected_claim_0.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
                self.operation.selected_claim_1.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::Session => {
                self.operation.session.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
                self.operation.issuer_credential_status_0.take()
            }
            reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
                self.operation.issuer_credential_status_1.take()
            }
            _ => None,
        }
    }
}

impl Drop for CommonCredentialRootPresentationProveOperationGuard {
    fn drop(&mut self) {
        zeroize_common_credential_root_presentation_prove_operation_proto(&mut self.operation);
    }
}

pub(crate) fn zeroize_common_credential_root_presentation_prove_operation_proto(
    operation: &mut pb::ZkCommonCredentialRootPresentationProveOperation,
) {
    if let Some(mut binding) = operation.expected_binding.take() {
        binding.nonce_hash.zeroize();
        binding.audience_hash.zeroize();
        binding.transaction_data_hash.zeroize();
        operation.expected_binding = MessageField::some(binding);
    }
    for stage in [
        &mut operation.root_attestation,
        &mut operation.root_status,
        &mut operation.lineage_0,
        &mut operation.lineage_1,
        &mut operation.selected_claim_0,
        &mut operation.selected_claim_1,
        &mut operation.session,
        &mut operation.issuer_credential_status_0,
        &mut operation.issuer_credential_status_1,
    ] {
        if let Some(mut stage_operation) = stage.take() {
            zeroize_common_credential_root_stage_prove_operation_proto(&mut stage_operation);
            *stage = MessageField::some(stage_operation);
        }
    }
}

pub(crate) fn zeroize_common_credential_root_stage_prove_operation_proto(
    operation: &mut pb::ZkCommonCredentialRootStageProveOperation,
) {
    if let Some(mut input) = operation.input.take() {
        zeroize_common_credential_root_stage_input_proto(&mut input);
        operation.input = Some(input);
    }
    if let Some(mut binding) = operation.expected_binding.take() {
        binding.nonce_hash.zeroize();
        binding.audience_hash.zeroize();
        binding.transaction_data_hash.zeroize();
        operation.expected_binding = MessageField::some(binding);
    }
}

pub(super) fn zeroize_common_credential_root_verify_operation_proto(
    operation: &mut pb::ZkCommonCredentialRootVerifyOperation,
) {
    if let Some(mut presentation) = operation.presentation.take() {
        zeroize_common_credential_root_presentation_proto(&mut presentation);
    }
    if let Some(mut policy) = operation.join_policy.take() {
        zeroize_common_credential_root_join_policy_proto(&mut policy);
    }
}

fn zeroize_common_credential_root_presentation_proto(
    presentation: &mut pb::ZkCommonCredentialRootPresentation,
) {
    if let Some(mut binding) = presentation.session_binding.take() {
        binding.nonce_hash.zeroize();
        binding.audience_hash.zeroize();
        binding.transaction_data_hash.zeroize();
    }
    for proof in &mut presentation.proofs {
        proof.proof.zeroize();
        if let Some(mut public_inputs) = proof.public_inputs.take() {
            public_inputs.raw_fields.zeroize();
        }
    }
}
