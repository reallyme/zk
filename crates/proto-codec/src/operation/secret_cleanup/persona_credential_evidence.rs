// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroize;

pub(in crate::operation) struct PersonaCredentialEvidenceCurrentStateProveOperationGuard {
    operation: pb::ZkPersonaCredentialEvidenceCurrentStateProveOperation,
}

impl PersonaCredentialEvidenceCurrentStateProveOperationGuard {
    pub(in crate::operation) const fn new(
        operation: pb::ZkPersonaCredentialEvidenceCurrentStateProveOperation,
    ) -> Self {
        Self { operation }
    }

    pub(in crate::operation) fn mode(
        &self,
    ) -> buffa::EnumValue<pb::ZkPersonaCredentialEvidenceMode> {
        self.operation.mode
    }

    pub(in crate::operation) fn take_circuit_ref(
        &mut self,
    ) -> MessageField<pb::ZkCircuitRef, buffa::Inline<pb::ZkCircuitRef>> {
        core::mem::take(&mut self.operation.circuit_ref)
    }

    pub(in crate::operation) fn proof_suite(&self) -> buffa::EnumValue<pb::ZkProofSuite> {
        self.operation.proof_suite
    }

    pub(in crate::operation) fn take_evidence_proof_set(
        &mut self,
    ) -> Option<pb::ZkPersonaCredentialEvidenceProofSet> {
        self.operation.evidence_proof_set.take()
    }

    pub(in crate::operation) fn take_credential(
        &mut self,
    ) -> Option<pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput> {
        self.operation.credential.take()
    }

    pub(in crate::operation) fn take_current_status(
        &mut self,
    ) -> Option<pb::ZkPersonaCredentialEvidenceCurrentStatusInput> {
        self.operation.current_status.take()
    }

    pub(in crate::operation) const fn verification_time_unix(&self) -> u64 {
        self.operation.verification_time_unix
    }
}

impl Drop for PersonaCredentialEvidenceCurrentStateProveOperationGuard {
    fn drop(&mut self) {
        zeroize_prepared_current_state_prove_operation_proto(&mut self.operation);
    }
}

pub(super) fn zeroize_prepared_current_state_prove_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidenceCurrentStateProveOperation,
) {
    if let Some(mut evidence) = operation.evidence_proof_set.take() {
        zeroize_persona_credential_evidence_proof_set_proto(&mut evidence);
        operation.evidence_proof_set = MessageField::some(evidence);
    }
    if let Some(mut credential) = operation.credential.take() {
        zeroize_prepared_current_state_credential_proto(&mut credential);
        operation.credential = MessageField::some(credential);
    }
    if let Some(mut status) = operation.current_status.take() {
        zeroize_prepared_current_status_proto(&mut status);
        operation.current_status = MessageField::some(status);
    }
}

pub(in crate::operation) fn zeroize_prepared_issuer_envelope_prove_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation,
) {
    zeroize_input_p256_public_key(&mut operation.issuer_public_key);
    zeroize_input_p256_public_key(&mut operation.holder_public_key);
    zeroize_input_bytes32(&mut operation.token_nonce);
    zeroize_input_bytes32(&mut operation.credential_binding);
    zeroize_input_bytes32(&mut operation.envelope_hash);
    zeroize_input_bytes32(&mut operation.claims_root);
    zeroize_input_p256_public_key(&mut operation.subject_public_key);
    zeroize_input_bytes64(&mut operation.issuer_envelope_signature);
    zeroize_input_bytes64(&mut operation.issuer_subject_binding_signature);
    operation.evidence_valid_from_unix = 0;
    operation.evidence_valid_until_unix = 0;
}

pub(in crate::operation) fn zeroize_prepared_claim_root_prove_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidenceClaimRootProveOperation,
) {
    zeroize_input_p256_public_key(&mut operation.issuer_public_key);
    zeroize_input_p256_public_key(&mut operation.holder_public_key);
    zeroize_input_bytes32(&mut operation.token_nonce);
    zeroize_input_bytes32(&mut operation.credential_binding);
    zeroize_input_bytes32(&mut operation.envelope_hash);
    zeroize_input_bytes32(&mut operation.claims_root);
    zeroize_input_p256_public_key(&mut operation.subject_public_key);
    zeroize_input_bytes64(&mut operation.issuer_root_binding_signature);
    operation.evidence_valid_from_unix = 0;
    operation.evidence_valid_until_unix = 0;
}

pub(in crate::operation) fn zeroize_prepared_signed_validity_prove_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidenceSignedValidityProveOperation,
) {
    zeroize_input_p256_public_key(&mut operation.issuer_public_key);
    zeroize_input_p256_public_key(&mut operation.holder_public_key);
    zeroize_input_bytes32(&mut operation.token_nonce);
    zeroize_input_bytes32(&mut operation.credential_binding);
    zeroize_input_bytes32(&mut operation.envelope_hash);
    zeroize_input_bytes32(&mut operation.claims_root);
    zeroize_input_p256_public_key(&mut operation.subject_public_key);
    zeroize_input_bytes64(&mut operation.issuer_validity_status_signature);
    zeroize_input_bytes32(&mut operation.status_list_id);
    zeroize_input_bytes32(&mut operation.status_url_hash);
    operation.evidence_valid_from_unix = 0;
    operation.evidence_valid_until_unix = 0;
    operation.valid_from_unix = 0;
    operation.valid_until_unix = 0;
    operation.status_index = 0;
    operation.status_purpose = Default::default();
}

pub(in crate::operation) fn zeroize_prepared_selected_claim_prove_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidenceSelectedClaimProveOperation,
) {
    zeroize_input_p256_public_key(&mut operation.issuer_public_key);
    zeroize_input_p256_public_key(&mut operation.holder_public_key);
    zeroize_input_bytes32(&mut operation.token_nonce);
    if let Some(mut disclosure) = operation.disclosure.take() {
        zeroize_input_bytes32(&mut disclosure.credential_binding);
        zeroize_input_bytes64(&mut disclosure.value);
        zeroize_input_bytes32(&mut disclosure.claim_name_hash);
        disclosure.value_length = 0;
        operation.disclosure = MessageField::some(disclosure);
    }
    if let Some(mut opening) = operation.claim_opening.take() {
        zeroize_input_bytes32(&mut opening.envelope_hash);
        zeroize_input_bytes32(&mut opening.merkle_root);
        if let Some(mut salt) = opening.claim_salt.take() {
            salt.value.zeroize();
            opening.claim_salt = MessageField::some(salt);
        }
        if let Some(mut path) = opening.path.take() {
            for sibling in &mut path.siblings {
                sibling.value.zeroize();
            }
            path.path_length = 0;
            opening.path = MessageField::some(path);
        }
        opening.leaf_index = 0;
        operation.claim_opening = MessageField::some(opening);
    }
    zeroize_input_p256_public_key(&mut operation.subject_public_key);
    zeroize_input_bytes64(&mut operation.issuer_subject_binding_signature);
    zeroize_input_p256_public_key(&mut operation.persona_public_key);
    zeroize_input_bytes64(&mut operation.subject_persona_link_signature);
    zeroize_input_bytes64(&mut operation.persona_token_authorization_signature);
    operation.evidence_valid_from_unix = 0;
    operation.evidence_valid_until_unix = 0;
}

pub(in crate::operation) fn zeroize_persona_credential_evidence_proof_set_proto(
    evidence: &mut pb::ZkPersonaCredentialEvidenceProofSet,
) {
    for slot in [
        &mut evidence.issuer_envelope,
        &mut evidence.claim_root,
        &mut evidence.signed_validity,
        &mut evidence.selected_claim,
    ] {
        if let Some(mut package) = slot.take() {
            zeroize_persona_credential_evidence_stage_proof_package_proto(&mut package);
            *slot = MessageField::some(package);
        }
    }
}

pub(in crate::operation) fn zeroize_persona_credential_evidence_stage_proof_package_proto(
    package: &mut pb::ZkPersonaCredentialEvidenceStageProof,
) {
    package.proof.zeroize();
    if let Some(mut inputs) = package.public_inputs.take() {
        inputs.raw_fields.zeroize();
        package.public_inputs = MessageField::some(inputs);
    }
    if let Some(mut digest) = package.artifact_set_identity_sha256.take() {
        digest.value.zeroize();
        package.artifact_set_identity_sha256 = MessageField::some(digest);
    }
}

pub(in crate::operation) fn zeroize_prepared_signing_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidencePresentationSigningOperation,
) {
    if let Some(mut evidence) = operation.evidence_proof_set.take() {
        zeroize_persona_credential_evidence_proof_set_proto(&mut evidence);
    }
    if let Some(mut status) = operation.current_state.take() {
        zeroize_persona_credential_evidence_stage_proof_package_proto(&mut status);
    }
    if let Some(mut request) = operation.verifier_request.take() {
        zeroize_prepared_verifier_request_proto(&mut request);
    }
}

pub(in crate::operation) fn zeroize_prepared_assemble_operation_proto(
    operation: &mut pb::ZkPersonaCredentialEvidencePresentationAssembleOperation,
) {
    operation.holder_signature_p256_raw.zeroize();
    if let Some(mut evidence) = operation.evidence_proof_set.take() {
        zeroize_persona_credential_evidence_proof_set_proto(&mut evidence);
    }
    if let Some(mut status) = operation.current_state.take() {
        zeroize_persona_credential_evidence_stage_proof_package_proto(&mut status);
    }
    if let Some(mut request) = operation.verifier_request.take() {
        zeroize_prepared_verifier_request_proto(&mut request);
    }
}

fn zeroize_prepared_verifier_request_proto(
    request: &mut pb::ZkPersonaCredentialEvidenceVerifierRequestV1,
) {
    request.nonce.zeroize();
    request.audience_sha256.zeroize();
    request.transaction_data_sha256.zeroize();
    request.requested_claims_sha256.zeroize();
    request.verifier_policy_sha256.zeroize();
    request.transport_context_sha256.zeroize();
}

pub(in crate::operation) fn zeroize_prepared_current_state_credential_proto(
    credential: &mut pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput,
) {
    zeroize_input_bytes32(&mut credential.envelope_hash);
    zeroize_input_bytes32(&mut credential.claims_root);
    zeroize_input_p256_public_key(&mut credential.subject_public_key);
    zeroize_input_bytes64(&mut credential.issuer_validity_status_signature);
    credential.valid_from = 0;
    credential.valid_until = 0;
    credential.status_index = 0;
}

pub(in crate::operation) fn zeroize_prepared_current_status_proto(
    status: &mut pb::ZkPersonaCredentialEvidenceCurrentStatusInput,
) {
    zeroize_input_bytes32(&mut status.status_root);
    zeroize_input_bytes32(&mut status.status_list_id);
    zeroize_input_bytes32(&mut status.status_url_hash);
    zeroize_input_bytes32(&mut status.status_chunk);
    for sibling in &mut status.path {
        sibling.value.zeroize();
    }
    status.status_length = 0;
    status.status_purpose = Default::default();
    status.issued_unix = 0;
    status.expires_unix = 0;
    status.path_length = 0;
}

fn zeroize_input_p256_public_key(
    field: &mut MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>>,
) {
    if let Some(mut key) = field.take() {
        zeroize_input_bytes32(&mut key.x);
        zeroize_input_bytes32(&mut key.y);
        *field = MessageField::some(key);
    }
}

fn zeroize_input_bytes32(
    field: &mut MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) {
    if let Some(mut bytes) = field.take() {
        bytes.value.zeroize();
        *field = MessageField::some(bytes);
    }
}

fn zeroize_input_bytes64(
    field: &mut MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>,
) {
    if let Some(mut bytes) = field.take() {
        bytes.value.zeroize();
        *field = MessageField::some(bytes);
    }
}

#[cfg(test)]
#[path = "persona_credential_evidence/tests.rs"]
mod tests;
