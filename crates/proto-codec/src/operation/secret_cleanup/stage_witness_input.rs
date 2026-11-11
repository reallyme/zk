// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroize;

pub(in crate::operation) fn zeroize_stage_witness_input_proto(input: &mut pb::ZkStageWitnessInput) {
    use pb::zk_stage_witness_input::Input;

    match input.input.as_mut() {
        Some(Input::CredentialSubjectClaimSession(input)) => {
            zeroize_credential_subject_claim_session_input(input)
        }
        Some(Input::PrivatePersonaSession(input)) => {
            zeroize_private_persona_session_input(input);
        }
        Some(Input::CredentialEnvelope(input)) => zeroize_credential_envelope_input(input),
        Some(Input::CredentialRoot(input)) => zeroize_credential_root_input(input),
        Some(Input::CredentialSubjectClaim(input)) => zeroize_credential_subject_claim_input(input),
        Some(Input::PrivatePersonaClaim(input)) => zeroize_private_persona_claim_input(input),
        None => {}
    }
}

fn zeroize_credential_subject_claim_session_input(
    input: &mut pb::ZkCredentialSubjectClaimSessionInput,
) {
    zeroize_session_context(&mut input.session_context);
    if let Some(mut authorization) = input.authorization.take() {
        zeroize_p256_public_key(&mut authorization.subject_public_key);
        zeroize_bytes64(&mut authorization.subject_signature);
        input.authorization = MessageField::some(authorization);
    }
}

fn zeroize_private_persona_session_input(input: &mut pb::ZkPrivatePersonaSessionInput) {
    zeroize_session_context(&mut input.session_context);
    if let Some(mut authorization) = input.authorization.take() {
        zeroize_p256_public_key(&mut authorization.persona_public_key);
        zeroize_bytes64(&mut authorization.persona_signature);
        input.authorization = MessageField::some(authorization);
    }
}

fn zeroize_credential_envelope_input(input: &mut pb::ZkCredentialEnvelopeInput) {
    zeroize_issuer_context(&mut input.issuer_context);
    zeroize_bytes32(&mut input.envelope_binding);
    if let Some(mut proof) = input.proof.take() {
        zeroize_bytes32(&mut proof.envelope_hash);
        zeroize_bytes64(&mut proof.issuer_signature);
        input.proof = MessageField::some(proof);
    }
}

fn zeroize_credential_root_input(input: &mut pb::ZkCredentialRootInput) {
    zeroize_issuer_context(&mut input.issuer_context);
    zeroize_bytes32(&mut input.envelope_binding);
    zeroize_bytes32(&mut input.credential_binding);
    if let Some(mut proof) = input.proof.take() {
        zeroize_bytes32(&mut proof.envelope_hash);
        zeroize_bytes32(&mut proof.merkle_root);
        zeroize_bytes64(&mut proof.issuer_root_binding_signature);
        input.proof = MessageField::some(proof);
    }
}

fn zeroize_credential_subject_claim_input(input: &mut pb::ZkCredentialSubjectClaimInput) {
    zeroize_issuer_context(&mut input.issuer_context);
    zeroize_bytes32(&mut input.session_binding);
    zeroize_claim_disclosure(&mut input.disclosure);
    zeroize_merkle_claim_proof(&mut input.proof);
    if let Some(mut link) = input.link.take() {
        zeroize_bytes64(&mut link.issuer_subject_binding_signature);
        zeroize_p256_public_key(&mut link.subject_public_key);
        input.link = MessageField::some(link);
    }
}

fn zeroize_private_persona_claim_input(input: &mut pb::ZkPrivatePersonaClaimInput) {
    zeroize_issuer_context(&mut input.issuer_context);
    zeroize_bytes32(&mut input.session_binding);
    zeroize_claim_disclosure(&mut input.disclosure);
    zeroize_merkle_claim_proof(&mut input.proof);
    if let Some(mut link) = input.link.take() {
        zeroize_bytes64(&mut link.issuer_subject_binding_signature);
        zeroize_p256_public_key(&mut link.subject_public_key);
        zeroize_p256_public_key(&mut link.persona_public_key);
        zeroize_bytes64(&mut link.subject_link_signature);
        input.link = MessageField::some(link);
    }
}

fn zeroize_session_context(
    field: &mut MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>>,
) {
    if let Some(mut context) = field.take() {
        zeroize_bytes32(&mut context.challenge);
        zeroize_bytes32(&mut context.audience_hash);
        zeroize_bytes32(&mut context.session_binding);
        zeroize_bytes32(&mut context.transaction_data_hash);
        context.expiry_unix = 0;
        *field = MessageField::some(context);
    }
}

fn zeroize_issuer_context(
    field: &mut MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>>,
) {
    if let Some(mut context) = field.take() {
        zeroize_p256_public_key(&mut context.issuer_public_key);
        zeroize_bytes32(&mut context.challenge);
        zeroize_bytes32(&mut context.audience_hash);
        zeroize_bytes32(&mut context.transaction_data_hash);
        context.expiry_unix = 0;
        *field = MessageField::some(context);
    }
}

fn zeroize_claim_disclosure(
    field: &mut MessageField<pb::ZkInputClaimDisclosure, buffa::Inline<pb::ZkInputClaimDisclosure>>,
) {
    if let Some(mut disclosure) = field.take() {
        zeroize_bytes32(&mut disclosure.credential_binding);
        disclosure.value_length = 0;
        zeroize_bytes64(&mut disclosure.value);
        zeroize_bytes32(&mut disclosure.claim_name_hash);
        *field = MessageField::some(disclosure);
    }
}

fn zeroize_merkle_claim_proof(
    field: &mut MessageField<
        pb::ZkInputMerkleClaimProof,
        buffa::Inline<pb::ZkInputMerkleClaimProof>,
    >,
) {
    if let Some(mut proof) = field.take() {
        zeroize_bytes32(&mut proof.envelope_hash);
        zeroize_bytes32(&mut proof.merkle_root);
        zeroize_bytes16(&mut proof.claim_salt);
        proof.leaf_index = 0;
        zeroize_merkle_path(&mut proof.path);
        *field = MessageField::some(proof);
    }
}

fn zeroize_merkle_path(
    field: &mut MessageField<pb::ZkInputMerklePath, buffa::Inline<pb::ZkInputMerklePath>>,
) {
    if let Some(mut path) = field.take() {
        path.path_length = 0;
        for sibling in &mut path.siblings {
            sibling.value.zeroize();
        }
        *field = MessageField::some(path);
    }
}

fn zeroize_p256_public_key(
    field: &mut MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>>,
) {
    if let Some(mut key) = field.take() {
        zeroize_bytes32(&mut key.x);
        zeroize_bytes32(&mut key.y);
        *field = MessageField::some(key);
    }
}

fn zeroize_bytes16(
    field: &mut MessageField<pb::ZkInputBytes16, buffa::Inline<pb::ZkInputBytes16>>,
) {
    if let Some(mut bytes) = field.take() {
        bytes.value.zeroize();
        *field = MessageField::some(bytes);
    }
}

fn zeroize_bytes32(
    field: &mut MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) {
    if let Some(mut bytes) = field.take() {
        bytes.value.zeroize();
        *field = MessageField::some(bytes);
    }
}

fn zeroize_bytes64(
    field: &mut MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>,
) {
    if let Some(mut bytes) = field.take() {
        bytes.value.zeroize();
        *field = MessageField::some(bytes);
    }
}
