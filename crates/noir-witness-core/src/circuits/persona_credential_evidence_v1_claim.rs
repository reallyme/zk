// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed witness boundary for both persona credential evidence claim circuits.
//!
//! The public lane authenticates a holder persona directly. The private lane
//! proves hidden persona authorization of a one-time holder key. Both retain
//! the issuer credential opening and claim path only inside `SecretInputs`.

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::abi_encoding::{
    byte_array_matrix_type, byte_array_type, input_value_for_byte_array,
    input_value_for_byte_array_matrix, input_value_for_u32, input_value_for_u64,
    unsigned_integer_type,
};
use crate::circuits::support::{abi_parameter, empty_input_map};
use crate::domain::{
    CompiledProgramArtifactJson, SecretInputs, SerializedWitnessStack, CLAIM_TREE_DEPTH,
    CLAIM_TREE_DEPTH_U32,
};
use crate::execution::generate_witness;
use crate::{WitnessError, WitnessErrorReason};

const CLAIM_VALUE_CAPACITY: usize = 64;
const MAX_CLAIM_INDEX: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PersonaCredentialEvidenceClaimMode {
    Public,
    PrivateOneTime,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidenceV1ClaimPublicInputs {
    pub issuer_x: [u8; 32],
    pub issuer_y: [u8; 32],
    pub holder_x: [u8; 32],
    pub holder_y: [u8; 32],
    pub token_nonce: [u8; 32],
    pub prepared_from: u64,
    pub prepared_until: u64,
    pub credential_binding: [u8; 32],
    pub value_length: u32,
    pub value: [u8; CLAIM_VALUE_CAPACITY],
    pub claim_name_hash: [u8; 32],
}

/// Hidden persona authorization exists only in the one-time-key circuit.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidencePrivatePersonaAuthorization {
    pub persona_x: [u8; 32],
    pub persona_y: [u8; 32],
    pub persona_token_authorization_signature: [u8; 64],
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidenceV1ClaimPrivateInputs {
    pub envelope_hash: [u8; 32],
    pub claims_root: [u8; 32],
    pub issuer_subject_binding_signature: [u8; 64],
    pub subject_x: [u8; 32],
    pub subject_y: [u8; 32],
    pub subject_persona_link_signature: [u8; 64],
    pub private_persona: Option<PersonaCredentialEvidencePrivatePersonaAuthorization>,
    pub claim_salt: [u8; 16],
    pub claim_index: u32,
    pub path_length: u32,
    pub path: [[u8; 32]; CLAIM_TREE_DEPTH],
}

pub struct PersonaCredentialEvidenceV1ClaimInputs {
    pub mode: PersonaCredentialEvidenceClaimMode,
    pub public_inputs: PersonaCredentialEvidenceV1ClaimPublicInputs,
    pub private_inputs: SecretInputs<PersonaCredentialEvidenceV1ClaimPrivateInputs>,
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &PersonaCredentialEvidenceV1ClaimInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    validate_inputs(inputs)?;
    generate_witness(
        artifact_json,
        &expected_abi_parameters(inputs.mode),
        encode_inputs(inputs),
    )
}

fn validate_inputs(inputs: &PersonaCredentialEvidenceV1ClaimInputs) -> Result<(), WitnessError> {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let key_is_zero = |x: &[u8; 32], y: &[u8; 32]| {
        x.iter().all(|byte| *byte == 0) && y.iter().all(|byte| *byte == 0)
    };
    let mode_invalid = match (inputs.mode, private.private_persona.as_ref()) {
        (PersonaCredentialEvidenceClaimMode::Public, None) => false,
        (PersonaCredentialEvidenceClaimMode::PrivateOneTime, Some(persona)) => {
            key_is_zero(&persona.persona_x, &persona.persona_y)
                || persona.persona_x == public.holder_x
        }
        _ => true,
    };
    let used_value_length = usize::try_from(public.value_length)
        .map_err(|_| WitnessError::new(WitnessErrorReason::PreparedClaimInputOutOfRange))?;
    let invalid = mode_invalid
        || key_is_zero(&public.issuer_x, &public.issuer_y)
        || key_is_zero(&public.holder_x, &public.holder_y)
        || key_is_zero(&private.subject_x, &private.subject_y)
        || private.subject_x == public.holder_x
        || public.token_nonce.iter().all(|byte| *byte == 0)
        || public.prepared_from >= public.prepared_until
        || used_value_length == 0
        || used_value_length > CLAIM_VALUE_CAPACITY
        || public.value[used_value_length..]
            .iter()
            .any(|byte| *byte != 0)
        || private.claim_salt.iter().all(|byte| *byte == 0)
        || private.claim_index >= MAX_CLAIM_INDEX
        || private.path_length != CLAIM_TREE_DEPTH_U32;
    if invalid {
        return Err(WitnessError::new(
            WitnessErrorReason::PreparedClaimInputOutOfRange,
        ));
    }
    Ok(())
}

fn expected_abi_parameters(mode: PersonaCredentialEvidenceClaimMode) -> Vec<AbiParameter> {
    let mut parameters = Vec::with_capacity(match mode {
        PersonaCredentialEvidenceClaimMode::Public => 21,
        PersonaCredentialEvidenceClaimMode::PrivateOneTime => 24,
    });
    for name in [
        "pk_issuer_x",
        "pk_issuer_y",
        "holder_x",
        "holder_y",
        "token_nonce",
    ] {
        parameters.push(abi_parameter(
            name,
            byte_array_type(32),
            AbiVisibility::Public,
        ));
    }
    for name in ["prepared_from", "prepared_until"] {
        parameters.push(abi_parameter(
            name,
            unsigned_integer_type(64),
            AbiVisibility::Public,
        ));
    }
    parameters.push(abi_parameter(
        "credential_binding",
        byte_array_type(32),
        AbiVisibility::Public,
    ));
    parameters.push(abi_parameter(
        "val_len",
        unsigned_integer_type(32),
        AbiVisibility::Public,
    ));
    for (name, length) in [("val_pub", 64), ("name_hash", 32)] {
        parameters.push(abi_parameter(
            name,
            byte_array_type(length),
            AbiVisibility::Public,
        ));
    }
    for (name, length) in [
        ("envelope_hash", 32),
        ("merkle_root", 32),
        ("issuer_subject_bind_sig", 64),
        ("pk_subject_x", 32),
        ("pk_subject_y", 32),
    ] {
        parameters.push(abi_parameter(
            name,
            byte_array_type(length),
            AbiVisibility::Private,
        ));
    }
    if mode == PersonaCredentialEvidenceClaimMode::PrivateOneTime {
        for name in ["pk_persona_x", "pk_persona_y"] {
            parameters.push(abi_parameter(
                name,
                byte_array_type(32),
                AbiVisibility::Private,
            ));
        }
    }
    parameters.push(abi_parameter(
        "subject_link_sig",
        byte_array_type(64),
        AbiVisibility::Private,
    ));
    if mode == PersonaCredentialEvidenceClaimMode::PrivateOneTime {
        parameters.push(abi_parameter(
            "persona_token_auth_sig",
            byte_array_type(64),
            AbiVisibility::Private,
        ));
    }
    parameters.push(abi_parameter(
        "salt",
        byte_array_type(16),
        AbiVisibility::Private,
    ));
    for name in ["index", "path_len"] {
        parameters.push(abi_parameter(
            name,
            unsigned_integer_type(32),
            AbiVisibility::Private,
        ));
    }
    parameters.push(abi_parameter(
        "path",
        byte_array_matrix_type(CLAIM_TREE_DEPTH_U32, 32),
        AbiVisibility::Private,
    ));
    parameters
}

fn encode_inputs(inputs: &PersonaCredentialEvidenceV1ClaimInputs) -> InputMap {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let mut input = empty_input_map();
    for (name, value) in [
        ("pk_issuer_x", &public.issuer_x),
        ("pk_issuer_y", &public.issuer_y),
        ("holder_x", &public.holder_x),
        ("holder_y", &public.holder_y),
        ("token_nonce", &public.token_nonce),
        ("credential_binding", &public.credential_binding),
        ("name_hash", &public.claim_name_hash),
    ] {
        input.insert(String::from(name), input_value_for_byte_array(value));
    }
    input.insert(
        String::from("prepared_from"),
        input_value_for_u64(public.prepared_from),
    );
    input.insert(
        String::from("prepared_until"),
        input_value_for_u64(public.prepared_until),
    );
    input.insert(
        String::from("val_len"),
        input_value_for_u32(public.value_length),
    );
    input.insert(
        String::from("val_pub"),
        input_value_for_byte_array(&public.value),
    );
    for (name, value) in [
        ("envelope_hash", &private.envelope_hash),
        ("merkle_root", &private.claims_root),
        ("pk_subject_x", &private.subject_x),
        ("pk_subject_y", &private.subject_y),
    ] {
        input.insert(String::from(name), input_value_for_byte_array(value));
    }
    input.insert(
        String::from("issuer_subject_bind_sig"),
        input_value_for_byte_array(&private.issuer_subject_binding_signature),
    );
    input.insert(
        String::from("subject_link_sig"),
        input_value_for_byte_array(&private.subject_persona_link_signature),
    );
    if let Some(persona) = private.private_persona.as_ref() {
        input.insert(
            String::from("pk_persona_x"),
            input_value_for_byte_array(&persona.persona_x),
        );
        input.insert(
            String::from("pk_persona_y"),
            input_value_for_byte_array(&persona.persona_y),
        );
        input.insert(
            String::from("persona_token_auth_sig"),
            input_value_for_byte_array(&persona.persona_token_authorization_signature),
        );
    }
    input.insert(
        String::from("salt"),
        input_value_for_byte_array(&private.claim_salt),
    );
    input.insert(
        String::from("index"),
        input_value_for_u32(private.claim_index),
    );
    input.insert(
        String::from("path_len"),
        input_value_for_u32(private.path_length),
    );
    input.insert(
        String::from("path"),
        input_value_for_byte_array_matrix(&private.path),
    );
    input
}

#[cfg(test)]
#[path = "persona_credential_evidence_v1_claim/tests.rs"]
mod tests;
