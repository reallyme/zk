// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed witness boundary for the immutable issuer validity and status pointer.

use std::collections::BTreeMap;

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::abi_encoding::{
    byte_array_type, input_value_for_byte_array, input_value_for_struct, input_value_for_u32,
    input_value_for_u64, struct_type, unsigned_integer_type,
};
use crate::circuits::support::{abi_parameter, empty_input_map};
use crate::domain::{CompiledProgramArtifactJson, SecretInputs, SerializedWitnessStack};
use crate::execution::generate_witness;
use crate::{WitnessError, WitnessErrorReason};

const MAX_STATUS_INDEX: u64 = 1_000_000;

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidenceV1SignedValidityPublicInputs {
    pub issuer_x: [u8; 32],
    pub issuer_y: [u8; 32],
    pub holder_x: [u8; 32],
    pub holder_y: [u8; 32],
    pub token_nonce: [u8; 32],
    pub prepared_from: u64,
    pub prepared_until: u64,
    pub credential_binding: [u8; 32],
    pub status_list_id: [u8; 32],
    pub status_url_hash: [u8; 32],
    pub status_purpose: u8,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersonaCredentialEvidenceV1SignedValidityPrivateInputs {
    pub envelope_hash: [u8; 32],
    pub claims_root: [u8; 32],
    pub subject_x: [u8; 32],
    pub subject_y: [u8; 32],
    pub issuer_validity_status_signature: [u8; 64],
    pub valid_from: u64,
    pub valid_until: u64,
    pub status_index: u64,
}

pub struct PersonaCredentialEvidenceV1SignedValidityInputs {
    pub public_inputs: PersonaCredentialEvidenceV1SignedValidityPublicInputs,
    pub private_inputs: SecretInputs<PersonaCredentialEvidenceV1SignedValidityPrivateInputs>,
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &PersonaCredentialEvidenceV1SignedValidityInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    validate_inputs(inputs)?;
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn validate_inputs(
    inputs: &PersonaCredentialEvidenceV1SignedValidityInputs,
) -> Result<(), WitnessError> {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let zero_key = |x: &[u8; 32], y: &[u8; 32]| {
        x.iter().all(|byte| *byte == 0) && y.iter().all(|byte| *byte == 0)
    };
    if zero_key(&public.issuer_x, &public.issuer_y)
        || zero_key(&public.holder_x, &public.holder_y)
        || zero_key(&private.subject_x, &private.subject_y)
        || public.token_nonce.iter().all(|byte| *byte == 0)
        || !matches!(public.status_purpose, 1 | 2)
        || private.status_index >= MAX_STATUS_INDEX
        || private.valid_from >= private.valid_until
        || public.prepared_from >= public.prepared_until
        || private.valid_from > public.prepared_from
        || public.prepared_until > private.valid_until
    {
        return Err(WitnessError::new(
            WitnessErrorReason::PreparedStatusInputOutOfRange,
        ));
    }
    Ok(())
}

fn expected_abi_parameters() -> [AbiParameter; 2] {
    [
        abi_parameter(
            "slot",
            struct_type(
                "PublicPreparedValidity",
                vec![
                    ("issuer_x", byte_array_type(32)),
                    ("issuer_y", byte_array_type(32)),
                    ("holder_x", byte_array_type(32)),
                    ("holder_y", byte_array_type(32)),
                    ("token_nonce", byte_array_type(32)),
                    ("prepared_from", unsigned_integer_type(64)),
                    ("prepared_until", unsigned_integer_type(64)),
                    ("credential_binding", byte_array_type(32)),
                    ("status_list_id", byte_array_type(32)),
                    ("status_url_hash", byte_array_type(32)),
                    ("status_purpose", unsigned_integer_type(8)),
                ],
            ),
            AbiVisibility::Public,
        ),
        abi_parameter(
            "witness",
            struct_type(
                "PrivatePreparedValidity",
                vec![
                    ("envelope_hash", byte_array_type(32)),
                    ("claims_root", byte_array_type(32)),
                    ("subject_x", byte_array_type(32)),
                    ("subject_y", byte_array_type(32)),
                    ("issuer_validity_status_signature", byte_array_type(64)),
                    ("valid_from", unsigned_integer_type(64)),
                    ("valid_until", unsigned_integer_type(64)),
                    ("status_index", unsigned_integer_type(64)),
                ],
            ),
            AbiVisibility::Private,
        ),
    ]
}

fn encode_inputs(inputs: &PersonaCredentialEvidenceV1SignedValidityInputs) -> InputMap {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let mut slot = BTreeMap::new();
    for (name, value) in [
        ("issuer_x", &public.issuer_x),
        ("issuer_y", &public.issuer_y),
        ("holder_x", &public.holder_x),
        ("holder_y", &public.holder_y),
        ("token_nonce", &public.token_nonce),
        ("credential_binding", &public.credential_binding),
        ("status_list_id", &public.status_list_id),
        ("status_url_hash", &public.status_url_hash),
    ] {
        slot.insert(String::from(name), input_value_for_byte_array(value));
    }
    slot.insert(
        String::from("prepared_from"),
        input_value_for_u64(public.prepared_from),
    );
    slot.insert(
        String::from("prepared_until"),
        input_value_for_u64(public.prepared_until),
    );
    slot.insert(
        String::from("status_purpose"),
        input_value_for_u32(u32::from(public.status_purpose)),
    );

    let mut witness = BTreeMap::new();
    for (name, value) in [
        ("envelope_hash", &private.envelope_hash),
        ("claims_root", &private.claims_root),
        ("subject_x", &private.subject_x),
        ("subject_y", &private.subject_y),
    ] {
        witness.insert(String::from(name), input_value_for_byte_array(value));
    }
    witness.insert(
        String::from("issuer_validity_status_signature"),
        input_value_for_byte_array(&private.issuer_validity_status_signature),
    );
    for (name, value) in [
        ("valid_from", private.valid_from),
        ("valid_until", private.valid_until),
        ("status_index", private.status_index),
    ] {
        witness.insert(String::from(name), input_value_for_u64(value));
    }
    let mut map = empty_input_map();
    map.insert(String::from("slot"), input_value_for_struct(slot));
    map.insert(String::from("witness"), input_value_for_struct(witness));
    map
}

#[cfg(test)]
#[path = "persona_credential_evidence_v1_signed_validity/tests.rs"]
mod tests;
