// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed ABI boundary for issuer-signed validity and private status opening.

use std::collections::BTreeMap;

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::abi_encoding::{
    byte_array_matrix_type, byte_array_type, input_value_for_byte_array,
    input_value_for_byte_array_matrix, input_value_for_struct, input_value_for_u32,
    input_value_for_u64, struct_type, unsigned_integer_type,
};
use crate::circuits::support::{
    abi_parameter, empty_input_map, insert_byte_array_input, public_byte_array_parameter,
};
use crate::domain::{CompiledProgramArtifactJson, SecretInputs, SerializedWitnessStack};
use crate::execution::generate_witness;
use crate::WitnessError;

const PATH_DEPTH: usize = 12;
const PATH_DEPTH_U32: u32 = 12;

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1IssuerCredentialStatusPublic {
    pub challenge: [u8; 32],
    pub audience_hash: [u8; 32],
    pub transaction_data_hash: [u8; 32],
    pub issuer_x: [u8; 32],
    pub issuer_y: [u8; 32],
    pub presentation_expiry: u64,
    pub credential_binding: [u8; 32],
    pub status_root: [u8; 32],
    pub status_length: u64,
    pub status_list_id: [u8; 32],
    pub status_url_hash: [u8; 32],
    pub status_purpose: u8,
    pub verifier_now: u64,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1IssuerCredentialStatusPrivate {
    pub envelope_hash: [u8; 32],
    pub claims_root: [u8; 32],
    pub issuer_validity_status_signature: [u8; 64],
    pub valid_from: u64,
    pub valid_until: u64,
    pub status_index: u64,
    pub status_chunk: [u8; 32],
    pub path_length: u32,
    pub path: [[u8; 32]; PATH_DEPTH],
}

pub struct CommonCredentialRootV1IssuerCredentialStatusInputs {
    pub public_inputs: CommonCredentialRootV1IssuerCredentialStatusPublic,
    pub private_inputs: SecretInputs<CommonCredentialRootV1IssuerCredentialStatusPrivate>,
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CommonCredentialRootV1IssuerCredentialStatusInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 5] {
    [
        public_byte_array_parameter("challenge", 32),
        public_byte_array_parameter("audience_hash", 32),
        public_byte_array_parameter("transaction_data_hash", 32),
        abi_parameter(
            "slot",
            struct_type(
                "PublicCredentialStatus",
                vec![
                    ("issuer_x", byte_array_type(32)),
                    ("issuer_y", byte_array_type(32)),
                    ("presentation_expiry", unsigned_integer_type(64)),
                    ("credential_binding", byte_array_type(32)),
                    ("status_root", byte_array_type(32)),
                    ("status_length", unsigned_integer_type(64)),
                    ("status_list_id", byte_array_type(32)),
                    ("status_url_hash", byte_array_type(32)),
                    ("status_purpose", unsigned_integer_type(8)),
                    ("verifier_now", unsigned_integer_type(64)),
                ],
            ),
            AbiVisibility::Public,
        ),
        abi_parameter(
            "witness",
            struct_type(
                "PrivateCredentialStatus",
                vec![
                    ("envelope_hash", byte_array_type(32)),
                    ("claims_root", byte_array_type(32)),
                    ("issuer_validity_status_signature", byte_array_type(64)),
                    ("valid_from", unsigned_integer_type(64)),
                    ("valid_until", unsigned_integer_type(64)),
                    ("status_index", unsigned_integer_type(64)),
                    ("status_chunk", byte_array_type(32)),
                    ("path_len", unsigned_integer_type(32)),
                    ("path", byte_array_matrix_type(PATH_DEPTH_U32, 32)),
                ],
            ),
            AbiVisibility::Private,
        ),
    ]
}

fn encode_inputs(inputs: &CommonCredentialRootV1IssuerCredentialStatusInputs) -> InputMap {
    let public = &inputs.public_inputs;
    let private = inputs.private_inputs.expose();
    let mut map = empty_input_map();
    insert_byte_array_input(&mut map, "challenge", &public.challenge);
    insert_byte_array_input(&mut map, "audience_hash", &public.audience_hash);
    insert_byte_array_input(
        &mut map,
        "transaction_data_hash",
        &public.transaction_data_hash,
    );

    let mut slot = BTreeMap::new();
    slot.insert(
        String::from("issuer_x"),
        input_value_for_byte_array(&public.issuer_x),
    );
    slot.insert(
        String::from("issuer_y"),
        input_value_for_byte_array(&public.issuer_y),
    );
    slot.insert(
        String::from("presentation_expiry"),
        input_value_for_u64(public.presentation_expiry),
    );
    slot.insert(
        String::from("credential_binding"),
        input_value_for_byte_array(&public.credential_binding),
    );
    slot.insert(
        String::from("status_root"),
        input_value_for_byte_array(&public.status_root),
    );
    slot.insert(
        String::from("status_length"),
        input_value_for_u64(public.status_length),
    );
    slot.insert(
        String::from("status_list_id"),
        input_value_for_byte_array(&public.status_list_id),
    );
    slot.insert(
        String::from("status_url_hash"),
        input_value_for_byte_array(&public.status_url_hash),
    );
    slot.insert(
        String::from("status_purpose"),
        input_value_for_u32(u32::from(public.status_purpose)),
    );
    slot.insert(
        String::from("verifier_now"),
        input_value_for_u64(public.verifier_now),
    );
    map.insert(String::from("slot"), input_value_for_struct(slot));

    let mut witness = BTreeMap::new();
    witness.insert(
        String::from("envelope_hash"),
        input_value_for_byte_array(&private.envelope_hash),
    );
    witness.insert(
        String::from("claims_root"),
        input_value_for_byte_array(&private.claims_root),
    );
    witness.insert(
        String::from("issuer_validity_status_signature"),
        input_value_for_byte_array(&private.issuer_validity_status_signature),
    );
    witness.insert(
        String::from("valid_from"),
        input_value_for_u64(private.valid_from),
    );
    witness.insert(
        String::from("valid_until"),
        input_value_for_u64(private.valid_until),
    );
    witness.insert(
        String::from("status_index"),
        input_value_for_u64(private.status_index),
    );
    witness.insert(
        String::from("status_chunk"),
        input_value_for_byte_array(&private.status_chunk),
    );
    witness.insert(
        String::from("path_len"),
        input_value_for_u32(private.path_length),
    );
    witness.insert(
        String::from("path"),
        input_value_for_byte_array_matrix(&private.path),
    );
    map.insert(String::from("witness"), input_value_for_struct(witness));
    map
}
