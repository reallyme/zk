// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::abi_encoding::{
    byte_array_matrix_type, byte_array_type, input_value_for_byte_array,
    input_value_for_byte_array_matrix, input_value_for_struct, input_value_for_u32,
    input_value_for_u64, struct_type, unsigned_integer_type,
};
use crate::domain::{
    CommonCredentialRootLineageCredentialWitness, CommonCredentialRootLineagePublicSlot,
    CommonCredentialRootStatusPath, CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32, FIELD_ELEMENT_BYTES,
    FIELD_ELEMENT_BYTES_U32, MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH,
    MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH_U32, SALT_BYTES_U32, SIGNATURE_BYTES_U32,
};
use zeroize::Zeroizing;

use super::{
    abi_parameter, insert_byte_array_matrix_input, insert_u32_input, private_byte_matrix_parameter,
    private_u32_parameter,
};

pub(crate) fn public_common_credential_root_lineage_slot_parameter(
    name: &'static str,
) -> AbiParameter {
    abi_parameter(
        name,
        struct_type(
            "PublicSlot",
            vec![
                ("issuer_x", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
                ("issuer_y", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
                ("expiry_unix", unsigned_integer_type(64)),
                (
                    "credential_binding",
                    byte_array_type(FIELD_ELEMENT_BYTES_U32),
                ),
                ("subject_join", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
            ],
        ),
        AbiVisibility::Public,
    )
}

pub(crate) fn private_common_credential_root_lineage_witness_parameter(
    name: &'static str,
) -> AbiParameter {
    abi_parameter(
        name,
        struct_type(
            "CredentialWitness",
            vec![
                ("envelope_hash", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
                ("merkle_root", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
                ("issuer_root_bind_sig", byte_array_type(SIGNATURE_BYTES_U32)),
                ("subject_x", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
                ("subject_y", byte_array_type(FIELD_ELEMENT_BYTES_U32)),
                (
                    "relationship_did_hash",
                    byte_array_type(FIELD_ELEMENT_BYTES_U32),
                ),
                (
                    "relationship_nonce",
                    byte_array_type(FIELD_ELEMENT_BYTES_U32),
                ),
                ("claim_salt", byte_array_type(SALT_BYTES_U32)),
                ("leaf_index", unsigned_integer_type(32)),
                ("path_len", unsigned_integer_type(32)),
                (
                    "path",
                    byte_array_matrix_type(CLAIM_TREE_DEPTH_U32, FIELD_ELEMENT_BYTES_U32),
                ),
            ],
        ),
        AbiVisibility::Private,
    )
}

pub(crate) fn insert_common_credential_root_lineage_slot(
    input_map: &mut InputMap,
    name: &'static str,
    slot: &CommonCredentialRootLineagePublicSlot,
) {
    let mut fields = BTreeMap::new();
    fields.insert(
        String::from("issuer_x"),
        input_value_for_byte_array(slot.issuer_public_key.x.as_bytes()),
    );
    fields.insert(
        String::from("issuer_y"),
        input_value_for_byte_array(slot.issuer_public_key.y.as_bytes()),
    );
    fields.insert(
        String::from("expiry_unix"),
        input_value_for_u64(slot.expiry_unix.value()),
    );
    fields.insert(
        String::from("credential_binding"),
        input_value_for_byte_array(slot.credential_binding_hash.as_bytes()),
    );
    fields.insert(
        String::from("subject_join"),
        input_value_for_byte_array(slot.subject_join_hash.as_bytes()),
    );
    input_map.insert(String::from(name), input_value_for_struct(fields));
}

pub(crate) fn insert_common_credential_root_lineage_witness(
    input_map: &mut InputMap,
    name: &'static str,
    witness: &CommonCredentialRootLineageCredentialWitness,
) {
    let mut fields = BTreeMap::new();
    fields.insert(
        String::from("envelope_hash"),
        input_value_for_byte_array(witness.envelope_hash.as_bytes()),
    );
    fields.insert(
        String::from("merkle_root"),
        input_value_for_byte_array(witness.merkle_root.as_bytes()),
    );
    fields.insert(
        String::from("issuer_root_bind_sig"),
        input_value_for_byte_array(witness.issuer_root_binding_signature.as_bytes()),
    );
    fields.insert(
        String::from("subject_x"),
        input_value_for_byte_array(witness.subject_public_key.x.as_bytes()),
    );
    fields.insert(
        String::from("subject_y"),
        input_value_for_byte_array(witness.subject_public_key.y.as_bytes()),
    );
    fields.insert(
        String::from("relationship_did_hash"),
        input_value_for_byte_array(witness.relationship_did_hash.as_bytes()),
    );
    fields.insert(
        String::from("relationship_nonce"),
        input_value_for_byte_array(witness.relationship_nonce.as_bytes()),
    );
    fields.insert(
        String::from("claim_salt"),
        input_value_for_byte_array(witness.claim_salt.as_bytes()),
    );
    fields.insert(
        String::from("leaf_index"),
        input_value_for_u32(witness.merkle_leaf_index.value()),
    );
    fields.insert(
        String::from("path_len"),
        input_value_for_u32(witness.merkle_path.length().value()),
    );

    let mut matrix = Zeroizing::new([[0_u8; FIELD_ELEMENT_BYTES]; CLAIM_TREE_DEPTH]);
    for (target, source) in matrix.iter_mut().zip(witness.merkle_path.siblings()) {
        target.copy_from_slice(source.as_bytes());
    }
    fields.insert(
        String::from("path"),
        input_value_for_byte_array_matrix(&matrix),
    );
    input_map.insert(String::from(name), input_value_for_struct(fields));
}

pub(crate) fn insert_common_credential_root_status_path(
    input_map: &mut InputMap,
    length_name: &'static str,
    path_name: &'static str,
    path: &CommonCredentialRootStatusPath,
) {
    insert_u32_input(input_map, length_name, path.length().value());
    let mut matrix =
        Zeroizing::new([[0_u8; FIELD_ELEMENT_BYTES]; MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH]);
    for (target, source) in matrix.iter_mut().zip(path.siblings()) {
        target.copy_from_slice(source.as_bytes());
    }
    insert_byte_array_matrix_input(input_map, path_name, &matrix);
}

pub(crate) fn common_credential_root_status_path_parameter_pair(
    path_len_name: &'static str,
    path_name: &'static str,
) -> [AbiParameter; 2] {
    [
        private_u32_parameter(path_len_name),
        private_byte_matrix_parameter(
            path_name,
            MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH_U32,
            FIELD_ELEMENT_BYTES_U32,
        ),
    ]
}
