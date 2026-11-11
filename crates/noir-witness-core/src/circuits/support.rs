// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use noirc_abi::{AbiParameter, AbiType, AbiVisibility, InputMap};

use crate::abi_encoding::{
    byte_array_matrix_type, byte_array_tensor_type, byte_array_type, input_value_for_byte_array,
    input_value_for_byte_array_matrix, input_value_for_byte_array_tensor, input_value_for_u32,
    input_value_for_u32_array, input_value_for_u64, unsigned_integer_array_type,
    unsigned_integer_type,
};
use crate::domain::{
    ActiveStatusRoot, AttestationId, AttestationJoinHash, AudienceHash, ChallengeNonceHash,
    ClaimBundleHash, ClaimDisclosure, ClaimNameHash, ClaimValue, CredentialBindingHash,
    EnvelopeBindingHash, IssuerBoundContext, JoinSalt, MerkleClaimProof, P256PublicKey,
    RootCommitment, RootJoinHash, SessionBindingHash, SessionContext, SubjectJoinHash,
    TransactionDataHash, UnixTimestamp, CLAIM_TREE_DEPTH_U32, FIELD_ELEMENT_BYTES_U32,
    MAX_CLAIM_VALUE_BYTES_U32, SIGNATURE_BYTES_U32,
};
use zeroize::Zeroizing;

mod claim_bundle;
mod common_credential_root;

pub(crate) use claim_bundle::{
    insert_claim_bundle_proof, validate_claim_bundle_slot_paths, ClaimBundleProofFieldNames,
};
pub(crate) use common_credential_root::{
    common_credential_root_status_path_parameter_pair, insert_common_credential_root_lineage_slot,
    insert_common_credential_root_lineage_witness, insert_common_credential_root_status_path,
    private_common_credential_root_lineage_witness_parameter,
    public_common_credential_root_lineage_slot_parameter,
};

pub(crate) fn public_byte_array_parameter(name: &'static str, length: u32) -> AbiParameter {
    abi_parameter(name, byte_array_type(length), AbiVisibility::Public)
}

pub(crate) fn private_byte_array_parameter(name: &'static str, length: u32) -> AbiParameter {
    abi_parameter(name, byte_array_type(length), AbiVisibility::Private)
}

pub(crate) fn public_u32_parameter(name: &'static str) -> AbiParameter {
    abi_parameter(name, unsigned_integer_type(32), AbiVisibility::Public)
}

pub(crate) fn private_u32_parameter(name: &'static str) -> AbiParameter {
    abi_parameter(name, unsigned_integer_type(32), AbiVisibility::Private)
}

pub(crate) fn private_u32_array_parameter(name: &'static str, length: u32) -> AbiParameter {
    abi_parameter(
        name,
        unsigned_integer_array_type(length, 32),
        AbiVisibility::Private,
    )
}

pub(crate) fn public_u64_parameter(name: &'static str) -> AbiParameter {
    abi_parameter(name, unsigned_integer_type(64), AbiVisibility::Public)
}

pub(crate) fn private_u64_parameter(name: &'static str) -> AbiParameter {
    abi_parameter(name, unsigned_integer_type(64), AbiVisibility::Private)
}

pub(crate) fn private_byte_matrix_parameter(
    name: &'static str,
    outer_length: u32,
    inner_length: u32,
) -> AbiParameter {
    abi_parameter(
        name,
        byte_array_matrix_type(outer_length, inner_length),
        AbiVisibility::Private,
    )
}

pub(crate) fn private_byte_tensor_parameter(
    name: &'static str,
    outer_length: u32,
    middle_length: u32,
    inner_length: u32,
) -> AbiParameter {
    abi_parameter(
        name,
        byte_array_tensor_type(outer_length, middle_length, inner_length),
        AbiVisibility::Private,
    )
}

pub(crate) fn empty_input_map() -> InputMap {
    BTreeMap::new()
}

pub(crate) fn insert_byte_array_input<const LENGTH: usize>(
    input_map: &mut InputMap,
    name: &'static str,
    bytes: &[u8; LENGTH],
) {
    input_map.insert(String::from(name), input_value_for_byte_array(bytes));
}

pub(crate) fn insert_byte_array_matrix_input<const OUTER: usize, const INNER: usize>(
    input_map: &mut InputMap,
    name: &'static str,
    matrix: &[[u8; INNER]; OUTER],
) {
    input_map.insert(
        String::from(name),
        input_value_for_byte_array_matrix(matrix),
    );
}

pub(crate) fn insert_byte_array_tensor_input<
    const OUTER: usize,
    const MIDDLE: usize,
    const INNER: usize,
>(
    input_map: &mut InputMap,
    name: &'static str,
    tensor: &[[[u8; INNER]; MIDDLE]; OUTER],
) {
    input_map.insert(
        String::from(name),
        input_value_for_byte_array_tensor(tensor),
    );
}

pub(crate) fn insert_u32_input(input_map: &mut InputMap, name: &'static str, value: u32) {
    input_map.insert(String::from(name), input_value_for_u32(value));
}

pub(crate) fn insert_u32_array_input<const LENGTH: usize>(
    input_map: &mut InputMap,
    name: &'static str,
    value: [u32; LENGTH],
) {
    input_map.insert(String::from(name), input_value_for_u32_array(value));
}

pub(crate) fn insert_u64_input(input_map: &mut InputMap, name: &'static str, value: u64) {
    input_map.insert(String::from(name), input_value_for_u64(value));
}

pub(crate) struct IssuerContextFieldNames {
    pub issuer_x_name: &'static str,
    pub issuer_y_name: &'static str,
    pub challenge_name: &'static str,
    pub audience_name: &'static str,
    pub transaction_data_name: &'static str,
    pub expiry_name: &'static str,
}

pub(crate) fn insert_issuer_context(
    input_map: &mut InputMap,
    field_names: IssuerContextFieldNames,
    context: &IssuerBoundContext,
) {
    insert_public_key(
        input_map,
        field_names.issuer_x_name,
        field_names.issuer_y_name,
        &context.issuer_public_key,
    );
    insert_challenge_nonce_hash(
        input_map,
        field_names.challenge_name,
        &context.challenge_nonce_hash,
    );
    insert_audience_hash(input_map, field_names.audience_name, &context.audience_hash);
    insert_transaction_data_hash(
        input_map,
        field_names.transaction_data_name,
        &context.transaction_data_hash,
    );
    insert_unix_timestamp(input_map, field_names.expiry_name, &context.expiry_unix);
}

pub(crate) fn insert_session_context(
    input_map: &mut InputMap,
    challenge_name: &'static str,
    audience_name: &'static str,
    transaction_data_name: &'static str,
    expiry_name: &'static str,
    session_binding_name: &'static str,
    context: &SessionContext,
) {
    insert_challenge_nonce_hash(input_map, challenge_name, &context.challenge_nonce_hash);
    insert_audience_hash(input_map, audience_name, &context.audience_hash);
    insert_transaction_data_hash(
        input_map,
        transaction_data_name,
        &context.transaction_data_hash,
    );
    insert_unix_timestamp(input_map, expiry_name, &context.expiry_unix);
    insert_session_binding_hash(
        input_map,
        session_binding_name,
        &context.session_binding_hash,
    );
}

pub(crate) fn insert_claim_disclosure(
    input_map: &mut InputMap,
    credential_binding_name: &'static str,
    value_length_name: &'static str,
    value_bytes_name: &'static str,
    claim_name_hash_name: &'static str,
    disclosure: &ClaimDisclosure,
) {
    insert_credential_binding_hash(
        input_map,
        credential_binding_name,
        &disclosure.credential_binding_hash,
    );
    insert_claim_value(
        input_map,
        value_length_name,
        value_bytes_name,
        &disclosure.claim_value,
    );
    insert_claim_name_hash(input_map, claim_name_hash_name, &disclosure.claim_name_hash);
}

pub(crate) struct MerkleClaimProofFieldNames {
    pub envelope_hash_name: &'static str,
    pub merkle_root_name: &'static str,
    pub salt_name: &'static str,
    pub index_name: &'static str,
    pub path_len_name: &'static str,
    pub path_name: &'static str,
}

pub(crate) fn insert_merkle_claim_proof(
    input_map: &mut InputMap,
    field_names: MerkleClaimProofFieldNames,
    proof: &MerkleClaimProof,
) {
    insert_envelope_hash(
        input_map,
        field_names.envelope_hash_name,
        &proof.envelope_hash,
    );
    insert_merkle_root(input_map, field_names.merkle_root_name, &proof.merkle_root);
    insert_claim_salt(input_map, field_names.salt_name, &proof.claim_salt);
    insert_u32_input(
        input_map,
        field_names.index_name,
        proof.merkle_leaf_index.value(),
    );
    insert_u32_input(
        input_map,
        field_names.path_len_name,
        proof.merkle_path.length().value(),
    );

    let mut matrix = Zeroizing::new(
        [[0_u8; crate::domain::FIELD_ELEMENT_BYTES]; crate::domain::CLAIM_TREE_DEPTH],
    );
    for (target, source) in matrix.iter_mut().zip(proof.merkle_path.siblings()) {
        target.copy_from_slice(source.as_bytes());
    }
    insert_byte_array_matrix_input(input_map, field_names.path_name, &matrix);
}

pub(crate) fn claim_value_parameter_pair(
    length_name: &'static str,
    bytes_name: &'static str,
) -> [AbiParameter; 2] {
    [
        public_u32_parameter(length_name),
        public_byte_array_parameter(bytes_name, MAX_CLAIM_VALUE_BYTES_U32),
    ]
}

pub(crate) fn merkle_path_parameter_pair(
    path_len_name: &'static str,
    path_name: &'static str,
) -> [AbiParameter; 2] {
    [
        private_u32_parameter(path_len_name),
        private_byte_matrix_parameter(path_name, CLAIM_TREE_DEPTH_U32, FIELD_ELEMENT_BYTES_U32),
    ]
}

pub(crate) fn signature_parameter(name: &'static str, visibility: AbiVisibility) -> AbiParameter {
    abi_parameter(name, byte_array_type(SIGNATURE_BYTES_U32), visibility)
}

pub(crate) fn insert_public_key(
    input_map: &mut InputMap,
    x_name: &'static str,
    y_name: &'static str,
    public_key: &P256PublicKey,
) {
    insert_byte_array_input(input_map, x_name, public_key.x.as_bytes());
    insert_byte_array_input(input_map, y_name, public_key.y.as_bytes());
}

pub(crate) fn insert_challenge_nonce_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &ChallengeNonceHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_audience_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &AudienceHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_transaction_data_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &TransactionDataHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_unix_timestamp(
    input_map: &mut InputMap,
    name: &'static str,
    value: &UnixTimestamp,
) {
    insert_u64_input(input_map, name, value.value());
}

pub(crate) fn insert_session_binding_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &SessionBindingHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_active_status_root(
    input_map: &mut InputMap,
    name: &'static str,
    value: &ActiveStatusRoot,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_attestation_id(
    input_map: &mut InputMap,
    name: &'static str,
    value: &AttestationId,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_attestation_join_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &AttestationJoinHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_join_salt(input_map: &mut InputMap, name: &'static str, value: &JoinSalt) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_root_commitment(
    input_map: &mut InputMap,
    name: &'static str,
    value: &RootCommitment,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_root_join_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &RootJoinHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_subject_join_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &SubjectJoinHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_envelope_binding_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &EnvelopeBindingHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_credential_binding_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &CredentialBindingHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_claim_bundle_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &ClaimBundleHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_claim_name_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &ClaimNameHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_claim_value(
    input_map: &mut InputMap,
    length_name: &'static str,
    bytes_name: &'static str,
    value: &ClaimValue,
) {
    insert_u32_input(input_map, length_name, value.length().value());
    insert_byte_array_input(input_map, bytes_name, value.as_bytes());
}

pub(crate) fn insert_envelope_hash(
    input_map: &mut InputMap,
    name: &'static str,
    value: &crate::domain::EnvelopeHash,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_merkle_root(
    input_map: &mut InputMap,
    name: &'static str,
    value: &crate::domain::MerkleRoot,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(crate) fn insert_claim_salt(
    input_map: &mut InputMap,
    name: &'static str,
    value: &crate::domain::ClaimSalt,
) {
    insert_byte_array_input(input_map, name, value.as_bytes());
}

pub(super) fn abi_parameter(
    name: &'static str,
    typ: AbiType,
    visibility: AbiVisibility,
) -> AbiParameter {
    AbiParameter {
        name: String::from(name),
        typ,
        visibility,
    }
}
