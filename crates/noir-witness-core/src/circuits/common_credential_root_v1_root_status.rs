// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, InputMap};

use crate::circuits::support::{
    common_credential_root_status_path_parameter_pair, empty_input_map, insert_active_status_root,
    insert_attestation_id, insert_attestation_join_hash, insert_challenge_nonce_hash,
    insert_common_credential_root_status_path, insert_join_salt, insert_root_commitment,
    insert_root_join_hash, insert_u32_input, private_byte_array_parameter, private_u32_parameter,
    public_byte_array_parameter,
};
use crate::domain::{
    ActiveStatusRoot, AttestationId, AttestationJoinHash, AudienceHash, ChallengeNonceHash,
    CommonCredentialRootStatusIndex, CommonCredentialRootStatusPath, CompiledProgramArtifactJson,
    JoinSalt, RootCommitment, RootJoinHash, SecretInputs, SerializedWitnessStack,
    TransactionDataHash,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1RootStatusPublicInputs {
    pub challenge_nonce_hash: ChallengeNonceHash,
    pub audience_hash: AudienceHash,
    pub transaction_data_hash: TransactionDataHash,
    pub active_status_root: ActiveStatusRoot,
    pub root_join_hash: RootJoinHash,
    pub attestation_join_hash: AttestationJoinHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1RootStatusPrivateInputs {
    pub root: RootCommitment,
    pub attestation_id: AttestationId,
    pub join_salt: JoinSalt,
    pub status_index: CommonCredentialRootStatusIndex,
    pub status_path: CommonCredentialRootStatusPath,
}

pub struct CommonCredentialRootV1RootStatusInputs {
    pub public_inputs: CommonCredentialRootV1RootStatusPublicInputs,
    pub private_inputs: SecretInputs<CommonCredentialRootV1RootStatusPrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Challenge,
    AudienceHash,
    TransactionDataHash,
    ActiveStatusRoot,
    RootJoin,
    AttestationJoin,
    Root,
    AttestationId,
    JoinSalt,
    StatusIndex,
    StatusPathLength,
    StatusPath,
}

impl Field {
    const fn name(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::ActiveStatusRoot => "active_status_root",
            Self::RootJoin => "root_join",
            Self::AttestationJoin => "attestation_join",
            Self::Root => "root",
            Self::AttestationId => "attestation_id",
            Self::JoinSalt => "join_salt",
            Self::StatusIndex => "status_index",
            Self::StatusPathLength => "status_path_len",
            Self::StatusPath => "status_path",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CommonCredentialRootV1RootStatusInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 12] {
    let status_path_parameters = common_credential_root_status_path_parameter_pair(
        Field::StatusPathLength.name(),
        Field::StatusPath.name(),
    );
    [
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_byte_array_parameter(Field::ActiveStatusRoot.name(), 32),
        public_byte_array_parameter(Field::RootJoin.name(), 32),
        public_byte_array_parameter(Field::AttestationJoin.name(), 32),
        private_byte_array_parameter(Field::Root.name(), 32),
        private_byte_array_parameter(Field::AttestationId.name(), 32),
        private_byte_array_parameter(Field::JoinSalt.name(), 32),
        private_u32_parameter(Field::StatusIndex.name()),
        status_path_parameters[0].clone(),
        status_path_parameters[1].clone(),
    ]
}

fn encode_inputs(inputs: &CommonCredentialRootV1RootStatusInputs) -> InputMap {
    let private_inputs = inputs.private_inputs.expose();
    let mut input_map = empty_input_map();

    insert_challenge_nonce_hash(
        &mut input_map,
        Field::Challenge.name(),
        &inputs.public_inputs.challenge_nonce_hash,
    );
    crate::circuits::support::insert_audience_hash(
        &mut input_map,
        Field::AudienceHash.name(),
        &inputs.public_inputs.audience_hash,
    );
    crate::circuits::support::insert_transaction_data_hash(
        &mut input_map,
        Field::TransactionDataHash.name(),
        &inputs.public_inputs.transaction_data_hash,
    );
    insert_active_status_root(
        &mut input_map,
        Field::ActiveStatusRoot.name(),
        &inputs.public_inputs.active_status_root,
    );
    insert_root_join_hash(
        &mut input_map,
        Field::RootJoin.name(),
        &inputs.public_inputs.root_join_hash,
    );
    insert_attestation_join_hash(
        &mut input_map,
        Field::AttestationJoin.name(),
        &inputs.public_inputs.attestation_join_hash,
    );
    insert_root_commitment(&mut input_map, Field::Root.name(), &private_inputs.root);
    insert_attestation_id(
        &mut input_map,
        Field::AttestationId.name(),
        &private_inputs.attestation_id,
    );
    insert_join_salt(
        &mut input_map,
        Field::JoinSalt.name(),
        &private_inputs.join_salt,
    );
    insert_u32_input(
        &mut input_map,
        Field::StatusIndex.name(),
        private_inputs.status_index.value(),
    );
    insert_common_credential_root_status_path(
        &mut input_map,
        Field::StatusPathLength.name(),
        Field::StatusPath.name(),
        &private_inputs.status_path,
    );

    input_map
}
