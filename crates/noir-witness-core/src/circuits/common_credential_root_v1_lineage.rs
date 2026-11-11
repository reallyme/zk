// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_challenge_nonce_hash, insert_common_credential_root_lineage_slot,
    insert_common_credential_root_lineage_witness, insert_join_salt, insert_root_commitment,
    insert_root_join_hash, private_byte_array_parameter,
    private_common_credential_root_lineage_witness_parameter, public_byte_array_parameter,
    public_common_credential_root_lineage_slot_parameter,
};
use crate::domain::{
    AudienceHash, ChallengeNonceHash, CommonCredentialRootLineageCredentialWitness,
    CommonCredentialRootLineagePublicSlot, CompiledProgramArtifactJson, JoinSalt, RootCommitment,
    RootJoinHash, SecretInputs, SerializedWitnessStack, TransactionDataHash,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1LineagePublicInputs {
    pub challenge_nonce_hash: ChallengeNonceHash,
    pub audience_hash: AudienceHash,
    pub transaction_data_hash: TransactionDataHash,
    pub root_join_hash: RootJoinHash,
    pub slot: CommonCredentialRootLineagePublicSlot,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1LineagePrivateInputs {
    pub root: RootCommitment,
    pub join_salt: JoinSalt,
    pub witness: CommonCredentialRootLineageCredentialWitness,
}

pub struct CommonCredentialRootV1LineageInputs {
    pub public_inputs: CommonCredentialRootV1LineagePublicInputs,
    pub private_inputs: SecretInputs<CommonCredentialRootV1LineagePrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Challenge,
    AudienceHash,
    TransactionDataHash,
    RootJoin,
    Slot,
    Root,
    JoinSalt,
    Witness,
}

impl Field {
    const fn name(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::RootJoin => "root_join",
            Self::Slot => "slot",
            Self::Root => "root",
            Self::JoinSalt => "join_salt",
            Self::Witness => "witness",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CommonCredentialRootV1LineageInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 8] {
    [
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_byte_array_parameter(Field::RootJoin.name(), 32),
        public_common_credential_root_lineage_slot_parameter(Field::Slot.name()),
        private_byte_array_parameter(Field::Root.name(), 32),
        private_byte_array_parameter(Field::JoinSalt.name(), 32),
        private_common_credential_root_lineage_witness_parameter(Field::Witness.name()),
    ]
}

fn encode_inputs(inputs: &CommonCredentialRootV1LineageInputs) -> InputMap {
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
    insert_root_join_hash(
        &mut input_map,
        Field::RootJoin.name(),
        &inputs.public_inputs.root_join_hash,
    );
    insert_common_credential_root_lineage_slot(
        &mut input_map,
        Field::Slot.name(),
        &inputs.public_inputs.slot,
    );
    insert_root_commitment(&mut input_map, Field::Root.name(), &private_inputs.root);
    insert_join_salt(
        &mut input_map,
        Field::JoinSalt.name(),
        &private_inputs.join_salt,
    );
    insert_common_credential_root_lineage_witness(
        &mut input_map,
        Field::Witness.name(),
        &private_inputs.witness,
    );

    input_map
}
