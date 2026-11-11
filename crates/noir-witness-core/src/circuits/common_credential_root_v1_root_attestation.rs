// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_attestation_join_hash, insert_byte_array_input,
    insert_challenge_nonce_hash, insert_join_salt, insert_public_key, insert_root_commitment,
    insert_root_join_hash, insert_u32_input, insert_unix_timestamp, private_byte_array_parameter,
    private_u32_parameter, public_byte_array_parameter, public_u64_parameter, signature_parameter,
};
use crate::domain::{
    AssurancePolicyId, AttestationEpoch, AttestationJoinHash, ChallengeNonceHash,
    CompiledProgramArtifactJson, IssuerSignature, JoinSalt, P256PublicKey, RootCommitment,
    RootJoinHash, SecretInputs, SerializedWitnessStack, TransactionDataHash, UnixTimestamp,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1RootAttestationPublicInputs {
    pub reallyme_public_key: P256PublicKey,
    pub assurance_policy_id: AssurancePolicyId,
    pub request_unix: UnixTimestamp,
    pub presentation_expiry_unix: UnixTimestamp,
    pub challenge_nonce_hash: ChallengeNonceHash,
    pub audience_hash: crate::domain::AudienceHash,
    pub transaction_data_hash: TransactionDataHash,
    pub root_join_hash: RootJoinHash,
    pub attestation_join_hash: AttestationJoinHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1RootAttestationPrivateInputs {
    pub root: RootCommitment,
    pub attestation_issued_unix: UnixTimestamp,
    pub attestation_expires_unix: UnixTimestamp,
    pub attestation_epoch: AttestationEpoch,
    pub attestation_signature: IssuerSignature,
    pub join_salt: JoinSalt,
}

pub struct CommonCredentialRootV1RootAttestationInputs {
    pub public_inputs: CommonCredentialRootV1RootAttestationPublicInputs,
    pub private_inputs: SecretInputs<CommonCredentialRootV1RootAttestationPrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    ReallyMePublicKeyX,
    ReallyMePublicKeyY,
    AssurancePolicyId,
    RequestUnix,
    PresentationExpiryUnix,
    Challenge,
    AudienceHash,
    TransactionDataHash,
    RootJoin,
    AttestationJoin,
    Root,
    AttestationIssuedUnix,
    AttestationExpiresUnix,
    AttestationEpoch,
    AttestationSignature,
    JoinSalt,
}

impl Field {
    const fn name(self) -> &'static str {
        match self {
            Self::ReallyMePublicKeyX => "reallyme_x",
            Self::ReallyMePublicKeyY => "reallyme_y",
            Self::AssurancePolicyId => "assurance_policy_id",
            Self::RequestUnix => "request_unix",
            Self::PresentationExpiryUnix => "presentation_expiry_unix",
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::RootJoin => "root_join",
            Self::AttestationJoin => "attestation_join",
            Self::Root => "root",
            Self::AttestationIssuedUnix => "attestation_issued_unix",
            Self::AttestationExpiresUnix => "attestation_expires_unix",
            Self::AttestationEpoch => "attestation_epoch",
            Self::AttestationSignature => "attestation_signature",
            Self::JoinSalt => "join_salt",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CommonCredentialRootV1RootAttestationInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 16] {
    [
        public_byte_array_parameter(Field::ReallyMePublicKeyX.name(), 32),
        public_byte_array_parameter(Field::ReallyMePublicKeyY.name(), 32),
        public_byte_array_parameter(Field::AssurancePolicyId.name(), 32),
        public_u64_parameter(Field::RequestUnix.name()),
        public_u64_parameter(Field::PresentationExpiryUnix.name()),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_byte_array_parameter(Field::RootJoin.name(), 32),
        public_byte_array_parameter(Field::AttestationJoin.name(), 32),
        private_byte_array_parameter(Field::Root.name(), 32),
        crate::circuits::support::private_u64_parameter(Field::AttestationIssuedUnix.name()),
        crate::circuits::support::private_u64_parameter(Field::AttestationExpiresUnix.name()),
        private_u32_parameter(Field::AttestationEpoch.name()),
        signature_parameter(Field::AttestationSignature.name(), AbiVisibility::Private),
        private_byte_array_parameter(Field::JoinSalt.name(), 32),
    ]
}

fn encode_inputs(inputs: &CommonCredentialRootV1RootAttestationInputs) -> InputMap {
    let private_inputs = inputs.private_inputs.expose();
    let mut input_map = empty_input_map();

    insert_public_key(
        &mut input_map,
        Field::ReallyMePublicKeyX.name(),
        Field::ReallyMePublicKeyY.name(),
        &inputs.public_inputs.reallyme_public_key,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::AssurancePolicyId.name(),
        inputs.public_inputs.assurance_policy_id.as_bytes(),
    );
    insert_unix_timestamp(
        &mut input_map,
        Field::RequestUnix.name(),
        &inputs.public_inputs.request_unix,
    );
    insert_unix_timestamp(
        &mut input_map,
        Field::PresentationExpiryUnix.name(),
        &inputs.public_inputs.presentation_expiry_unix,
    );
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
    insert_attestation_join_hash(
        &mut input_map,
        Field::AttestationJoin.name(),
        &inputs.public_inputs.attestation_join_hash,
    );
    insert_root_commitment(&mut input_map, Field::Root.name(), &private_inputs.root);
    insert_unix_timestamp(
        &mut input_map,
        Field::AttestationIssuedUnix.name(),
        &private_inputs.attestation_issued_unix,
    );
    insert_unix_timestamp(
        &mut input_map,
        Field::AttestationExpiresUnix.name(),
        &private_inputs.attestation_expires_unix,
    );
    insert_u32_input(
        &mut input_map,
        Field::AttestationEpoch.name(),
        private_inputs.attestation_epoch.value(),
    );
    insert_byte_array_input(
        &mut input_map,
        Field::AttestationSignature.name(),
        private_inputs.attestation_signature.as_bytes(),
    );
    insert_join_salt(
        &mut input_map,
        Field::JoinSalt.name(),
        &private_inputs.join_salt,
    );

    input_map
}
