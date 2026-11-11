// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_byte_array_input, insert_public_key, insert_session_context,
    public_byte_array_parameter, public_u64_parameter, signature_parameter,
};
use crate::domain::{
    CompiledProgramArtifactJson, P256PublicKey, PublicPersonaSessionAuthorization, SecretInputs,
    SerializedWitnessStack, SessionContext,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1PublicSessionPublicInputs {
    pub persona_public_key: P256PublicKey,
    pub session_context: SessionContext,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1PublicSessionPrivateInputs {
    pub authorization: PublicPersonaSessionAuthorization,
}

pub struct CommonCredentialRootV1PublicSessionInputs {
    pub public_inputs: CommonCredentialRootV1PublicSessionPublicInputs,
    pub private_inputs: SecretInputs<CommonCredentialRootV1PublicSessionPrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    PersonaPublicKeyX,
    PersonaPublicKeyY,
    Challenge,
    AudienceHash,
    TransactionDataHash,
    ExpiryUnix,
    SessionBinding,
    PersonaFreshSignature,
}

impl Field {
    const fn name(self) -> &'static str {
        match self {
            Self::PersonaPublicKeyX => "pk_persona_x",
            Self::PersonaPublicKeyY => "pk_persona_y",
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::ExpiryUnix => "expiry_unix",
            Self::SessionBinding => "session_binding",
            Self::PersonaFreshSignature => "persona_fresh_sig",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CommonCredentialRootV1PublicSessionInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 8] {
    [
        public_byte_array_parameter(Field::PersonaPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::PersonaPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::SessionBinding.name(), 32),
        signature_parameter(Field::PersonaFreshSignature.name(), AbiVisibility::Private),
    ]
}

fn encode_inputs(inputs: &CommonCredentialRootV1PublicSessionInputs) -> InputMap {
    let private_inputs = inputs.private_inputs.expose();
    let mut input_map = empty_input_map();

    insert_public_key(
        &mut input_map,
        Field::PersonaPublicKeyX.name(),
        Field::PersonaPublicKeyY.name(),
        &inputs.public_inputs.persona_public_key,
    );
    insert_session_context(
        &mut input_map,
        Field::Challenge.name(),
        Field::AudienceHash.name(),
        Field::TransactionDataHash.name(),
        Field::ExpiryUnix.name(),
        Field::SessionBinding.name(),
        &inputs.public_inputs.session_context,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::PersonaFreshSignature.name(),
        private_inputs
            .authorization
            .persona_fresh_signature
            .as_bytes(),
    );

    input_map
}
