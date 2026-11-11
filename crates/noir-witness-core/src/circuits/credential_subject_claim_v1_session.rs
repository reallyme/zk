// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_byte_array_input, insert_public_key, insert_session_context,
    private_byte_array_parameter, public_byte_array_parameter, public_u64_parameter,
    signature_parameter,
};
use crate::domain::{
    CompiledProgramArtifactJson, SecretInputs, SerializedWitnessStack, SessionContext,
    SubjectSessionAuthorization,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialSubjectClaimV1SessionPublicInputs {
    pub session_context: SessionContext,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialSubjectClaimV1SessionPrivateInputs {
    pub authorization: SubjectSessionAuthorization,
}

pub struct CredentialSubjectClaimV1SessionInputs {
    pub public_inputs: CredentialSubjectClaimV1SessionPublicInputs,
    pub private_inputs: SecretInputs<CredentialSubjectClaimV1SessionPrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Challenge,
    AudienceHash,
    TransactionDataHash,
    ExpiryUnix,
    SessionBinding,
    SubjectPublicKeyX,
    SubjectPublicKeyY,
    SubjectSignature,
}

impl Field {
    const fn name(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::ExpiryUnix => "expiry_unix",
            Self::SessionBinding => "session_binding",
            Self::SubjectPublicKeyX => "pk_subject_x",
            Self::SubjectPublicKeyY => "pk_subject_y",
            Self::SubjectSignature => "subject_sig",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CredentialSubjectClaimV1SessionInputs,
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
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::SessionBinding.name(), 32),
        private_byte_array_parameter(Field::SubjectPublicKeyX.name(), 32),
        private_byte_array_parameter(Field::SubjectPublicKeyY.name(), 32),
        signature_parameter(Field::SubjectSignature.name(), AbiVisibility::Private),
    ]
}

fn encode_inputs(inputs: &CredentialSubjectClaimV1SessionInputs) -> InputMap {
    let private_inputs = inputs.private_inputs.expose();
    let mut input_map = empty_input_map();

    insert_session_context(
        &mut input_map,
        Field::Challenge.name(),
        Field::AudienceHash.name(),
        Field::TransactionDataHash.name(),
        Field::ExpiryUnix.name(),
        Field::SessionBinding.name(),
        &inputs.public_inputs.session_context,
    );
    insert_public_key(
        &mut input_map,
        Field::SubjectPublicKeyX.name(),
        Field::SubjectPublicKeyY.name(),
        &private_inputs.authorization.subject_public_key,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::SubjectSignature.name(),
        private_inputs.authorization.subject_signature.as_bytes(),
    );

    input_map
}
