// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_byte_array_input, insert_envelope_binding_hash, insert_envelope_hash,
    insert_issuer_context, private_byte_array_parameter, public_byte_array_parameter,
    public_u64_parameter, signature_parameter, IssuerContextFieldNames,
};
use crate::domain::{
    CompiledProgramArtifactJson, EnvelopeBindingHash, EnvelopeSignatureProof, IssuerBoundContext,
    SecretInputs, SerializedWitnessStack,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialEnvelopeV1PublicInputs {
    pub issuer_context: IssuerBoundContext,
    pub envelope_binding_hash: EnvelopeBindingHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialEnvelopeV1PrivateInputs {
    pub proof: EnvelopeSignatureProof,
}

pub struct CredentialEnvelopeV1Inputs {
    pub public_inputs: CredentialEnvelopeV1PublicInputs,
    pub private_inputs: SecretInputs<CredentialEnvelopeV1PrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    IssuerPublicKeyX,
    IssuerPublicKeyY,
    Challenge,
    AudienceHash,
    TransactionDataHash,
    ExpiryUnix,
    EnvelopeBinding,
    EnvelopeHash,
    IssuerSignature,
}

impl Field {
    const fn name(self) -> &'static str {
        match self {
            Self::IssuerPublicKeyX => "pk_issuer_x",
            Self::IssuerPublicKeyY => "pk_issuer_y",
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::ExpiryUnix => "expiry_unix",
            Self::EnvelopeBinding => "envelope_binding",
            Self::EnvelopeHash => "envelope_hash",
            Self::IssuerSignature => "issuer_sig",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CredentialEnvelopeV1Inputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 9] {
    [
        public_byte_array_parameter(Field::IssuerPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::IssuerPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::EnvelopeBinding.name(), 32),
        private_byte_array_parameter(Field::EnvelopeHash.name(), 32),
        signature_parameter(Field::IssuerSignature.name(), AbiVisibility::Private),
    ]
}

fn encode_inputs(inputs: &CredentialEnvelopeV1Inputs) -> InputMap {
    let private_inputs = inputs.private_inputs.expose();
    let mut input_map = empty_input_map();

    insert_issuer_context(
        &mut input_map,
        IssuerContextFieldNames {
            issuer_x_name: Field::IssuerPublicKeyX.name(),
            issuer_y_name: Field::IssuerPublicKeyY.name(),
            challenge_name: Field::Challenge.name(),
            audience_name: Field::AudienceHash.name(),
            transaction_data_name: Field::TransactionDataHash.name(),
            expiry_name: Field::ExpiryUnix.name(),
        },
        &inputs.public_inputs.issuer_context,
    );
    insert_envelope_binding_hash(
        &mut input_map,
        Field::EnvelopeBinding.name(),
        &inputs.public_inputs.envelope_binding_hash,
    );
    insert_envelope_hash(
        &mut input_map,
        Field::EnvelopeHash.name(),
        &private_inputs.proof.envelope_hash,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::IssuerSignature.name(),
        private_inputs.proof.issuer_signature.as_bytes(),
    );

    input_map
}
