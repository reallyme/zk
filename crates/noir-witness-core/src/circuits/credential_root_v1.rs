// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_byte_array_input, insert_credential_binding_hash,
    insert_envelope_binding_hash, insert_envelope_hash, insert_issuer_context, insert_merkle_root,
    private_byte_array_parameter, public_byte_array_parameter, public_u64_parameter,
    signature_parameter, IssuerContextFieldNames,
};
use crate::domain::{
    CompiledProgramArtifactJson, CredentialBindingHash, CredentialRootProof, EnvelopeBindingHash,
    IssuerBoundContext, SecretInputs, SerializedWitnessStack,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialRootV1PublicInputs {
    pub issuer_context: IssuerBoundContext,
    pub envelope_binding_hash: EnvelopeBindingHash,
    pub credential_binding_hash: CredentialBindingHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialRootV1PrivateInputs {
    pub proof: CredentialRootProof,
}

pub struct CredentialRootV1Inputs {
    pub public_inputs: CredentialRootV1PublicInputs,
    pub private_inputs: SecretInputs<CredentialRootV1PrivateInputs>,
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
    CredentialBinding,
    EnvelopeHash,
    MerkleRoot,
    IssuerRootBindingSignature,
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
            Self::CredentialBinding => "credential_binding",
            Self::EnvelopeHash => "envelope_hash",
            Self::MerkleRoot => "merkle_root",
            Self::IssuerRootBindingSignature => "issuer_root_bind_sig",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CredentialRootV1Inputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 11] {
    [
        public_byte_array_parameter(Field::IssuerPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::IssuerPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::EnvelopeBinding.name(), 32),
        public_byte_array_parameter(Field::CredentialBinding.name(), 32),
        private_byte_array_parameter(Field::EnvelopeHash.name(), 32),
        private_byte_array_parameter(Field::MerkleRoot.name(), 32),
        signature_parameter(
            Field::IssuerRootBindingSignature.name(),
            AbiVisibility::Private,
        ),
    ]
}

fn encode_inputs(inputs: &CredentialRootV1Inputs) -> InputMap {
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
    insert_credential_binding_hash(
        &mut input_map,
        Field::CredentialBinding.name(),
        &inputs.public_inputs.credential_binding_hash,
    );
    insert_envelope_hash(
        &mut input_map,
        Field::EnvelopeHash.name(),
        &private_inputs.proof.envelope_hash,
    );
    insert_merkle_root(
        &mut input_map,
        Field::MerkleRoot.name(),
        &private_inputs.proof.merkle_root,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::IssuerRootBindingSignature.name(),
        private_inputs
            .proof
            .issuer_root_binding_signature
            .as_bytes(),
    );

    input_map
}
