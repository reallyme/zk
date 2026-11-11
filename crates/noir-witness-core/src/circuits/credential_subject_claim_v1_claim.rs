// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    claim_value_parameter_pair, empty_input_map, insert_byte_array_input, insert_claim_disclosure,
    insert_issuer_context, insert_merkle_claim_proof, insert_public_key,
    merkle_path_parameter_pair, private_byte_array_parameter, private_u32_parameter,
    public_byte_array_parameter, public_u64_parameter, signature_parameter,
    IssuerContextFieldNames, MerkleClaimProofFieldNames,
};
use crate::domain::{
    ClaimDisclosure, CompiledProgramArtifactJson, IssuerBoundContext, MerkleClaimProof,
    SecretInputs, SerializedWitnessStack, SessionBindingHash, SubjectClaimLink,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialSubjectClaimV1ClaimPublicInputs {
    pub issuer_context: IssuerBoundContext,
    pub session_binding_hash: SessionBindingHash,
    pub disclosure: ClaimDisclosure,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CredentialSubjectClaimV1ClaimPrivateInputs {
    pub proof: MerkleClaimProof,
    pub link: SubjectClaimLink,
}

pub struct CredentialSubjectClaimV1ClaimInputs {
    pub public_inputs: CredentialSubjectClaimV1ClaimPublicInputs,
    pub private_inputs: SecretInputs<CredentialSubjectClaimV1ClaimPrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    IssuerPublicKeyX,
    IssuerPublicKeyY,
    Challenge,
    AudienceHash,
    TransactionDataHash,
    ExpiryUnix,
    SessionBinding,
    CredentialBinding,
    ClaimValueLength,
    ClaimValueBytes,
    ClaimNameHash,
    EnvelopeHash,
    MerkleRoot,
    IssuerSubjectBindingSignature,
    SubjectPublicKeyX,
    SubjectPublicKeyY,
    ClaimSalt,
    MerkleLeafIndex,
    MerklePathLength,
    MerklePath,
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
            Self::SessionBinding => "session_binding",
            Self::CredentialBinding => "credential_binding",
            Self::ClaimValueLength => "val_len",
            Self::ClaimValueBytes => "val_pub",
            Self::ClaimNameHash => "name_hash",
            Self::EnvelopeHash => "envelope_hash",
            Self::MerkleRoot => "merkle_root",
            Self::IssuerSubjectBindingSignature => "issuer_subject_bind_sig",
            Self::SubjectPublicKeyX => "pk_subject_x",
            Self::SubjectPublicKeyY => "pk_subject_y",
            Self::ClaimSalt => "salt",
            Self::MerkleLeafIndex => "index",
            Self::MerklePathLength => "path_len",
            Self::MerklePath => "path",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CredentialSubjectClaimV1ClaimInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 20] {
    let claim_parameters = claim_value_parameter_pair(
        Field::ClaimValueLength.name(),
        Field::ClaimValueBytes.name(),
    );
    let path_parameters =
        merkle_path_parameter_pair(Field::MerklePathLength.name(), Field::MerklePath.name());

    [
        public_byte_array_parameter(Field::IssuerPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::IssuerPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::SessionBinding.name(), 32),
        public_byte_array_parameter(Field::CredentialBinding.name(), 32),
        claim_parameters[0].clone(),
        claim_parameters[1].clone(),
        public_byte_array_parameter(Field::ClaimNameHash.name(), 32),
        private_byte_array_parameter(Field::EnvelopeHash.name(), 32),
        private_byte_array_parameter(Field::MerkleRoot.name(), 32),
        signature_parameter(
            Field::IssuerSubjectBindingSignature.name(),
            AbiVisibility::Private,
        ),
        private_byte_array_parameter(Field::SubjectPublicKeyX.name(), 32),
        private_byte_array_parameter(Field::SubjectPublicKeyY.name(), 32),
        private_byte_array_parameter(Field::ClaimSalt.name(), 16),
        private_u32_parameter(Field::MerkleLeafIndex.name()),
        path_parameters[0].clone(),
        path_parameters[1].clone(),
    ]
}

fn encode_inputs(inputs: &CredentialSubjectClaimV1ClaimInputs) -> InputMap {
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
    crate::circuits::support::insert_session_binding_hash(
        &mut input_map,
        Field::SessionBinding.name(),
        &inputs.public_inputs.session_binding_hash,
    );
    insert_claim_disclosure(
        &mut input_map,
        Field::CredentialBinding.name(),
        Field::ClaimValueLength.name(),
        Field::ClaimValueBytes.name(),
        Field::ClaimNameHash.name(),
        &inputs.public_inputs.disclosure,
    );
    insert_merkle_claim_proof(
        &mut input_map,
        MerkleClaimProofFieldNames {
            envelope_hash_name: Field::EnvelopeHash.name(),
            merkle_root_name: Field::MerkleRoot.name(),
            salt_name: Field::ClaimSalt.name(),
            index_name: Field::MerkleLeafIndex.name(),
            path_len_name: Field::MerklePathLength.name(),
            path_name: Field::MerklePath.name(),
        },
        &private_inputs.proof,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::IssuerSubjectBindingSignature.name(),
        private_inputs
            .link
            .issuer_subject_binding_signature
            .as_bytes(),
    );
    insert_public_key(
        &mut input_map,
        Field::SubjectPublicKeyX.name(),
        Field::SubjectPublicKeyY.name(),
        &private_inputs.link.subject_public_key,
    );

    input_map
}
