// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    claim_value_parameter_pair, empty_input_map, insert_byte_array_input, insert_claim_disclosure,
    insert_issuer_context, insert_join_salt, insert_merkle_claim_proof, insert_public_key,
    insert_subject_join_hash, merkle_path_parameter_pair, private_byte_array_parameter,
    private_u32_parameter, public_byte_array_parameter, public_u64_parameter, signature_parameter,
    IssuerContextFieldNames, MerkleClaimProofFieldNames,
};
use crate::domain::{
    ClaimDisclosure, CompiledProgramArtifactJson, IssuerBoundContext, JoinSalt, MerkleClaimProof,
    P256PublicKey, PublicPersonaClaimLink, SecretInputs, SerializedWitnessStack,
    SessionBindingHash, SubjectJoinHash,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1PublicPersonaClaimPublicInputs {
    pub issuer_context: IssuerBoundContext,
    pub persona_public_key: P256PublicKey,
    pub session_binding_hash: SessionBindingHash,
    pub credential_subject_join_hash: SubjectJoinHash,
    pub disclosure: ClaimDisclosure,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CommonCredentialRootV1PublicPersonaClaimPrivateInputs {
    pub proof: MerkleClaimProof,
    pub link: PublicPersonaClaimLink,
    pub join_salt: JoinSalt,
}

pub struct CommonCredentialRootV1PublicPersonaClaimInputs {
    pub public_inputs: CommonCredentialRootV1PublicPersonaClaimPublicInputs,
    pub private_inputs: SecretInputs<CommonCredentialRootV1PublicPersonaClaimPrivateInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    IssuerPublicKeyX,
    IssuerPublicKeyY,
    PersonaPublicKeyX,
    PersonaPublicKeyY,
    Challenge,
    AudienceHash,
    TransactionDataHash,
    ExpiryUnix,
    SessionBinding,
    CredentialBinding,
    SubjectJoin,
    ClaimValueLength,
    ClaimValueBytes,
    ClaimNameHash,
    EnvelopeHash,
    MerkleRoot,
    IssuerSubjectBindingSignature,
    SubjectPublicKeyX,
    SubjectPublicKeyY,
    SubjectLinkSignature,
    JoinSalt,
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
            Self::PersonaPublicKeyX => "pk_persona_x",
            Self::PersonaPublicKeyY => "pk_persona_y",
            Self::Challenge => "challenge",
            Self::AudienceHash => "audience_hash",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::ExpiryUnix => "expiry_unix",
            Self::SessionBinding => "session_binding",
            Self::CredentialBinding => "credential_binding",
            Self::SubjectJoin => "subject_join",
            Self::ClaimValueLength => "val_len",
            Self::ClaimValueBytes => "val_pub",
            Self::ClaimNameHash => "name_hash",
            Self::EnvelopeHash => "envelope_hash",
            Self::MerkleRoot => "merkle_root",
            Self::IssuerSubjectBindingSignature => "issuer_subject_bind_sig",
            Self::SubjectPublicKeyX => "pk_subject_x",
            Self::SubjectPublicKeyY => "pk_subject_y",
            Self::SubjectLinkSignature => "subject_link_sig",
            Self::JoinSalt => "join_salt",
            Self::ClaimSalt => "salt",
            Self::MerkleLeafIndex => "index",
            Self::MerklePathLength => "path_len",
            Self::MerklePath => "path",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &CommonCredentialRootV1PublicPersonaClaimInputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 25] {
    let claim_parameters = claim_value_parameter_pair(
        Field::ClaimValueLength.name(),
        Field::ClaimValueBytes.name(),
    );
    let path_parameters =
        merkle_path_parameter_pair(Field::MerklePathLength.name(), Field::MerklePath.name());

    [
        public_byte_array_parameter(Field::IssuerPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::IssuerPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::PersonaPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::PersonaPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::SessionBinding.name(), 32),
        public_byte_array_parameter(Field::CredentialBinding.name(), 32),
        public_byte_array_parameter(Field::SubjectJoin.name(), 32),
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
        signature_parameter(Field::SubjectLinkSignature.name(), AbiVisibility::Private),
        private_byte_array_parameter(Field::JoinSalt.name(), 32),
        private_byte_array_parameter(Field::ClaimSalt.name(), 16),
        private_u32_parameter(Field::MerkleLeafIndex.name()),
        path_parameters[0].clone(),
        path_parameters[1].clone(),
    ]
}

fn encode_inputs(inputs: &CommonCredentialRootV1PublicPersonaClaimInputs) -> InputMap {
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
    insert_public_key(
        &mut input_map,
        Field::PersonaPublicKeyX.name(),
        Field::PersonaPublicKeyY.name(),
        &inputs.public_inputs.persona_public_key,
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
    insert_subject_join_hash(
        &mut input_map,
        Field::SubjectJoin.name(),
        &inputs.public_inputs.credential_subject_join_hash,
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
    insert_byte_array_input(
        &mut input_map,
        Field::SubjectLinkSignature.name(),
        private_inputs.link.subject_link_signature.as_bytes(),
    );
    insert_join_salt(
        &mut input_map,
        Field::JoinSalt.name(),
        &private_inputs.join_salt,
    );

    input_map
}
