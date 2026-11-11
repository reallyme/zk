// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{AbiParameter, AbiVisibility, InputMap};

use crate::circuits::support::{
    empty_input_map, insert_byte_array_input, insert_claim_bundle_hash, insert_claim_bundle_proof,
    insert_credential_binding_hash, insert_issuer_context, insert_public_key,
    private_byte_array_parameter, private_byte_matrix_parameter, private_byte_tensor_parameter,
    private_u32_array_parameter, public_byte_array_parameter, public_u32_parameter,
    public_u64_parameter, signature_parameter, ClaimBundleProofFieldNames, IssuerContextFieldNames,
};
use crate::domain::{
    ClaimBundleCount, ClaimBundleHash, ClaimBundleProof, CompiledProgramArtifactJson,
    CredentialBindingHash, IssuerBoundContext, PersonaClaimLink, SecretInputs,
    SerializedWitnessStack, SessionBindingHash,
};
use crate::execution::generate_witness;
use crate::WitnessError;
use zeroize::{Zeroize, ZeroizeOnDrop};

const BUNDLE_SIZE: usize = 4;
const BUNDLE_SIZE_U32: u32 = 4;

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrivatePersonaClaimV1ClaimBundle4PublicInputs {
    pub issuer_context: IssuerBoundContext,
    pub session_binding_hash: SessionBindingHash,
    pub credential_binding_hash: CredentialBindingHash,
    pub bundle_count: ClaimBundleCount<BUNDLE_SIZE>,
    pub bundle_hash: ClaimBundleHash,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrivatePersonaClaimV1ClaimBundle4PrivateInputs {
    pub proof: ClaimBundleProof<BUNDLE_SIZE>,
    pub link: PersonaClaimLink,
}

pub struct PrivatePersonaClaimV1ClaimBundle4Inputs {
    pub public_inputs: PrivatePersonaClaimV1ClaimBundle4PublicInputs,
    pub private_inputs: SecretInputs<PrivatePersonaClaimV1ClaimBundle4PrivateInputs>,
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
    BundleCount,
    BundleHash,
    EnvelopeHash,
    MerkleRoot,
    IssuerSubjectBindingSignature,
    SubjectPublicKeyX,
    SubjectPublicKeyY,
    PersonaPublicKeyX,
    PersonaPublicKeyY,
    SubjectLinkSignature,
    ClaimValueLengths,
    ClaimValueBytes,
    ClaimNameHashes,
    ClaimSalts,
    MerkleLeafIndices,
    MerklePathLengths,
    MerklePaths,
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
            Self::BundleCount => "bundle_count",
            Self::BundleHash => "bundle_hash",
            Self::EnvelopeHash => "envelope_hash",
            Self::MerkleRoot => "merkle_root",
            Self::IssuerSubjectBindingSignature => "issuer_subject_bind_sig",
            Self::SubjectPublicKeyX => "pk_subject_x",
            Self::SubjectPublicKeyY => "pk_subject_y",
            Self::PersonaPublicKeyX => "pk_persona_x",
            Self::PersonaPublicKeyY => "pk_persona_y",
            Self::SubjectLinkSignature => "subject_link_sig",
            Self::ClaimValueLengths => "val_lens",
            Self::ClaimValueBytes => "val_pubs",
            Self::ClaimNameHashes => "name_hashes",
            Self::ClaimSalts => "salts",
            Self::MerkleLeafIndices => "indices",
            Self::MerklePathLengths => "path_lens",
            Self::MerklePaths => "paths",
        }
    }
}

pub fn generate_witness_from_artifact_json(
    artifact_json: CompiledProgramArtifactJson<'_>,
    inputs: &PrivatePersonaClaimV1ClaimBundle4Inputs,
) -> Result<SerializedWitnessStack, WitnessError> {
    crate::circuits::support::validate_claim_bundle_slot_paths(
        &inputs.public_inputs.bundle_count,
        &inputs.private_inputs.expose().proof,
    )?;
    generate_witness(
        artifact_json,
        &expected_abi_parameters(),
        encode_inputs(inputs),
    )
}

fn expected_abi_parameters() -> [AbiParameter; 25] {
    [
        public_byte_array_parameter(Field::IssuerPublicKeyX.name(), 32),
        public_byte_array_parameter(Field::IssuerPublicKeyY.name(), 32),
        public_byte_array_parameter(Field::Challenge.name(), 32),
        public_byte_array_parameter(Field::AudienceHash.name(), 32),
        public_byte_array_parameter(Field::TransactionDataHash.name(), 32),
        public_u64_parameter(Field::ExpiryUnix.name()),
        public_byte_array_parameter(Field::SessionBinding.name(), 32),
        public_byte_array_parameter(Field::CredentialBinding.name(), 32),
        public_u32_parameter(Field::BundleCount.name()),
        public_byte_array_parameter(Field::BundleHash.name(), 32),
        private_byte_array_parameter(Field::EnvelopeHash.name(), 32),
        private_byte_array_parameter(Field::MerkleRoot.name(), 32),
        signature_parameter(
            Field::IssuerSubjectBindingSignature.name(),
            AbiVisibility::Private,
        ),
        private_byte_array_parameter(Field::SubjectPublicKeyX.name(), 32),
        private_byte_array_parameter(Field::SubjectPublicKeyY.name(), 32),
        private_byte_array_parameter(Field::PersonaPublicKeyX.name(), 32),
        private_byte_array_parameter(Field::PersonaPublicKeyY.name(), 32),
        signature_parameter(Field::SubjectLinkSignature.name(), AbiVisibility::Private),
        private_u32_array_parameter(Field::ClaimValueLengths.name(), BUNDLE_SIZE_U32),
        private_byte_matrix_parameter(Field::ClaimValueBytes.name(), BUNDLE_SIZE_U32, 64),
        private_byte_matrix_parameter(Field::ClaimNameHashes.name(), BUNDLE_SIZE_U32, 32),
        private_byte_matrix_parameter(Field::ClaimSalts.name(), BUNDLE_SIZE_U32, 16),
        private_u32_array_parameter(Field::MerkleLeafIndices.name(), BUNDLE_SIZE_U32),
        private_u32_array_parameter(Field::MerklePathLengths.name(), BUNDLE_SIZE_U32),
        private_byte_tensor_parameter(
            Field::MerklePaths.name(),
            BUNDLE_SIZE_U32,
            crate::domain::CLAIM_TREE_DEPTH_U32,
            32,
        ),
    ]
}

fn encode_inputs(inputs: &PrivatePersonaClaimV1ClaimBundle4Inputs) -> InputMap {
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
    insert_credential_binding_hash(
        &mut input_map,
        Field::CredentialBinding.name(),
        &inputs.public_inputs.credential_binding_hash,
    );
    crate::circuits::support::insert_u32_input(
        &mut input_map,
        Field::BundleCount.name(),
        inputs.public_inputs.bundle_count.value(),
    );
    insert_claim_bundle_hash(
        &mut input_map,
        Field::BundleHash.name(),
        &inputs.public_inputs.bundle_hash,
    );
    insert_claim_bundle_proof(
        &mut input_map,
        ClaimBundleProofFieldNames {
            envelope_hash_name: Field::EnvelopeHash.name(),
            merkle_root_name: Field::MerkleRoot.name(),
            value_lengths_name: Field::ClaimValueLengths.name(),
            value_bytes_name: Field::ClaimValueBytes.name(),
            name_hashes_name: Field::ClaimNameHashes.name(),
            salts_name: Field::ClaimSalts.name(),
            indices_name: Field::MerkleLeafIndices.name(),
            path_lengths_name: Field::MerklePathLengths.name(),
            paths_name: Field::MerklePaths.name(),
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
    insert_public_key(
        &mut input_map,
        Field::PersonaPublicKeyX.name(),
        Field::PersonaPublicKeyY.name(),
        &private_inputs.link.persona_public_key,
    );
    insert_byte_array_input(
        &mut input_map,
        Field::SubjectLinkSignature.name(),
        private_inputs.link.subject_link_signature.as_bytes(),
    );

    input_map
}
