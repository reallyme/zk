// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkWitness,
};
use reallyme_zk_backend_bb::BbExactCircuitArtifacts;
use reallyme_zk_noir_witness_core::{
    circuits::{
        common_credential_root_v1_issuer_credential_status::{
            CommonCredentialRootV1IssuerCredentialStatusInputs,
            CommonCredentialRootV1IssuerCredentialStatusPrivate,
            CommonCredentialRootV1IssuerCredentialStatusPublic,
        },
        common_credential_root_v1_lineage::{
            CommonCredentialRootV1LineageInputs, CommonCredentialRootV1LineagePrivateInputs,
            CommonCredentialRootV1LineagePublicInputs,
        },
        common_credential_root_v1_private_persona_claim::{
            CommonCredentialRootV1PrivatePersonaClaimInputs,
            CommonCredentialRootV1PrivatePersonaClaimPrivateInputs,
            CommonCredentialRootV1PrivatePersonaClaimPublicInputs,
        },
        common_credential_root_v1_public_persona_claim::{
            CommonCredentialRootV1PublicPersonaClaimInputs,
            CommonCredentialRootV1PublicPersonaClaimPrivateInputs,
            CommonCredentialRootV1PublicPersonaClaimPublicInputs,
        },
        common_credential_root_v1_public_session::generate_witness_from_artifact_json as generate_public_session,
        common_credential_root_v1_root_attestation::{
            CommonCredentialRootV1RootAttestationInputs,
            CommonCredentialRootV1RootAttestationPrivateInputs,
            CommonCredentialRootV1RootAttestationPublicInputs,
        },
        common_credential_root_v1_root_status::{
            CommonCredentialRootV1RootStatusInputs, CommonCredentialRootV1RootStatusPrivateInputs,
            CommonCredentialRootV1RootStatusPublicInputs,
        },
        private_persona_claim_v1_session::generate_witness_from_artifact_json as generate_private_session,
    },
    ActiveStatusRoot, AssurancePolicyId, AttestationEpoch, AttestationId, AttestationJoinHash,
    AudienceHash, ChallengeNonceHash, ClaimSalt, CommonCredentialRootLineageCredentialWitness,
    CommonCredentialRootLineagePublicSlot, CommonCredentialRootStatusIndex,
    CommonCredentialRootStatusPath, CommonCredentialRootStatusPathLength,
    CompiledProgramArtifactJson, CredentialBindingHash, EnvelopeHash, IssuerRootBindingSignature,
    IssuerSignature, IssuerSubjectBindingSignature, JoinSalt, MerkleLeafIndex, MerkleRoot,
    MerkleSiblingHash, PersonaClaimLink, RelationshipDidHash, RelationshipNonce, RootCommitment,
    RootJoinHash, SecretInputs, SessionBindingHash, SubjectJoinHash, SubjectLinkSignature,
    TransactionDataHash, UnixTimestamp, MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkCommonCredentialRootStageInputOwner;
use zeroize::Zeroizing;

use super::input::{
    bytes16, bytes32, bytes64, claim_disclosure, fixed_bytes, issuer_context, merkle_claim_proof,
    merkle_path, p256_public_key, private_persona_session_inputs, public_persona_session_inputs,
};

pub(crate) fn generate_common_credential_root_stage_witness(
    circuit_ref: ZkCircuitRef,
    artifacts: &BbExactCircuitArtifacts,
    input: ZkCommonCredentialRootStageInputOwner,
) -> Result<ZkWitness, ZkError> {
    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(artifacts.bytecode().as_bytes())
            .map_err(super::map_witness_error)?;
    use pb::zk_common_credential_root_stage_prove_operation::Input;
    let witness = match input.active_input() {
        Input::RootAttestation(value) => {
            let inputs = root_attestation_inputs(value)?;
            reallyme_zk_noir_witness_core::circuits::common_credential_root_v1_root_attestation::generate_witness_from_artifact_json(artifact_json, &inputs)
        }
        Input::RootStatus(value) => {
            let inputs = root_status_inputs(value)?;
            reallyme_zk_noir_witness_core::circuits::common_credential_root_v1_root_status::generate_witness_from_artifact_json(artifact_json, &inputs)
        }
        Input::IssuerCredentialStatus(value) => {
            let inputs = issuer_credential_status_inputs(value)?;
            reallyme_zk_noir_witness_core::circuits::common_credential_root_v1_issuer_credential_status::generate_witness_from_artifact_json(artifact_json, &inputs)
        }
        Input::Lineage(value) => {
            let inputs = lineage_inputs(value)?;
            reallyme_zk_noir_witness_core::circuits::common_credential_root_v1_lineage::generate_witness_from_artifact_json(artifact_json, &inputs)
        }
        Input::PrivatePersonaClaim(value) => {
            let inputs = private_persona_claim_inputs(value)?;
            reallyme_zk_noir_witness_core::circuits::common_credential_root_v1_private_persona_claim::generate_witness_from_artifact_json(artifact_json, &inputs)
        }
        Input::PublicPersonaClaim(value) => {
            let inputs = public_persona_claim_inputs(value)?;
            reallyme_zk_noir_witness_core::circuits::common_credential_root_v1_public_persona_claim::generate_witness_from_artifact_json(artifact_json, &inputs)
        }
        Input::PrivatePersonaSession(value) => {
            let inputs = private_persona_session_inputs(value)?;
            generate_private_session(artifact_json, &inputs)
        }
        Input::PublicPersonaSession(value) => {
            let inputs = public_persona_session_inputs(value)?;
            generate_public_session(artifact_json, &inputs)
        }
    }
    .map_err(super::map_witness_error)?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness.into_zeroizing_bytes())
}

fn issuer_credential_status_inputs(
    input: &pb::ZkCommonCredentialRootIssuerCredentialStatusInput,
) -> Result<CommonCredentialRootV1IssuerCredentialStatusInputs, ZkError> {
    let presentation = presentation_context(&input.presentation)?;
    let issuer = p256_public_key(&input.issuer_public_key)?;
    let status_purpose =
        reallyme_zk_proto_codec::issuer_status::purpose_from_proto(input.status_purpose)?
            .wire_value();
    if input.path.len() > 12 {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    let mut path = Zeroizing::new([[0_u8; 32]; 12]);
    for (target, sibling) in path.iter_mut().zip(&input.path) {
        *target = *fixed_bytes(sibling.value.as_slice())?;
    }
    // Convert every fallible field, in request order, before the private
    // struct literal so an early return can only drop zeroizing owners, never
    // bare witness arrays held in a half-built value.
    let credential_binding = bytes32(&input.credential_binding)?;
    let status_root = bytes32(&input.status_root)?;
    let status_list_id = bytes32(&input.status_list_id)?;
    let status_url_hash = bytes32(&input.status_url_hash)?;
    let envelope_hash = bytes32(&input.envelope_hash)?;
    let claims_root = bytes32(&input.claims_root)?;
    let issuer_validity_status_signature = bytes64(&input.issuer_validity_status_signature)?;
    let status_chunk = bytes32(&input.status_chunk)?;
    Ok(CommonCredentialRootV1IssuerCredentialStatusInputs {
        public_inputs: CommonCredentialRootV1IssuerCredentialStatusPublic {
            challenge: *presentation.challenge.as_bytes(),
            audience_hash: *presentation.audience.as_bytes(),
            transaction_data_hash: *presentation.transaction.as_bytes(),
            issuer_x: *issuer.x.as_bytes(),
            issuer_y: *issuer.y.as_bytes(),
            presentation_expiry: input.presentation_expiry,
            credential_binding: *credential_binding,
            status_root: *status_root,
            status_length: input.status_length,
            status_list_id: *status_list_id,
            status_url_hash: *status_url_hash,
            status_purpose,
            verifier_now: input.verifier_now,
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1IssuerCredentialStatusPrivate {
            envelope_hash: *envelope_hash,
            claims_root: *claims_root,
            issuer_validity_status_signature: *issuer_validity_status_signature,
            valid_from: input.valid_from,
            valid_until: input.valid_until,
            status_index: input.status_index,
            status_chunk: *status_chunk,
            path_length: input.path_length,
            path: *path,
        }),
    })
}

fn root_attestation_inputs(
    input: &pb::ZkCommonCredentialRootAttestationInput,
) -> Result<CommonCredentialRootV1RootAttestationInputs, ZkError> {
    let presentation = presentation_context(&input.presentation)?;
    Ok(CommonCredentialRootV1RootAttestationInputs {
        public_inputs: CommonCredentialRootV1RootAttestationPublicInputs {
            reallyme_public_key: p256_public_key(&input.reallyme_public_key)?,
            assurance_policy_id: AssurancePolicyId::new(*bytes32(&input.assurance_policy_id)?),
            request_unix: UnixTimestamp::new(input.request_unix),
            presentation_expiry_unix: UnixTimestamp::new(presentation.expiry_unix),
            challenge_nonce_hash: presentation.challenge,
            audience_hash: presentation.audience,
            transaction_data_hash: presentation.transaction,
            root_join_hash: RootJoinHash::new(*bytes32(&input.root_join)?),
            attestation_join_hash: AttestationJoinHash::new(*bytes32(&input.attestation_join)?),
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1RootAttestationPrivateInputs {
            root: RootCommitment::new(*bytes32(&input.root)?),
            attestation_issued_unix: UnixTimestamp::new(input.attestation_issued_unix),
            attestation_expires_unix: UnixTimestamp::new(input.attestation_expires_unix),
            attestation_epoch: AttestationEpoch::new(input.attestation_epoch),
            attestation_signature: IssuerSignature::new(*bytes64(&input.attestation_signature)?),
            join_salt: JoinSalt::new(*bytes32(&input.join_salt)?),
        }),
    })
}

fn root_status_inputs(
    input: &pb::ZkCommonCredentialRootStatusInput,
) -> Result<CommonCredentialRootV1RootStatusInputs, ZkError> {
    let presentation = presentation_context(&input.presentation)?;
    let path = input
        .status_path
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let path_length = CommonCredentialRootStatusPathLength::new(path.path_length)
        .map_err(super::map_witness_error)?;
    if path.siblings.len() > MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    let mut siblings = core::array::from_fn(|_| MerkleSiblingHash::new([0_u8; 32]));
    for (index, sibling) in path.siblings.iter().enumerate() {
        let slot = siblings
            .get_mut(index)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        *slot = MerkleSiblingHash::new(*fixed_bytes(sibling.value.as_slice())?);
    }
    Ok(CommonCredentialRootV1RootStatusInputs {
        public_inputs: CommonCredentialRootV1RootStatusPublicInputs {
            challenge_nonce_hash: presentation.challenge,
            audience_hash: presentation.audience,
            transaction_data_hash: presentation.transaction,
            active_status_root: ActiveStatusRoot::new(*bytes32(&input.active_status_root)?),
            root_join_hash: RootJoinHash::new(*bytes32(&input.root_join)?),
            attestation_join_hash: AttestationJoinHash::new(*bytes32(&input.attestation_join)?),
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1RootStatusPrivateInputs {
            root: RootCommitment::new(*bytes32(&input.root)?),
            attestation_id: AttestationId::new(*bytes32(&input.attestation_id)?),
            join_salt: JoinSalt::new(*bytes32(&input.join_salt)?),
            status_index: CommonCredentialRootStatusIndex::new(input.status_index),
            status_path: CommonCredentialRootStatusPath::new(siblings, path_length),
        }),
    })
}

fn lineage_inputs(
    input: &pb::ZkCommonCredentialRootLineageInput,
) -> Result<CommonCredentialRootV1LineageInputs, ZkError> {
    let presentation = presentation_context(&input.presentation)?;
    let slot = input
        .slot
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let witness = input
        .witness
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CommonCredentialRootV1LineageInputs {
        public_inputs: CommonCredentialRootV1LineagePublicInputs {
            challenge_nonce_hash: presentation.challenge,
            audience_hash: presentation.audience,
            transaction_data_hash: presentation.transaction,
            root_join_hash: RootJoinHash::new(*bytes32(&input.root_join)?),
            slot: CommonCredentialRootLineagePublicSlot {
                issuer_public_key: p256_public_key(&slot.issuer_public_key)?,
                expiry_unix: UnixTimestamp::new(slot.expiry_unix),
                credential_binding_hash: CredentialBindingHash::new(*bytes32(
                    &slot.credential_binding,
                )?),
                subject_join_hash: SubjectJoinHash::new(*bytes32(&slot.subject_join)?),
            },
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1LineagePrivateInputs {
            root: RootCommitment::new(*bytes32(&input.root)?),
            join_salt: JoinSalt::new(*bytes32(&input.join_salt)?),
            witness: CommonCredentialRootLineageCredentialWitness {
                envelope_hash: EnvelopeHash::new(*bytes32(&witness.envelope_hash)?),
                merkle_root: MerkleRoot::new(*bytes32(&witness.merkle_root)?),
                issuer_root_binding_signature: IssuerRootBindingSignature::new(*bytes64(
                    &witness.issuer_root_binding_signature,
                )?),
                subject_public_key: p256_public_key(&witness.subject_public_key)?,
                relationship_did_hash: RelationshipDidHash::new(*bytes32(
                    &witness.relationship_did_hash,
                )?),
                relationship_nonce: RelationshipNonce::new(*bytes32(&witness.relationship_nonce)?),
                claim_salt: ClaimSalt::new(*bytes16(&witness.claim_salt)?),
                merkle_leaf_index: MerkleLeafIndex::new(witness.merkle_leaf_index),
                merkle_path: merkle_path(&witness.merkle_path)?,
            },
        }),
    })
}

fn private_persona_claim_inputs(
    input: &pb::ZkCommonCredentialRootPrivatePersonaClaimInput,
) -> Result<CommonCredentialRootV1PrivatePersonaClaimInputs, ZkError> {
    let link = input
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CommonCredentialRootV1PrivatePersonaClaimInputs {
        public_inputs: CommonCredentialRootV1PrivatePersonaClaimPublicInputs {
            issuer_context: issuer_context(&input.issuer_context)?,
            session_binding_hash: SessionBindingHash::new(*bytes32(&input.session_binding)?),
            credential_subject_join_hash: SubjectJoinHash::new(*bytes32(&input.subject_join)?),
            disclosure: claim_disclosure(&input.disclosure)?,
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1PrivatePersonaClaimPrivateInputs {
            proof: merkle_claim_proof(&input.proof)?,
            link: PersonaClaimLink {
                issuer_subject_binding_signature: IssuerSubjectBindingSignature::new(*bytes64(
                    &link.issuer_subject_binding_signature,
                )?),
                subject_public_key: p256_public_key(&link.subject_public_key)?,
                persona_public_key: p256_public_key(&link.persona_public_key)?,
                subject_link_signature: SubjectLinkSignature::new(*bytes64(
                    &link.subject_link_signature,
                )?),
            },
            join_salt: JoinSalt::new(*bytes32(&input.join_salt)?),
        }),
    })
}

fn public_persona_claim_inputs(
    input: &pb::ZkCommonCredentialRootPublicPersonaClaimInput,
) -> Result<CommonCredentialRootV1PublicPersonaClaimInputs, ZkError> {
    let link = input
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CommonCredentialRootV1PublicPersonaClaimInputs {
        public_inputs: CommonCredentialRootV1PublicPersonaClaimPublicInputs {
            issuer_context: issuer_context(&input.issuer_context)?,
            persona_public_key: p256_public_key(&input.persona_public_key)?,
            session_binding_hash: SessionBindingHash::new(*bytes32(&input.session_binding)?),
            credential_subject_join_hash: SubjectJoinHash::new(*bytes32(&input.subject_join)?),
            disclosure: claim_disclosure(&input.disclosure)?,
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1PublicPersonaClaimPrivateInputs {
            proof: merkle_claim_proof(&input.proof)?,
            link: reallyme_zk_noir_witness_core::PublicPersonaClaimLink {
                issuer_subject_binding_signature: IssuerSubjectBindingSignature::new(*bytes64(
                    &link.issuer_subject_binding_signature,
                )?),
                subject_public_key: p256_public_key(&link.subject_public_key)?,
                subject_link_signature: SubjectLinkSignature::new(*bytes64(
                    &link.subject_link_signature,
                )?),
            },
            join_salt: JoinSalt::new(*bytes32(&input.join_salt)?),
        }),
    })
}

struct PresentationContext {
    challenge: ChallengeNonceHash,
    audience: AudienceHash,
    transaction: TransactionDataHash,
    expiry_unix: u64,
}

fn presentation_context(
    field: &MessageField<
        pb::ZkInputPresentationContext,
        buffa::Inline<pb::ZkInputPresentationContext>,
    >,
) -> Result<PresentationContext, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(PresentationContext {
        challenge: ChallengeNonceHash::new(*bytes32(&context.challenge)?),
        audience: AudienceHash::new(*bytes32(&context.audience_hash)?),
        transaction: TransactionDataHash::new(*bytes32(&context.transaction_data_hash)?),
        expiry_unix: context.expiry_unix,
    })
}
