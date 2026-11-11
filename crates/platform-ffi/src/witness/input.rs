// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_noir_witness_core::{
    circuits::{
        common_credential_root_v1_public_session::{
            CommonCredentialRootV1PublicSessionInputs,
            CommonCredentialRootV1PublicSessionPrivateInputs,
            CommonCredentialRootV1PublicSessionPublicInputs,
        },
        credential_envelope_v1::{
            CredentialEnvelopeV1Inputs, CredentialEnvelopeV1PrivateInputs,
            CredentialEnvelopeV1PublicInputs,
        },
        credential_root_v1::{
            CredentialRootV1Inputs, CredentialRootV1PrivateInputs, CredentialRootV1PublicInputs,
        },
        credential_subject_claim_v1_claim::{
            CredentialSubjectClaimV1ClaimInputs, CredentialSubjectClaimV1ClaimPrivateInputs,
            CredentialSubjectClaimV1ClaimPublicInputs,
        },
        credential_subject_claim_v1_session::{
            CredentialSubjectClaimV1SessionInputs, CredentialSubjectClaimV1SessionPrivateInputs,
            CredentialSubjectClaimV1SessionPublicInputs,
        },
        private_persona_claim_v1_claim::{
            PrivatePersonaClaimV1ClaimInputs, PrivatePersonaClaimV1ClaimPrivateInputs,
            PrivatePersonaClaimV1ClaimPublicInputs,
        },
        private_persona_claim_v1_session::{
            PrivatePersonaClaimV1SessionInputs, PrivatePersonaClaimV1SessionPrivateInputs,
            PrivatePersonaClaimV1SessionPublicInputs,
        },
    },
    AudienceHash, ChallengeNonceHash, ClaimDisclosure, ClaimNameHash, ClaimSalt, ClaimValue,
    ClaimValueLength, CredentialBindingHash, CredentialRootProof, EnvelopeBindingHash,
    EnvelopeHash, EnvelopeSignatureProof, IssuerBoundContext, IssuerRootBindingSignature,
    IssuerSignature, IssuerSubjectBindingSignature, MerkleClaimProof, MerkleLeafIndex, MerklePath,
    MerklePathLength, MerkleRoot, MerkleSiblingHash, P256Coordinate, P256PublicKey,
    PersonaClaimLink, PersonaFreshSignature, PersonaSessionAuthorization, PersonaSignature,
    PublicPersonaSessionAuthorization, SecretInputs, SessionBindingHash, SessionContext,
    SubjectClaimLink, SubjectLinkSignature, SubjectSessionAuthorization, SubjectSignature,
    TransactionDataHash, UnixTimestamp, CLAIM_TREE_DEPTH, CLAIM_TREE_DEPTH_U32,
    FIELD_ELEMENT_BYTES, MAX_CLAIM_VALUE_BYTES, SALT_BYTES, SIGNATURE_BYTES,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "input/merkle_path_tests.rs"]
mod merkle_path_tests;

pub(super) fn private_session_inputs(
    input: &pb::ZkCredentialSubjectClaimSessionInput,
) -> Result<CredentialSubjectClaimV1SessionInputs, ZkError> {
    let authorization = input
        .authorization
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CredentialSubjectClaimV1SessionInputs {
        public_inputs: CredentialSubjectClaimV1SessionPublicInputs {
            session_context: session_context(&input.session_context)?,
        },
        private_inputs: SecretInputs::new(CredentialSubjectClaimV1SessionPrivateInputs {
            authorization: SubjectSessionAuthorization {
                subject_public_key: p256_public_key(&authorization.subject_public_key)?,
                subject_signature: SubjectSignature::new(*bytes64(
                    &authorization.subject_signature,
                )?),
            },
        }),
    })
}

pub(super) fn private_persona_session_inputs(
    input: &pb::ZkPrivatePersonaSessionInput,
) -> Result<PrivatePersonaClaimV1SessionInputs, ZkError> {
    let authorization = input
        .authorization
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(PrivatePersonaClaimV1SessionInputs {
        public_inputs: PrivatePersonaClaimV1SessionPublicInputs {
            session_context: session_context(&input.session_context)?,
        },
        private_inputs: SecretInputs::new(PrivatePersonaClaimV1SessionPrivateInputs {
            authorization: PersonaSessionAuthorization {
                persona_public_key: p256_public_key(&authorization.persona_public_key)?,
                persona_signature: PersonaSignature::new(*bytes64(
                    &authorization.persona_signature,
                )?),
            },
        }),
    })
}

pub(super) fn public_persona_session_inputs(
    input: &pb::ZkPublicPersonaSessionInput,
) -> Result<CommonCredentialRootV1PublicSessionInputs, ZkError> {
    let authorization = input
        .authorization
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CommonCredentialRootV1PublicSessionInputs {
        public_inputs: CommonCredentialRootV1PublicSessionPublicInputs {
            persona_public_key: p256_public_key(&input.persona_public_key)?,
            session_context: session_context(&input.session_context)?,
        },
        private_inputs: SecretInputs::new(CommonCredentialRootV1PublicSessionPrivateInputs {
            authorization: PublicPersonaSessionAuthorization {
                persona_fresh_signature: PersonaFreshSignature::new(*bytes64(
                    &authorization.persona_fresh_signature,
                )?),
            },
        }),
    })
}

pub(super) fn credential_envelope_inputs(
    input: &pb::ZkCredentialEnvelopeInput,
) -> Result<CredentialEnvelopeV1Inputs, ZkError> {
    let proof = input
        .proof
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CredentialEnvelopeV1Inputs {
        public_inputs: CredentialEnvelopeV1PublicInputs {
            issuer_context: issuer_context(&input.issuer_context)?,
            envelope_binding_hash: EnvelopeBindingHash::new(*bytes32(&input.envelope_binding)?),
        },
        private_inputs: SecretInputs::new(CredentialEnvelopeV1PrivateInputs {
            proof: EnvelopeSignatureProof {
                envelope_hash: EnvelopeHash::new(*bytes32(&proof.envelope_hash)?),
                issuer_signature: IssuerSignature::new(*bytes64(&proof.issuer_signature)?),
            },
        }),
    })
}

pub(super) fn credential_root_inputs(
    input: &pb::ZkCredentialRootInput,
) -> Result<CredentialRootV1Inputs, ZkError> {
    let proof = input
        .proof
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CredentialRootV1Inputs {
        public_inputs: CredentialRootV1PublicInputs {
            issuer_context: issuer_context(&input.issuer_context)?,
            envelope_binding_hash: EnvelopeBindingHash::new(*bytes32(&input.envelope_binding)?),
            credential_binding_hash: CredentialBindingHash::new(*bytes32(
                &input.credential_binding,
            )?),
        },
        private_inputs: SecretInputs::new(CredentialRootV1PrivateInputs {
            proof: CredentialRootProof {
                envelope_hash: EnvelopeHash::new(*bytes32(&proof.envelope_hash)?),
                merkle_root: MerkleRoot::new(*bytes32(&proof.merkle_root)?),
                issuer_root_binding_signature: IssuerRootBindingSignature::new(*bytes64(
                    &proof.issuer_root_binding_signature,
                )?),
            },
        }),
    })
}

pub(super) fn credential_subject_claim_inputs(
    input: &pb::ZkCredentialSubjectClaimInput,
) -> Result<CredentialSubjectClaimV1ClaimInputs, ZkError> {
    let link = input
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(CredentialSubjectClaimV1ClaimInputs {
        public_inputs: CredentialSubjectClaimV1ClaimPublicInputs {
            issuer_context: issuer_context(&input.issuer_context)?,
            session_binding_hash: SessionBindingHash::new(*bytes32(&input.session_binding)?),
            disclosure: claim_disclosure(&input.disclosure)?,
        },
        private_inputs: SecretInputs::new(CredentialSubjectClaimV1ClaimPrivateInputs {
            proof: merkle_claim_proof(&input.proof)?,
            link: SubjectClaimLink {
                issuer_subject_binding_signature: IssuerSubjectBindingSignature::new(*bytes64(
                    &link.issuer_subject_binding_signature,
                )?),
                subject_public_key: p256_public_key(&link.subject_public_key)?,
            },
        }),
    })
}

pub(super) fn private_persona_claim_inputs(
    input: &pb::ZkPrivatePersonaClaimInput,
) -> Result<PrivatePersonaClaimV1ClaimInputs, ZkError> {
    let link = input
        .link
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(PrivatePersonaClaimV1ClaimInputs {
        public_inputs: PrivatePersonaClaimV1ClaimPublicInputs {
            issuer_context: issuer_context(&input.issuer_context)?,
            session_binding_hash: SessionBindingHash::new(*bytes32(&input.session_binding)?),
            disclosure: claim_disclosure(&input.disclosure)?,
        },
        private_inputs: SecretInputs::new(PrivatePersonaClaimV1ClaimPrivateInputs {
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
        }),
    })
}

fn session_context(
    field: &MessageField<pb::ZkInputSessionContext, buffa::Inline<pb::ZkInputSessionContext>>,
) -> Result<SessionContext, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(SessionContext {
        challenge_nonce_hash: ChallengeNonceHash::new(*bytes32(&context.challenge)?),
        audience_hash: AudienceHash::new(*bytes32(&context.audience_hash)?),
        transaction_data_hash: TransactionDataHash::new(*bytes32(&context.transaction_data_hash)?),
        expiry_unix: UnixTimestamp::new(context.expiry_unix),
        session_binding_hash: SessionBindingHash::new(*bytes32(&context.session_binding)?),
    })
}

pub(super) fn issuer_context(
    field: &MessageField<pb::ZkInputIssuerContext, buffa::Inline<pb::ZkInputIssuerContext>>,
) -> Result<IssuerBoundContext, ZkError> {
    let context = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(IssuerBoundContext {
        issuer_public_key: p256_public_key(&context.issuer_public_key)?,
        challenge_nonce_hash: ChallengeNonceHash::new(*bytes32(&context.challenge)?),
        audience_hash: AudienceHash::new(*bytes32(&context.audience_hash)?),
        transaction_data_hash: TransactionDataHash::new(*bytes32(&context.transaction_data_hash)?),
        expiry_unix: UnixTimestamp::new(context.expiry_unix),
    })
}

pub(super) fn claim_disclosure(
    field: &MessageField<pb::ZkInputClaimDisclosure, buffa::Inline<pb::ZkInputClaimDisclosure>>,
) -> Result<ClaimDisclosure, ZkError> {
    let disclosure = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let length =
        ClaimValueLength::new(disclosure.value_length).map_err(super::map_witness_error)?;
    let value = bytes64(&disclosure.value)?;
    validate_claim_tail(&value, disclosure.value_length)?;
    Ok(ClaimDisclosure {
        credential_binding_hash: CredentialBindingHash::new(*bytes32(
            &disclosure.credential_binding,
        )?),
        claim_value: ClaimValue::new(*value, length),
        claim_name_hash: ClaimNameHash::new(*bytes32(&disclosure.claim_name_hash)?),
    })
}

pub(super) fn merkle_claim_proof(
    field: &MessageField<pb::ZkInputMerkleClaimProof, buffa::Inline<pb::ZkInputMerkleClaimProof>>,
) -> Result<MerkleClaimProof, ZkError> {
    let proof = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(MerkleClaimProof {
        envelope_hash: EnvelopeHash::new(*bytes32(&proof.envelope_hash)?),
        merkle_root: MerkleRoot::new(*bytes32(&proof.merkle_root)?),
        claim_salt: ClaimSalt::new(*bytes16(&proof.claim_salt)?),
        merkle_leaf_index: MerkleLeafIndex::new(proof.leaf_index),
        merkle_path: merkle_path(&proof.path)?,
    })
}

pub(super) fn merkle_path(
    field: &MessageField<pb::ZkInputMerklePath, buffa::Inline<pb::ZkInputMerklePath>>,
) -> Result<MerklePath, ZkError> {
    let path = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    if path.path_length > CLAIM_TREE_DEPTH_U32 || path.siblings.len() > CLAIM_TREE_DEPTH {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    if path.siblings.len() != CLAIM_TREE_DEPTH {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let length = MerklePathLength::new(path.path_length)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let mut siblings =
        core::array::from_fn(|_| MerkleSiblingHash::new([0_u8; FIELD_ELEMENT_BYTES]));
    for (index, sibling) in path.siblings.iter().enumerate() {
        let slot = siblings
            .get_mut(index)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        *slot = MerkleSiblingHash::new(*fixed_bytes(sibling.value.as_slice())?);
    }
    Ok(MerklePath::new(siblings, length))
}

pub(in crate::witness) fn p256_public_key(
    field: &MessageField<pb::ZkInputP256PublicKey, buffa::Inline<pb::ZkInputP256PublicKey>>,
) -> Result<P256PublicKey, ZkError> {
    let key = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    Ok(P256PublicKey {
        x: P256Coordinate::new(*bytes32(&key.x)?),
        y: P256Coordinate::new(*bytes32(&key.y)?),
    })
}

pub(in crate::witness) fn bytes32(
    field: &MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<Zeroizing<[u8; FIELD_ELEMENT_BYTES]>, ZkError> {
    let message = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    fixed_bytes(message.value.as_slice())
}

pub(super) fn bytes16(
    field: &MessageField<pb::ZkInputBytes16, buffa::Inline<pb::ZkInputBytes16>>,
) -> Result<Zeroizing<[u8; SALT_BYTES]>, ZkError> {
    let message = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    fixed_bytes(message.value.as_slice())
}

pub(in crate::witness) fn bytes64(
    field: &MessageField<pb::ZkInputBytes64, buffa::Inline<pb::ZkInputBytes64>>,
) -> Result<Zeroizing<[u8; SIGNATURE_BYTES]>, ZkError> {
    let message = field
        .as_option()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    fixed_bytes(message.value.as_slice())
}

/// Copy an exact-length field into a zeroizing owner.
///
/// The request fields these helpers read carry private witness material as
/// well as public inputs, so the bytes are written straight into the owner and
/// are wiped when it drops, including on a caller's early return.
pub(in crate::witness) fn fixed_bytes<const N: usize>(
    bytes: &[u8],
) -> Result<Zeroizing<[u8; N]>, ZkError> {
    if bytes.len() != N {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    let mut owned = Zeroizing::new([0_u8; N]);
    owned.copy_from_slice(bytes);
    Ok(owned)
}

fn validate_claim_tail(value: &[u8; MAX_CLAIM_VALUE_BYTES], length: u32) -> Result<(), ZkError> {
    let active =
        usize::try_from(length).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if active > MAX_CLAIM_VALUE_BYTES {
        return Err(ZkError::new(ZkErrorReason::ClaimPayloadTooLarge));
    }
    if value
        .get(active..)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}
