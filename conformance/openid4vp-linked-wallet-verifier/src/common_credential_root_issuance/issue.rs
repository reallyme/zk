// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential::committed::proof_binding::issue_credential_proof_binding;
use reallyme_credential::{
    sign_credential_envelope, AssuranceLevel, CredentialEnvelope, CredentialError,
    CredentialIssuerSigner, CredentialKind, CredentialStatus, CredentialSubject, HolderBinding,
    PartyReference, PublicKeyIdentity,
};
use reallyme_credential_claims::{
    ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, DomainTags, Signature,
};
use reallyme_credential_status::{
    status_list_signing_payload, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusPurpose,
};
use reallyme_identity::zk::validate_zk_common_root_issuance;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        build_common_credential_root_poseidon2_claims_commitment,
        build_common_credential_root_sha256_claims_commitment,
        derive_common_credential_root_v1_lineage, ZkCommonCredentialRootClaim,
        ZkCommonCredentialRootSubjectPublicKey, COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING,
    },
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkSensitiveProviderRequest;
use zeroize::Zeroizing;

use crate::error::HarnessError;

use super::{
    crypto::{
        coordinates, coordinates_from_proto, hash_parts, input16, input32, issuance_policy,
        issuer_key, key_ref, public_key, raw_key, scalar, sign_raw, stage, verified_proof,
    },
    transport::transport_one,
    IssuedCredential, VerifiedZkStoredCredential, ISSUER_SCALARS, PROFILE_ID, STATUS_ISSUER_URLS,
    STATUS_LIST_IDS, STATUS_LIST_INDEX, SUBJECT_SCALARS,
};

const COMMON_CREDENTIAL_ROOT_MAX_CLAIM_VALUE_LEN: u32 = 64;
const COMMON_CREDENTIAL_ROOT_CLAIM_SALT_LEN: u32 = 16;
const SSI_SHA256_HASH_ALGORITHM: &str = "sha-256";
const SSI_POSEIDON2_HASH_ALGORITHM: &str = "poseidon2-bn254";

struct TestIssuer {
    secret: Zeroizing<[u8; 32]>,
    verification_key: reallyme_credential_claims::PublicKeyRef,
}

impl CredentialIssuerSigner for TestIssuer {
    fn verification_key(&self) -> &reallyme_credential_claims::PublicKeyRef {
        &self.verification_key
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        sign_raw(&self.secret, payload)
            .map(|signature| signature.to_vec())
            .map_err(|_| {
                CredentialError::Signature(
                    reallyme_credential::CredentialSignatureReason::SigningFailed,
                )
            })
    }
}

pub(super) fn issue_and_transport_credentials_for_stage_requests(
    requests: &[ZkSensitiveProviderRequest],
    request_time: u64,
) -> Result<(VerifiedZkStoredCredential, VerifiedZkStoredCredential), HarnessError> {
    if requests.len() != 9 {
        return Err(HarnessError::InvalidLength);
    }
    let first = issue_one(
        &requests[2],
        &requests[4],
        ISSUER_SCALARS[0],
        SUBJECT_SCALARS[0],
        "university",
        request_time,
    )?;
    let second = issue_one(
        &requests[3],
        &requests[5],
        ISSUER_SCALARS[1],
        SUBJECT_SCALARS[1],
        "employer",
        request_time,
    )?;
    let first = transport_one(first, ISSUER_SCALARS[0], SUBJECT_SCALARS[0])?;
    let second = transport_one(second, ISSUER_SCALARS[1], SUBJECT_SCALARS[1])?;
    Ok((first, second))
}

fn issue_one(
    request: &ZkSensitiveProviderRequest,
    claim_request: &ZkSensitiveProviderRequest,
    issuer_scalar: u8,
    subject_scalar: u8,
    relationship: &str,
    request_time: u64,
) -> Result<IssuedCredential, HarnessError> {
    let lineage_stage = stage(request)?;
    let credential_hash_algorithm = stage_credential_hash_algorithm(lineage_stage)?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(input)) =
        lineage_stage.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let slot = input.slot.as_option().ok_or(HarnessError::MissingField)?;
    let witness = input
        .witness
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let issuer_fixture = slot
        .issuer_public_key
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let subject_fixture = witness
        .subject_public_key
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let issuer_secret = scalar(issuer_scalar);
    let subject_secret = scalar(subject_scalar);
    let issuer_public = public_key(&issuer_secret)?;
    let subject_public = public_key(&subject_secret)?;
    if coordinates(&issuer_public)? != coordinates_from_proto(issuer_fixture)?
        || coordinates(&subject_public)? != coordinates_from_proto(subject_fixture)?
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let issuer_coordinates = coordinates(&issuer_public)?;
    let subject_coordinates = coordinates(&subject_public)?;
    let status_role = match relationship {
        "university" => 0,
        "employer" => 1,
        _ => return Err(HarnessError::InvalidLength),
    };
    let lineage = derive_common_credential_root_v1_lineage(
        &input32(&input.root)?,
        ZkIssuerPublicKey {
            x: issuer_coordinates.0,
            y: issuer_coordinates.1,
        },
        &format!("did:me:fixture:{relationship}"),
        ZkCommonCredentialRootSubjectPublicKey {
            x: subject_coordinates.0,
            y: subject_coordinates.1,
        },
        &input32(&witness.relationship_nonce)?,
    )
    .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
    let claim_stage = stage(claim_request)?;
    if stage_credential_hash_algorithm(claim_stage)? != credential_hash_algorithm {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let (disclosure, claim_proof) = selected_claim_parts(claim_stage)?;
    let value = &disclosure
        .value
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .value;
    let value_length =
        usize::try_from(disclosure.value_length).map_err(|_| HarnessError::InvalidLength)?;
    let selected_value = value
        .get(..value_length)
        .ok_or(HarnessError::InvalidLength)?;
    let selected_name = format!("fixture selected claim name:{relationship}");
    if input32(&disclosure.claim_name_hash)? != hash_parts(&[selected_name.as_bytes()]) {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let selected_salt = input16(&claim_proof.claim_salt)?;
    let lineage_salt = input16(&witness.claim_salt)?;
    let claims = [ZkCommonCredentialRootClaim {
        name: &selected_name,
        value: selected_value,
        salt: &selected_salt,
    }];
    let commitment =
        build_claims_commitment(credential_hash_algorithm, &lineage, &lineage_salt, &claims)?;
    let private_lineage =
        reallyme_zk_api::common_root::ZkCommonCredentialRootPrivateLineageMaterial::new(
            input32(&input.root)?,
            format!("did:me:fixture:{relationship}"),
            input32(&witness.relationship_nonce)?,
            ZkIssuerPublicKey {
                x: issuer_coordinates.0,
                y: issuer_coordinates.1,
            },
            ZkCommonCredentialRootSubjectPublicKey {
                x: subject_coordinates.0,
                y: subject_coordinates.1,
            },
            &commitment,
        )
        .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
    let claims_root = commitment.root();
    if claims_root != input32(&witness.merkle_root)?
        || claims_root != input32(&claim_proof.merkle_root)?
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let signer = TestIssuer {
        secret: issuer_secret,
        verification_key: key_ref(&issuer_public),
    };
    let mut envelope = CredentialEnvelope {
        kind: CredentialKind::Generic,
        profile_id: PROFILE_ID.to_owned(),
        assurance: AssuranceLevel::High,
        issuer_reference: PartyReference::PublicKey(PublicKeyIdentity {
            alg: CredentialAlgorithm::P256,
            public_key: raw_key(&issuer_public),
        }),
        issuer_country: "MT".to_owned(),
        valid_from: 1,
        valid_until: 2_100_000_000,
        status: CredentialStatus {
            status_list_url: STATUS_ISSUER_URLS[status_role].to_owned(),
            status_list_id: STATUS_LIST_IDS[status_role],
            status_list_index: STATUS_LIST_INDEX,
            purpose: StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::Absent,
            holder_binding: HolderBinding::CryptographicKey(key_ref(&subject_public)),
        },
        claims_commitment: ClaimsCommitment {
            merkle_root: claims_root.to_vec(),
            claimset_id: PROFILE_ID.to_owned(),
            hash_alg: ssi_hash_algorithm(credential_hash_algorithm)?.to_owned(),
            value_encoding: COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING.to_owned(),
            domain_tags: DomainTags {
                clm: "CLM1".to_owned(),
                leaf: "LEAF1".to_owned(),
                node: "NODE1".to_owned(),
            },
            limits: CommitmentLimits {
                max_value_len: COMMON_CREDENTIAL_ROOT_MAX_CLAIM_VALUE_LEN,
                salt_len: COMMON_CREDENTIAL_ROOT_CLAIM_SALT_LEN,
            },
        },
        qeaa_compliance: None,
        issuer_signature: Signature {
            verification_key: signer.verification_key.clone(),
            raw_rs: vec![0_u8; 64],
        },
    };
    sign_credential_envelope(&mut envelope, &signer)?;
    let wrong_issuer_secret = scalar(
        issuer_scalar
            .checked_add(1)
            .ok_or(HarnessError::InvalidLength)?,
    );
    let wrong_issuer = TestIssuer {
        verification_key: key_ref(&public_key(&wrong_issuer_secret)?),
        secret: wrong_issuer_secret,
    };
    if issue_credential_proof_binding(&envelope, &wrong_issuer).is_ok() {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let binding = issue_credential_proof_binding(&envelope, &signer)?;
    // Fixture time is the verifier session clock. A wall-clock timestamp here
    // would make the signed-list freshness test depend on when CI runs.
    let issued_at = request_time;
    let next_update = issued_at
        .checked_add(3_600)
        .ok_or(HarnessError::InvalidLength)?;
    let mut status_list = StatusList {
        issuer: STATUS_ISSUER_URLS[status_role].to_owned(),
        purpose: StatusPurpose::Revocation,
        issued_at,
        next_update,
        encoded_list: vec![0_u8; 2],
        length: 16,
        list_id: Some(STATUS_LIST_IDS[status_role]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::P256,
            sig_bytes: Vec::new(),
        },
    };
    let status_payload = status_list_signing_payload(&status_list)?;
    status_list.signature.sig_bytes = sign_raw(&signer.secret, &status_payload)?.to_vec();
    let proof = verified_proof(&binding)?;
    validate_zk_common_root_issuance(
        &envelope,
        &proof,
        &binding,
        issuer_key(&binding),
        issuance_policy(STATUS_LIST_IDS[status_role]),
    )?;
    Ok(IssuedCredential {
        envelope,
        binding,
        status_list,
        private_claims: commitment,
        private_lineage,
        claim_name: selected_name,
        claim_value: Zeroizing::new(selected_value.to_vec()),
        claim_salt: Zeroizing::new(selected_salt),
    })
}

fn selected_claim_parts(
    stage: &pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<(&pb::ZkInputClaimDisclosure, &pb::ZkInputMerkleClaimProof), HarnessError> {
    match stage.input.as_ref() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => Ok((
            input
                .disclosure
                .as_option()
                .ok_or(HarnessError::MissingField)?,
            input.proof.as_option().ok_or(HarnessError::MissingField)?,
        )),
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PublicPersonaClaim(
            input,
        )) => Ok((
            input
                .disclosure
                .as_option()
                .ok_or(HarnessError::MissingField)?,
            input.proof.as_option().ok_or(HarnessError::MissingField)?,
        )),
        _ => Err(HarnessError::MissingField),
    }
}

fn build_claims_commitment(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    lineage: &reallyme_zk_api::common_root::ZkCommonCredentialRootDerivedLineage,
    lineage_salt: &[u8; 16],
    claims: &[ZkCommonCredentialRootClaim<'_>],
) -> Result<reallyme_zk_api::common_root::ZkCommonCredentialRootClaimsCommitment, HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            build_common_credential_root_sha256_claims_commitment(lineage, lineage_salt, claims)
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            build_common_credential_root_poseidon2_claims_commitment(lineage, lineage_salt, claims)
        }
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    }
    .map_err(|_| HarnessError::InvalidPresentationAccepted)
}

fn ssi_hash_algorithm(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<&'static str, HarnessError> {
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => Ok(SSI_SHA256_HASH_ALGORITHM),
        ZkCredentialHashAlgorithm::Poseidon2 => Ok(SSI_POSEIDON2_HASH_ALGORITHM),
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

fn stage_credential_hash_algorithm(
    stage: &pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<ZkCredentialHashAlgorithm, HarnessError> {
    let circuit_ref = stage
        .circuit_ref
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    match circuit_ref.credential_hash_algorithm.as_known() {
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256) => {
            Ok(ZkCredentialHashAlgorithm::Sha256)
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2) => {
            Ok(ZkCredentialHashAlgorithm::Poseidon2)
        }
        Some(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED) | None => {
            Err(HarnessError::InvalidPresentationAccepted)
        }
    }
}
