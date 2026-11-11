// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    common_root::{
        ZkCommonCredentialRootClaimExpectation, ZkCommonCredentialRootIssuerStatusExpectation,
        ZkCommonCredentialRootJoinPolicy, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootProof, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootRawPublicInputs, ZkCommonCredentialRootVerifyRequest,
        COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusPurpose,
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH},
};

const FIELD_BYTES: usize = 32;
const REQUEST_TIME: u64 = 1_900_000_000;
const EXPIRY: u64 = REQUEST_TIME + 180;
const CHALLENGE: [u8; 32] = [0x11; 32];
const AUDIENCE: [u8; 32] = [0x22; 32];
const ROOT_JOIN: [u8; 32] = [0x44; 32];
const ATTESTATION_JOIN: [u8; 32] = [0x55; 32];
const STATUS_ROOT: [u8; 32] = [0x66; 32];
const SESSION_BINDING: [u8; 32] = [0x88; 32];
const FIRST_NAME: [u8; 32] = [0x91; 32];
const SECOND_NAME: [u8; 32] = [0x92; 32];
const FIRST_VALUE: &[u8] = b"degree";
const SECOND_VALUE: &[u8] = b"employed";

#[test]
fn verification_request_rejects_mixed_hash_lanes() -> Result<(), ZkError> {
    let mut proofs = proofs_for(ZkCredentialHashAlgorithm::Sha256)?;
    let poseidon2_lineage = proof_for(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::Lineage1,
    )?;
    proofs[usize::from(ZkCommonCredentialRootProofSlot::Lineage1.index())] = poseidon2_lineage;

    let error = match ZkCommonCredentialRootVerifyRequest::try_new(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
        ZkProofSuite::PRODUCTION,
        binding(),
        proofs.as_slice(),
        policy(),
    ) {
        Ok(_) => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
        Err(error) => error,
    };
    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn verification_request_accepts_single_hash_lane_shape() -> Result<(), ZkError> {
    let proofs = proofs_for(ZkCredentialHashAlgorithm::Sha256)?;
    let request = ZkCommonCredentialRootVerifyRequest::try_new(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
        ZkProofSuite::PRODUCTION,
        binding(),
        proofs.as_slice(),
        policy(),
    )?;
    assert_eq!(
        request.expected_credential_hash_algorithm(),
        ZkCredentialHashAlgorithm::Sha256
    );
    Ok(())
}

fn proofs_for(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<Vec<ZkCommonCredentialRootProof>, ZkError> {
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for slot in ZkCommonCredentialRootProofSlot::ALL {
        proofs.push(proof_for(credential_hash_algorithm, *slot)?);
    }
    Ok(proofs)
}

fn proof_for(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<ZkCommonCredentialRootProof, ZkError> {
    let circuit_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona
        .source_ref(credential_hash_algorithm, slot);
    let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        circuit_ref,
        raw_inputs(circuit_ref, slot),
    )?;
    ZkCommonCredentialRootProof::try_from_parts(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        slot,
        ZkProofSuite::PRODUCTION,
        ZkArtifactManifestDigest::from_bytes([0x77; 32]),
        ZkProofBytes::try_copy_from_slice(&[slot.index() + 1])?,
        public_inputs,
    )
}

fn raw_inputs(circuit_ref: ZkCircuitRef, slot: ZkCommonCredentialRootProofSlot) -> Vec<u8> {
    let field_count = match circuit_ref.stage {
        crate::circuits::ZkCircuitStage::RootAttestation => 258,
        crate::circuits::ZkCircuitStage::RootStatus => 192,
        crate::circuits::ZkCircuitStage::Lineage => 257,
        crate::circuits::ZkCircuitStage::IssuerCredentialStatus => 292,
        crate::circuits::ZkCircuitStage::PrivatePersonaClaim => 354,
        crate::circuits::ZkCircuitStage::Session => 129,
        _ => 0,
    };
    let mut fields = vec![0_u8; field_count * FIELD_BYTES];
    let request_start = match circuit_ref.stage {
        crate::circuits::ZkCircuitStage::RootAttestation => 98,
        crate::circuits::ZkCircuitStage::RootStatus
        | crate::circuits::ZkCircuitStage::Lineage
        | crate::circuits::ZkCircuitStage::IssuerCredentialStatus
        | crate::circuits::ZkCircuitStage::Session => 0,
        crate::circuits::ZkCircuitStage::PrivatePersonaClaim => 64,
        _ => 0,
    };
    set_request(&mut fields, request_start);
    match circuit_ref.stage {
        crate::circuits::ZkCircuitStage::RootAttestation => {
            set_key(&mut fields, 0, issuer(0xa0));
            set_bytes(&mut fields, 64, &[0x77; 32]);
            set_u64(&mut fields, 96, REQUEST_TIME);
            set_u64(&mut fields, 97, EXPIRY);
            set_bytes(&mut fields, 194, &ROOT_JOIN);
            set_bytes(&mut fields, 226, &ATTESTATION_JOIN);
        }
        crate::circuits::ZkCircuitStage::RootStatus => {
            set_bytes(&mut fields, 96, &STATUS_ROOT);
            set_bytes(&mut fields, 128, &ROOT_JOIN);
            set_bytes(&mut fields, 160, &ATTESTATION_JOIN);
        }
        crate::circuits::ZkCircuitStage::Lineage => {
            set_bytes(&mut fields, 96, &ROOT_JOIN);
            set_key(&mut fields, 128, credential_issuer(slot));
            set_u64(&mut fields, 192, EXPIRY);
            set_bytes(&mut fields, 193, &credential_binding(slot));
            set_bytes(&mut fields, 225, &subject_join(slot));
        }
        crate::circuits::ZkCircuitStage::IssuerCredentialStatus => {
            set_key(&mut fields, 96, credential_issuer(slot));
            set_u64(&mut fields, 160, EXPIRY);
            set_bytes(&mut fields, 161, &credential_binding(slot));
            set_bytes(&mut fields, 193, &status_root(slot));
            set_u64(&mut fields, 225, 256);
            set_bytes(&mut fields, 226, &status_list_id(slot));
            set_bytes(&mut fields, 258, &status_url_hash(slot));
            set_bytes(&mut fields, 290, &[1]);
            set_u64(&mut fields, 291, REQUEST_TIME);
        }
        crate::circuits::ZkCircuitStage::PrivatePersonaClaim => {
            let value = claim_value(slot);
            set_key(&mut fields, 0, credential_issuer(slot));
            set_u64(&mut fields, 160, EXPIRY);
            set_bytes(&mut fields, 161, &SESSION_BINDING);
            set_bytes(&mut fields, 193, &credential_binding(slot));
            set_bytes(&mut fields, 225, &subject_join(slot));
            let value_length = u32::try_from(value.len()).unwrap_or_default();
            set_u32(&mut fields, 257, value_length);
            set_bytes(&mut fields, 258, value);
            set_bytes(&mut fields, 322, &claim_name(slot));
        }
        crate::circuits::ZkCircuitStage::Session => {
            set_u64(&mut fields, 96, EXPIRY);
            set_bytes(&mut fields, 97, &SESSION_BINDING);
        }
        _ => {}
    }
    fields
}

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: None,
    }
}

fn policy() -> ZkCommonCredentialRootJoinPolicy<'static> {
    ZkCommonCredentialRootJoinPolicy {
        challenge: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: ABSENT_TRANSACTION_DATA_HASH,
        request_time_unix: REQUEST_TIME,
        status_validation_time_unix: REQUEST_TIME,
        status_validation_max_age_seconds: 120,
        attestation_signer: crate::keys::ZkAttestationPublicKey::from(
            crate::keys::ZkP256PublicKey::from(issuer(0xa0)),
        ),
        assurance_policy_id: [0x77; 32],
        status_root: STATUS_ROOT,
        claims: [
            ZkCommonCredentialRootClaimExpectation {
                issuer: issuer(0xc0),
                claim_name_hash: FIRST_NAME,
                value: FIRST_VALUE,
            },
            ZkCommonCredentialRootClaimExpectation {
                issuer: issuer(0xc2),
                claim_name_hash: SECOND_NAME,
                value: SECOND_VALUE,
            },
        ],
        issuer_status: [
            ZkCommonCredentialRootIssuerStatusExpectation {
                root: [0x99; 32],
                length: 256,
                list_id: [0x98; 32],
                url_hash: [0x97; 32],
                purpose: ZkIssuerStatusPurpose::Revocation,
            },
            ZkCommonCredentialRootIssuerStatusExpectation {
                root: [0x9a; 32],
                length: 256,
                list_id: [0x9b; 32],
                url_hash: [0x9c; 32],
                purpose: ZkIssuerStatusPurpose::Revocation,
            },
        ],
        persona_mode: ZkCommonCredentialRootPersonaMode::PrivatePersona,
    }
}

fn credential_issuer(slot: ZkCommonCredentialRootProofSlot) -> ZkIssuerPublicKey {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => issuer(0xc2),
        _ => issuer(0xc0),
    }
}

fn credential_binding(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => [0xd2; 32],
        _ => [0xd1; 32],
    }
}

fn subject_join(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1 => [0xe2; 32],
        _ => [0xe1; 32],
    }
}

fn claim_name(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::SelectedClaim1 {
        SECOND_NAME
    } else {
        FIRST_NAME
    }
}

fn claim_value(slot: ZkCommonCredentialRootProofSlot) -> &'static [u8] {
    if slot == ZkCommonCredentialRootProofSlot::SelectedClaim1 {
        SECOND_VALUE
    } else {
        FIRST_VALUE
    }
}

fn status_root(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 {
        [0x9a; 32]
    } else {
        [0x99; 32]
    }
}

fn status_list_id(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 {
        [0x9b; 32]
    } else {
        [0x98; 32]
    }
}

fn status_url_hash(slot: ZkCommonCredentialRootProofSlot) -> [u8; 32] {
    if slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 {
        [0x9c; 32]
    } else {
        [0x97; 32]
    }
}

fn issuer(marker: u8) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [marker; 32],
        y: [marker + 1; 32],
    }
}

fn set_request(fields: &mut [u8], first: usize) {
    set_bytes(fields, first, &CHALLENGE);
    set_bytes(fields, first + 32, &AUDIENCE);
    set_bytes(fields, first + 64, &ABSENT_TRANSACTION_DATA_HASH);
}

fn set_bytes(fields: &mut [u8], first: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        let index = (first + offset) * FIELD_BYTES + FIELD_BYTES - 1;
        fields[index] = *byte;
    }
}

fn set_key(fields: &mut [u8], first: usize, key: ZkIssuerPublicKey) {
    set_bytes(fields, first, &key.x);
    set_bytes(fields, first + 32, &key.y);
}

fn set_u64(fields: &mut [u8], index: usize, value: u64) {
    let start = index * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn set_u32(fields: &mut [u8], index: usize, value: u32) {
    let start = index * FIELD_BYTES + FIELD_BYTES - 4;
    fields[start..start + 4].copy_from_slice(&value.to_be_bytes());
}
