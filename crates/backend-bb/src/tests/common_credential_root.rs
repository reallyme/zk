// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::Ordering;

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    common_root::{
        verify_common_credential_root_with, ZkCommonCredentialRootClaimExpectation,
        ZkCommonCredentialRootIssuerStatusExpectation, ZkCommonCredentialRootJoinPolicy,
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProof,
        ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootRawPublicInputs,
        ZkCommonCredentialRootVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusPurpose,
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding, ABSENT_TRANSACTION_DATA_HASH},
};
use reallyme_zk_artifacts::{ArtifactKind, Digest32, VerifiedArtifactBytes};

use super::{
    BarretenbergBundleProvider, BbExactCircuitArtifacts, CountingCommonCredentialRootBackend,
    StaticArtifactResolver,
};

const COMMON_CREDENTIAL_ROOT_FIELD_BYTES: usize = 32;
const COMMON_CREDENTIAL_ROOT_NOW: u64 = 1_900_000_000;
const COMMON_CREDENTIAL_ROOT_EXPIRY: u64 = COMMON_CREDENTIAL_ROOT_NOW + 180;
const COMMON_CREDENTIAL_ROOT_CHALLENGE: [u8; 32] = [0x11; 32];
const COMMON_CREDENTIAL_ROOT_AUDIENCE: [u8; 32] = [0x22; 32];
const COMMON_CREDENTIAL_ROOT_POLICY_ID: [u8; 32] = [0x77; 32];
const COMMON_CREDENTIAL_ROOT_STATUS_ROOT: [u8; 32] = [0x66; 32];
const COMMON_CREDENTIAL_ROOT_JOIN: [u8; 32] = [0x44; 32];
const COMMON_CREDENTIAL_ROOT_ATTESTATION_JOIN: [u8; 32] = [0x55; 32];
const COMMON_CREDENTIAL_ROOT_SESSION_BINDING: [u8; 32] = [0x88; 32];
const COMMON_CREDENTIAL_ROOT_FIRST_NAME: [u8; 32] = [0x91; 32];
const COMMON_CREDENTIAL_ROOT_SECOND_NAME: [u8; 32] = [0x92; 32];
const COMMON_CREDENTIAL_ROOT_FIRST_VALUE: &[u8] = b"degree";
const COMMON_CREDENTIAL_ROOT_SECOND_VALUE: &[u8] = b"employed";

pub(super) fn common_credential_root_artifact_identity(
    circuit_ref: ZkCircuitRef,
) -> ZkArtifactManifestDigest {
    let stage_marker = match circuit_ref.stage {
        ZkCircuitStage::RootAttestation => 1,
        ZkCircuitStage::RootStatus => 2,
        ZkCircuitStage::Lineage => 3,
        ZkCircuitStage::PrivatePersonaClaim => 4,
        ZkCircuitStage::PublicPersonaClaim => 5,
        ZkCircuitStage::Session => 6,
        ZkCircuitStage::IssuerCredentialStatus => 7,
        _ => 0,
    };
    let hash_marker = match circuit_ref.credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => 0x50,
        ZkCredentialHashAlgorithm::Poseidon2 => 0x60,
        _ => 0x70,
    };
    let mut bytes = [0_u8; 32];
    bytes[0] = hash_marker;
    bytes[1] = stage_marker;
    ZkArtifactManifestDigest::from_bytes(bytes)
}

pub(super) fn common_credential_root_artifacts(
    circuit_ref: ZkCircuitRef,
    slot: ZkCommonCredentialRootProofSlot,
    artifact_identity: ZkArtifactManifestDigest,
) -> Result<BbExactCircuitArtifacts, ZkError> {
    let bytecode_bytes = vec![0x40, slot.index()];
    let verification_key_bytes = vec![0x80, slot.index()];
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        bytecode_bytes.clone(),
        Digest32::sha256(bytecode_bytes.as_slice()),
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key_bytes.clone(),
        Digest32::sha256(verification_key_bytes.as_slice()),
    )?;
    BbExactCircuitArtifacts::try_new(circuit_ref, artifact_identity, bytecode, verification_key)
}

fn common_credential_root_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: COMMON_CREDENTIAL_ROOT_CHALLENGE,
        audience_hash: COMMON_CREDENTIAL_ROOT_AUDIENCE,
        transaction_data_hash: None,
    }
}

fn common_credential_root_policy() -> ZkCommonCredentialRootJoinPolicy<'static> {
    ZkCommonCredentialRootJoinPolicy {
        challenge: COMMON_CREDENTIAL_ROOT_CHALLENGE,
        audience_hash: COMMON_CREDENTIAL_ROOT_AUDIENCE,
        transaction_data_hash: ABSENT_TRANSACTION_DATA_HASH,
        request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
        status_validation_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
        status_validation_max_age_seconds: 120,
        attestation_signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(common_credential_root_issuer(0xa0)),
        ),
        assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
        status_root: COMMON_CREDENTIAL_ROOT_STATUS_ROOT,
        claims: [
            ZkCommonCredentialRootClaimExpectation {
                issuer: common_credential_root_issuer(0xc0),
                claim_name_hash: COMMON_CREDENTIAL_ROOT_FIRST_NAME,
                value: COMMON_CREDENTIAL_ROOT_FIRST_VALUE,
            },
            ZkCommonCredentialRootClaimExpectation {
                issuer: common_credential_root_issuer(0xc2),
                claim_name_hash: COMMON_CREDENTIAL_ROOT_SECOND_NAME,
                value: COMMON_CREDENTIAL_ROOT_SECOND_VALUE,
            },
        ],
        issuer_status: [ZkCommonCredentialRootIssuerStatusExpectation {
            root: [0xa1; 32],
            length: 256,
            list_id: [0xa2; 32],
            url_hash: [0xa3; 32],
            purpose: ZkIssuerStatusPurpose::Revocation,
        }; 2],
        persona_mode: ZkCommonCredentialRootPersonaMode::PrivatePersona,
    }
}

const fn common_credential_root_issuer(marker: u8) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [marker; 32],
        y: [marker + 1; 32],
    }
}

fn common_credential_root_proofs() -> Result<Vec<ZkCommonCredentialRootProof>, ZkError> {
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for slot in ZkCommonCredentialRootProofSlot::ALL {
        let circuit_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona
            .source_ref(ZkCredentialHashAlgorithm::Sha256, *slot);
        let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
            circuit_ref,
            common_credential_root_raw_public_inputs(*slot),
        )?;
        proofs.push(ZkCommonCredentialRootProof::try_from_parts(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            *slot,
            ZkProofSuite::PRODUCTION,
            common_credential_root_artifact_identity(circuit_ref),
            ZkProofBytes::try_copy_from_slice(&[slot.index().saturating_add(1)])?,
            public_inputs,
        )?);
    }
    Ok(proofs)
}

fn common_credential_root_raw_public_inputs(slot: ZkCommonCredentialRootProofSlot) -> Vec<u8> {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => {
            common_credential_root_attestation_inputs()
        }
        ZkCommonCredentialRootProofSlot::RootStatus => common_credential_root_status_inputs(),
        ZkCommonCredentialRootProofSlot::Lineage0 => common_credential_root_lineage_inputs(0),
        ZkCommonCredentialRootProofSlot::Lineage1 => common_credential_root_lineage_inputs(1),
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => common_credential_root_claim_inputs(0),
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => common_credential_root_claim_inputs(1),
        ZkCommonCredentialRootProofSlot::Session => common_credential_root_session_inputs(),
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
            common_credential_root_issuer_credential_status_inputs(0)
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            common_credential_root_issuer_credential_status_inputs(1)
        }
        _ => Vec::new(),
    }
}

fn common_credential_root_attestation_inputs() -> Vec<u8> {
    let mut fields = vec![0_u8; 258 * COMMON_CREDENTIAL_ROOT_FIELD_BYTES];
    common_credential_root_set_key(&mut fields, 0, common_credential_root_issuer(0xa0));
    common_credential_root_set_bytes(&mut fields, 64, &COMMON_CREDENTIAL_ROOT_POLICY_ID);
    common_credential_root_set_u64(&mut fields, 96, COMMON_CREDENTIAL_ROOT_NOW);
    common_credential_root_set_u64(&mut fields, 97, COMMON_CREDENTIAL_ROOT_EXPIRY);
    common_credential_root_set_request(&mut fields, 98);
    common_credential_root_set_bytes(&mut fields, 194, &COMMON_CREDENTIAL_ROOT_JOIN);
    common_credential_root_set_bytes(&mut fields, 226, &COMMON_CREDENTIAL_ROOT_ATTESTATION_JOIN);
    fields
}

fn common_credential_root_status_inputs() -> Vec<u8> {
    let mut fields = vec![0_u8; 192 * COMMON_CREDENTIAL_ROOT_FIELD_BYTES];
    common_credential_root_set_request(&mut fields, 0);
    common_credential_root_set_bytes(&mut fields, 96, &COMMON_CREDENTIAL_ROOT_STATUS_ROOT);
    common_credential_root_set_bytes(&mut fields, 128, &COMMON_CREDENTIAL_ROOT_JOIN);
    common_credential_root_set_bytes(&mut fields, 160, &COMMON_CREDENTIAL_ROOT_ATTESTATION_JOIN);
    fields
}

fn common_credential_root_lineage_inputs(slot: usize) -> Vec<u8> {
    let mut fields = vec![0_u8; 257 * COMMON_CREDENTIAL_ROOT_FIELD_BYTES];
    common_credential_root_set_request(&mut fields, 0);
    common_credential_root_set_bytes(&mut fields, 96, &COMMON_CREDENTIAL_ROOT_JOIN);
    common_credential_root_set_key(
        &mut fields,
        128,
        common_credential_root_credential_issuer(slot),
    );
    common_credential_root_set_u64(&mut fields, 192, COMMON_CREDENTIAL_ROOT_EXPIRY);
    common_credential_root_set_bytes(
        &mut fields,
        193,
        &common_credential_root_credential_binding(slot),
    );
    common_credential_root_set_bytes(
        &mut fields,
        225,
        &common_credential_root_subject_binding(slot),
    );
    fields
}

fn common_credential_root_claim_inputs(slot: usize) -> Vec<u8> {
    let mut fields = vec![0_u8; 354 * COMMON_CREDENTIAL_ROOT_FIELD_BYTES];
    let value = common_credential_root_claim_value(slot);
    common_credential_root_set_key(
        &mut fields,
        0,
        common_credential_root_credential_issuer(slot),
    );
    common_credential_root_set_request(&mut fields, 64);
    common_credential_root_set_u64(&mut fields, 160, COMMON_CREDENTIAL_ROOT_EXPIRY);
    common_credential_root_set_bytes(&mut fields, 161, &COMMON_CREDENTIAL_ROOT_SESSION_BINDING);
    common_credential_root_set_bytes(
        &mut fields,
        193,
        &common_credential_root_credential_binding(slot),
    );
    common_credential_root_set_bytes(
        &mut fields,
        225,
        &common_credential_root_subject_binding(slot),
    );
    common_credential_root_set_u32(&mut fields, 257, u32::try_from(value.len()).unwrap_or(0));
    common_credential_root_set_bytes(&mut fields, 258, value);
    common_credential_root_set_bytes(&mut fields, 322, &common_credential_root_claim_name(slot));
    fields
}

fn common_credential_root_session_inputs() -> Vec<u8> {
    let mut fields = vec![0_u8; 129 * COMMON_CREDENTIAL_ROOT_FIELD_BYTES];
    common_credential_root_set_request(&mut fields, 0);
    common_credential_root_set_u64(&mut fields, 96, COMMON_CREDENTIAL_ROOT_EXPIRY);
    common_credential_root_set_bytes(&mut fields, 97, &COMMON_CREDENTIAL_ROOT_SESSION_BINDING);
    fields
}

fn common_credential_root_issuer_credential_status_inputs(slot: usize) -> Vec<u8> {
    let mut fields = vec![0_u8; 292 * COMMON_CREDENTIAL_ROOT_FIELD_BYTES];
    common_credential_root_set_request(&mut fields, 0);
    common_credential_root_set_key(
        &mut fields,
        96,
        common_credential_root_credential_issuer(slot),
    );
    common_credential_root_set_u64(&mut fields, 160, COMMON_CREDENTIAL_ROOT_EXPIRY);
    common_credential_root_set_bytes(
        &mut fields,
        161,
        &common_credential_root_credential_binding(slot),
    );
    common_credential_root_set_bytes(&mut fields, 193, &[0xa1; 32]);
    common_credential_root_set_u64(&mut fields, 225, 256);
    common_credential_root_set_bytes(&mut fields, 226, &[0xa2; 32]);
    common_credential_root_set_bytes(&mut fields, 258, &[0xa3; 32]);
    common_credential_root_set_bytes(&mut fields, 290, &[1]);
    common_credential_root_set_u64(&mut fields, 291, COMMON_CREDENTIAL_ROOT_NOW);
    fields
}

fn common_credential_root_credential_issuer(slot: usize) -> ZkIssuerPublicKey {
    if slot == 0 {
        common_credential_root_issuer(0xc0)
    } else {
        common_credential_root_issuer(0xc2)
    }
}

fn common_credential_root_credential_binding(slot: usize) -> [u8; 32] {
    if slot == 0 {
        [0xd1; 32]
    } else {
        [0xd2; 32]
    }
}

fn common_credential_root_subject_binding(slot: usize) -> [u8; 32] {
    if slot == 0 {
        [0xe1; 32]
    } else {
        [0xe2; 32]
    }
}

fn common_credential_root_claim_name(slot: usize) -> [u8; 32] {
    if slot == 0 {
        COMMON_CREDENTIAL_ROOT_FIRST_NAME
    } else {
        COMMON_CREDENTIAL_ROOT_SECOND_NAME
    }
}

fn common_credential_root_claim_value(slot: usize) -> &'static [u8] {
    if slot == 0 {
        COMMON_CREDENTIAL_ROOT_FIRST_VALUE
    } else {
        COMMON_CREDENTIAL_ROOT_SECOND_VALUE
    }
}

fn common_credential_root_set_request(fields: &mut [u8], first: usize) {
    common_credential_root_set_bytes(fields, first, &COMMON_CREDENTIAL_ROOT_CHALLENGE);
    common_credential_root_set_bytes(fields, first + 32, &COMMON_CREDENTIAL_ROOT_AUDIENCE);
    common_credential_root_set_bytes(fields, first + 64, &ABSENT_TRANSACTION_DATA_HASH);
}

fn common_credential_root_set_key(fields: &mut [u8], first: usize, key: ZkIssuerPublicKey) {
    common_credential_root_set_bytes(fields, first, &key.x);
    common_credential_root_set_bytes(fields, first + 32, &key.y);
}

fn common_credential_root_set_bytes(fields: &mut [u8], first: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        let index = (first + offset) * COMMON_CREDENTIAL_ROOT_FIELD_BYTES
            + COMMON_CREDENTIAL_ROOT_FIELD_BYTES
            - 1;
        fields[index] = *byte;
    }
}

fn common_credential_root_set_u64(fields: &mut [u8], index: usize, value: u64) {
    let start = index * COMMON_CREDENTIAL_ROOT_FIELD_BYTES + COMMON_CREDENTIAL_ROOT_FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn common_credential_root_set_u32(fields: &mut [u8], index: usize, value: u32) {
    let start = index * COMMON_CREDENTIAL_ROOT_FIELD_BYTES + COMMON_CREDENTIAL_ROOT_FIELD_BYTES - 4;
    fields[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn common_credential_root_provider_verifies_all_slots_before_join_success() -> Result<(), ZkError> {
    let backend = CountingCommonCredentialRootBackend::new();
    let provider = BarretenbergBundleProvider::new(backend, StaticArtifactResolver::matching());
    let proofs = common_credential_root_proofs()?;
    let request = ZkCommonCredentialRootVerifyRequest::try_new(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
        ZkProofSuite::PRODUCTION,
        common_credential_root_binding(),
        proofs.as_slice(),
        common_credential_root_policy(),
    )?;

    let verified = verify_common_credential_root_with(&provider, request)?;

    assert_eq!(verified.verified_proof_count(), 9);
    assert_eq!(
        provider
            .backend()
            .common_credential_root_calls
            .load(Ordering::SeqCst),
        9
    );
    Ok(())
}

#[test]
fn common_credential_root_provider_rejects_unsealed_artifact_identity_before_backend(
) -> Result<(), ZkError> {
    let backend = CountingCommonCredentialRootBackend::new();
    let provider = BarretenbergBundleProvider::new(
        backend,
        StaticArtifactResolver::wrong_common_credential_root_artifact_identity(),
    );
    let proofs = common_credential_root_proofs()?;
    let request = ZkCommonCredentialRootVerifyRequest::try_new(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCredentialHashAlgorithm::Sha256,
        ZkProofSuite::PRODUCTION,
        common_credential_root_binding(),
        proofs.as_slice(),
        common_credential_root_policy(),
    )?;
    let error = verify_common_credential_root_with(&provider, request)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    assert_eq!(
        provider
            .backend()
            .common_credential_root_calls
            .load(Ordering::SeqCst),
        0
    );
    Ok(())
}
