// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRawPublicInputs,
        ZkPersonaCredentialEvidenceSourceStage, ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};

use super::{decode_persona_credential_evidence_proof_set, ZkPersonaCredentialEvidenceProofSet};

const FIELD_BYTES: usize = 32;
const PROFILE: ZkPersonaCredentialEvidenceMode =
    ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1;

struct ProofSet {
    issuer_envelope: ZkPersonaCredentialEvidenceStageProof,
    claim_root: ZkPersonaCredentialEvidenceStageProof,
    signed_validity: ZkPersonaCredentialEvidenceStageProof,
    selected_claim: ZkPersonaCredentialEvidenceStageProof,
    current_state: ZkPersonaCredentialEvidenceStageProof,
}

fn put_bytes(bytes: &mut [u8], start: usize, value: &[u8; FIELD_BYTES]) {
    for (offset, byte) in value.iter().enumerate() {
        bytes[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn put_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], field: usize, value: u32) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 4;
    bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_byte(bytes: &mut [u8], field: usize, value: u8) {
    bytes[field * FIELD_BYTES + FIELD_BYTES - 1] = value;
}

fn claim_fields(token: u8) -> Vec<u8> {
    let mut fields = vec![0_u8; 291 * FIELD_BYTES];
    put_bytes(&mut fields, 0, &[1; FIELD_BYTES]);
    put_bytes(&mut fields, 32, &[2; FIELD_BYTES]);
    put_bytes(&mut fields, 64, &[3; FIELD_BYTES]);
    put_bytes(&mut fields, 96, &[4; FIELD_BYTES]);
    put_bytes(&mut fields, 128, &[token; FIELD_BYTES]);
    put_u64(&mut fields, 160, 100);
    put_u64(&mut fields, 161, 200);
    put_bytes(&mut fields, 162, &[5; FIELD_BYTES]);
    put_u32(&mut fields, 194, 1);
    put_byte(&mut fields, 195, 18);
    put_bytes(&mut fields, 259, &[6; FIELD_BYTES]);
    fields
}

fn stage_fields(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    token: u8,
    status_root: u8,
) -> Vec<u8> {
    let claim = claim_fields(token);
    match stage {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope
        | ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => claim[..194 * FIELD_BYTES].to_vec(),
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => {
            let mut fields = vec![0_u8; 259 * FIELD_BYTES];
            fields[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
            put_bytes(&mut fields, 194, &[7; FIELD_BYTES]);
            put_bytes(&mut fields, 226, &[8; FIELD_BYTES]);
            put_byte(&mut fields, 258, 1);
            fields
        }
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => claim,
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => {
            let mut fields = vec![0_u8; 292 * FIELD_BYTES];
            fields[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
            put_bytes(&mut fields, 194, &[status_root; FIELD_BYTES]);
            put_u64(&mut fields, 226, 1_000);
            put_bytes(&mut fields, 227, &[7; FIELD_BYTES]);
            put_bytes(&mut fields, 259, &[8; FIELD_BYTES]);
            put_byte(&mut fields, 291, 1);
            fields
        }
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim => claim,
    }
}

fn proof_marker(stage: ZkPersonaCredentialEvidenceSourceStage) -> u8 {
    match stage {
        ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope => 1,
        ZkPersonaCredentialEvidenceSourceStage::ClaimRoot => 2,
        ZkPersonaCredentialEvidenceSourceStage::SignedValidity => 3,
        ZkPersonaCredentialEvidenceSourceStage::PublicClaim => 4,
        ZkPersonaCredentialEvidenceSourceStage::PrivateClaim => 5,
        ZkPersonaCredentialEvidenceSourceStage::CurrentState => 6,
    }
}

fn proof(
    stage: ZkPersonaCredentialEvidenceSourceStage,
    token: u8,
    status_root: u8,
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        PROFILE,
        ZkProofSuite::PRODUCTION,
        reallyme_zk_api::artifacts::ZkArtifactSetIdentity::from_bytes(
            *(ZkArtifactManifestDigest::from_bytes([proof_marker(stage); FIELD_BYTES])).as_bytes(),
        ),
        ZkProofBytes::try_from_bytes(vec![proof_marker(stage)])?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            stage.source_ref(ZkCredentialHashAlgorithm::Sha256),
            stage_fields(stage, token, status_root),
        )?,
    )
}

fn proof_set(token: u8, status_root: u8) -> Result<ProofSet, ZkError> {
    Ok(ProofSet {
        issuer_envelope: proof(
            ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
            token,
            status_root,
        )?,
        claim_root: proof(
            ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
            token,
            status_root,
        )?,
        signed_validity: proof(
            ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
            token,
            status_root,
        )?,
        selected_claim: proof(
            ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
            token,
            status_root,
        )?,
        current_state: proof(
            ZkPersonaCredentialEvidenceSourceStage::CurrentState,
            token,
            status_root,
        )?,
    })
}

#[test]
fn durable_wallet_evidence_is_exactly_four_canonical_proofs() -> Result<(), ZkError> {
    let proofs = proof_set(9, 10)?;
    let evidence = ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        proofs.issuer_envelope,
        proofs.claim_root,
        proofs.signed_validity,
        proofs.selected_claim,
    )?;
    let encoded = evidence.encode()?;
    let decoded = decode_persona_credential_evidence_proof_set(encoded.as_slice())?;

    assert_eq!(decoded.mode(), PROFILE);
    assert_eq!(
        decoded.credential_hash_algorithm(),
        ZkCredentialHashAlgorithm::Sha256
    );
    assert_eq!(decoded.encode()?.as_slice(), encoded.as_slice());
    Ok(())
}

#[test]
fn current_state_proof_cannot_be_stored_as_wallet_evidence() -> Result<(), ZkError> {
    let proofs = proof_set(9, 10)?;
    let result = ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        proofs.current_state,
        proofs.claim_root,
        proofs.signed_validity,
        proofs.selected_claim,
    );

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(ZkErrorReason::StageMismatch)
    );
    Ok(())
}

#[test]
fn durable_wallet_evidence_is_independent_of_current_status_root() -> Result<(), ZkError> {
    let first = proof_set(9, 10)?;
    let second = proof_set(9, 11)?;
    assert_ne!(
        first.current_state.public_inputs().status_feed()?.root,
        second.current_state.public_inputs().status_feed()?.root
    );

    let first_evidence = ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        first.issuer_envelope,
        first.claim_root,
        first.signed_validity,
        first.selected_claim,
    )?
    .encode()?;
    let second_evidence = ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        second.issuer_envelope,
        second.claim_root,
        second.signed_validity,
        second.selected_claim,
    )?
    .encode()?;

    assert_eq!(first_evidence.as_slice(), second_evidence.as_slice());
    Ok(())
}

#[test]
fn cross_token_wallet_evidence_fails_before_storage_acceptance() -> Result<(), ZkError> {
    let first = proof_set(9, 10)?;
    let second = proof_set(10, 10)?;
    let result = ZkPersonaCredentialEvidenceProofSet::try_from_parts(
        first.issuer_envelope,
        second.claim_root,
        first.signed_validity,
        first.selected_claim,
    );

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    Ok(())
}
