// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkIssuerStatusFeed, ZkPersonaCredentialEvidenceRawPublicInputs,
    ZkPersonaCredentialEvidenceSourceStage, FIELD_BYTES,
};
use crate::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::check_persona_credential_evidence_v1_joins,
    proofs::ZkProofSuite,
};

fn put_byte(bytes: &mut [u8], field: usize, value: u8) {
    bytes[field * FIELD_BYTES + FIELD_BYTES - 1] = value;
}

fn put_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn valid_claim() -> Vec<u8> {
    let mut bytes = vec![0_u8; 291 * FIELD_BYTES];
    for (field, value) in [(0, 1), (32, 2), (64, 3), (96, 4), (128, 5), (162, 6)] {
        put_byte(&mut bytes, field, value);
    }
    put_u64(&mut bytes, 160, 100);
    put_u64(&mut bytes, 161, 200);
    put_byte(&mut bytes, 194, 1);
    put_byte(&mut bytes, 195, 18);
    put_byte(&mut bytes, 259, 7);
    bytes
}

fn source(stage: ZkPersonaCredentialEvidenceSourceStage) -> crate::circuits::ZkCircuitRef {
    stage.source_ref(ZkCredentialHashAlgorithm::Sha256)
}

fn valid_status() -> Vec<u8> {
    let claim = valid_claim();
    let mut bytes = vec![0_u8; 292 * FIELD_BYTES];
    bytes[..194 * FIELD_BYTES].copy_from_slice(&claim[..194 * FIELD_BYTES]);
    put_byte(&mut bytes, 194, 8);
    put_u64(&mut bytes, 226, 1_000);
    put_byte(&mut bytes, 227, 9);
    put_byte(&mut bytes, 259, 10);
    put_byte(&mut bytes, 291, 1);
    bytes
}

#[test]
fn exact_claim_status_abi_and_join() -> Result<(), ZkError> {
    let claim_bytes = valid_claim();
    let claim = ZkPersonaCredentialEvidenceRawPublicInputs::try_copy_from_slice(
        source(ZkPersonaCredentialEvidenceSourceStage::PrivateClaim),
        &claim_bytes,
    )?;
    assert_eq!(claim.as_bytes(), claim_bytes);
    let status = ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
        source(ZkPersonaCredentialEvidenceSourceStage::CurrentState),
        valid_status(),
    )?;
    assert_eq!(
        claim.status_feed().err().map(|error| error.reason()),
        Some(ZkErrorReason::UnsupportedCircuit)
    );
    let mut name = [0_u8; 32];
    name[0] = 7;
    claim.validate_claim(&name, &[18])?;
    assert_eq!(
        claim.claim_selector_digest("copy-1")?,
        crate::persona_evidence::persona_credential_evidence_claim_selector_digest(
            "copy-1",
            ZkCredentialHashAlgorithm::Sha256,
            &name,
            &[18],
        )?
    );
    assert_eq!(
        status
            .claim_selector_digest("copy-1")
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UnsupportedCircuit)
    );
    assert_eq!(
        status
            .validate_claim(&name, &[18])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UnsupportedCircuit)
    );
    assert_eq!(
        claim
            .validate_claim(&name, &[19])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    let feed = status.status_feed()?;
    assert_eq!(feed.length, 1_000);
    assert_eq!(
        feed.purpose,
        crate::issuer_status::ZkIssuerStatusPurpose::Revocation
    );
    assert_eq!(feed.root[0], 8);
    let expected = ZkIssuerStatusFeed {
        root: feed.root,
        length: feed.length,
        list_id: feed.list_id,
        url_hash: feed.url_hash,
        purpose: feed.purpose,
    };
    status.validate_status_feed(&expected)?;
    let mut wrong_root = expected;
    wrong_root.root[0] ^= 1;
    assert_eq!(
        status
            .validate_status_feed(&wrong_root)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    let claim_join = claim.join(ZkProofSuite::PRODUCTION)?;
    let status_join = status.join(ZkProofSuite::PRODUCTION)?;
    assert!(check_persona_credential_evidence_v1_joins(&claim_join, &status_join, 199).is_ok());
    assert!(check_persona_credential_evidence_v1_joins(&claim_join, &status_join, 200).is_err());
    Ok(())
}

#[test]
fn malformed_public_fields_fail_closed() {
    let wrong_family = crate::circuits::ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        crate::circuits::ZkCircuitFamily::CommonCredentialRootV1,
        crate::circuits::ZkCircuitStage::Lineage,
    );
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(wrong_family, valid_claim())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UnsupportedCircuit)
    );
    let mut wrong_version = source(ZkPersonaCredentialEvidenceSourceStage::PrivateClaim);
    wrong_version.revision = 2;
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(wrong_version, valid_claim())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UnsupportedCircuit)
    );
    let mut wrong_length = valid_claim();
    wrong_length.pop();
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            source(ZkPersonaCredentialEvidenceSourceStage::PublicClaim),
            wrong_length
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );
    let mut noncanonical_byte = valid_claim();
    noncanonical_byte[0] = 1;
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            source(ZkPersonaCredentialEvidenceSourceStage::PublicClaim),
            noncanonical_byte,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );
    let mut nonzero_padding = valid_claim();
    put_byte(&mut nonzero_padding, 196, 1);
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            source(ZkPersonaCredentialEvidenceSourceStage::PrivateClaim),
            nonzero_padding,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );
    let mut wrong_purpose = valid_status();
    put_byte(&mut wrong_purpose, 291, 3);
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            source(ZkPersonaCredentialEvidenceSourceStage::CurrentState),
            wrong_purpose,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );
    let mut oversized_list = valid_status();
    put_u64(&mut oversized_list, 226, 1_000_001);
    assert_eq!(
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            source(ZkPersonaCredentialEvidenceSourceStage::CurrentState),
            oversized_list,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );
}
