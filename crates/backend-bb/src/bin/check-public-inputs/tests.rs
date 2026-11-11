// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::ZkError,
    proofs::{ZkPublicInputDescriptor, ZkPublicInputs},
};

use super::{
    audit_file, fs, parse_arguments, AuditStage, BarretenbergPublicInputCodec, OsString,
    PublicInputAuditError, PublicInputAuditErrorReason, ZkCircuitStage, ZkClaimProofBundleKind,
    ZkCredentialHashAlgorithm,
};

impl PublicInputAuditError {
    const fn reason(self) -> PublicInputAuditErrorReason {
        self.reason
    }
}

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn parser_rejects_unknown_coordinates_and_extra_arguments() {
    let unknown = [
        "binary",
        "unknown",
        "credential_subject_claim_v1",
        "session",
        "/tmp/input",
    ]
    .map(OsString::from);
    let extra = [
        "binary",
        "sha256",
        "credential_subject_claim_v1",
        "session",
        "/tmp/input",
        "extra",
    ]
    .map(OsString::from);

    assert_eq!(
        parse_arguments(unknown).err().map(|error| error.reason()),
        Some(PublicInputAuditErrorReason::InvalidArguments)
    );
    assert_eq!(
        parse_arguments(extra).err().map(|error| error.reason()),
        Some(PublicInputAuditErrorReason::InvalidArguments)
    );
}

#[test]
fn parser_preserves_bundle_as_an_audit_only_stage() -> Result<(), PublicInputAuditError> {
    let arguments = [
        "binary",
        "poseidon2",
        "private_persona_claim_v1",
        "claim_bundle_4",
        "/tmp/input",
    ]
    .map(OsString::from);

    let parsed = parse_arguments(arguments)?;

    assert_eq!(parsed.stage, AuditStage::ClaimBundle4);
    assert_eq!(
        parsed.circuit_ref(),
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkClaimProofBundleKind::PrivatePersonaClaimV1.family(),
            ZkCircuitStage::ClaimBundle4,
        )
    );
    Ok(())
}

#[test]
fn exact_backend_fields_round_trip_through_a_bounded_file() -> Result<(), ZkError> {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let compact = ZkPublicInputs::try_from_bytes(vec![0_u8; descriptor.encoded_len()?])?;
    let serialized = BarretenbergPublicInputCodec::encode(circuit_ref, &compact)?;
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "reallyme-zk-public-input-audit-{}-{sequence}",
        std::process::id()
    ));
    fs::write(&path, serialized)
        .map_err(|_| ZkError::new(reallyme_zk_api::errors::ZkErrorReason::BackendFailure))?;

    let result = audit_file(circuit_ref, &path);
    fs::remove_file(path)
        .map_err(|_| ZkError::new(reallyme_zk_api::errors::ZkErrorReason::BackendFailure))?;

    assert!(result.is_ok());
    Ok(())
}
