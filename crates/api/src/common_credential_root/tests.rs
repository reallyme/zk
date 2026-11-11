// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
    ZkCommonCredentialRootRawPublicInputs, ZkCommonCredentialRootSourceStage,
    COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES, COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT,
};
use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::ZkErrorReason,
    proofs::ZkSessionBinding,
};

#[test]
fn common_credential_root_sources_are_in_canonical_registry() {
    assert_eq!(
        ZkCircuitRef::ALL
            .iter()
            .filter(|circuit_ref| circuit_ref.family == ZkCircuitFamily::CommonCredentialRootV1)
            .count(),
        ZkCredentialHashAlgorithm::ALL.len() * ZkCommonCredentialRootSourceStage::ALL.len()
    );
    assert_eq!(
        ZkCommonCredentialRootProofSlot::ALL.len(),
        COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT
    );
}

#[test]
fn common_credential_root_source_refs_match_imported_noir_tree() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let circuits_dir = crate_dir.join("../../circuits");

    for circuit_ref in ZkCircuitRef::ALL
        .iter()
        .filter(|circuit_ref| circuit_ref.family == ZkCircuitFamily::CommonCredentialRootV1)
    {
        let nargo = circuits_dir
            .join(circuit_ref.credential_hash_algorithm.source_dir())
            .join("families")
            .join(circuit_ref.family.source_dir())
            .join(circuit_ref.stage.source_dir())
            .join("Nargo.toml");

        assert!(
            nargo.is_file(),
            "missing common-credential-root source circuit: {nargo:?}"
        );
    }
}

#[test]
fn nine_bundle_kind_owns_public_session_source() {
    let private_session = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::Session,
    );
    let public_session = ZkCommonCredentialRootPersonaMode::PublicPersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::Session,
    );

    assert_eq!(
        private_session,
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::Session,
        )
    );
    assert_eq!(
        public_session,
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::PublicSession,
        )
    );
}

#[test]
fn common_credential_root_persona_mode_points_to_canonical_refs() {
    let credential_subject_claim = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    );
    assert!(ZkCircuitRef::ALL.contains(&credential_subject_claim));
    assert_eq!(
        credential_subject_claim.family,
        ZkCircuitFamily::CommonCredentialRootV1
    );
    assert_eq!(
        credential_subject_claim.stage,
        ZkCircuitStage::PrivatePersonaClaim
    );
}

#[test]
fn raw_public_inputs_use_exact_common_credential_root_lengths() -> Result<(), crate::errors::ZkError>
{
    let claim_ref = ZkCommonCredentialRootPersonaMode::PublicPersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    );
    let raw =
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(claim_ref, canonical_raw(claim_ref))?;
    assert_eq!(raw.circuit_ref(), claim_ref);
    assert_eq!(
        raw.as_bytes().len(),
        COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES
    );

    assert!(
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(claim_ref, vec![0_u8; 4096]).is_err()
    );
    Ok(())
}

#[test]
fn raw_public_inputs_reject_unregistered_refs() {
    let invalid_version = ZkCircuitRef {
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Poseidon2,
        family: ZkCircuitFamily::CommonCredentialRootV1,
        stage: ZkCircuitStage::Lineage,
        revision: 2,
    };
    let invalid_stage = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::Session,
    );

    assert!(ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        invalid_version,
        vec![0_u8; 8192]
    )
    .is_err());
    assert!(
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(invalid_stage, vec![0_u8; 8192])
            .is_err()
    );
}

#[test]
fn raw_public_inputs_reject_noncanonical_byte_fields() {
    let circuit_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    );
    let mut raw = canonical_raw(circuit_ref);
    raw[0] = 1;

    assert!(matches!(
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, raw),
        Err(error) if error.reason() == crate::errors::ZkErrorReason::InvalidProofEncoding
    ));
}

#[test]
fn raw_root_attestation_accepts_canonical_presentation_expiry() -> Result<(), crate::errors::ZkError>
{
    let circuit_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    );
    let mut canonical = canonical_raw(circuit_ref);
    set_u64(&mut canonical, 97, 1_900_000_180);

    let public_inputs =
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, canonical)?;
    assert_eq!(public_inputs.circuit_ref(), circuit_ref);

    let mut noncanonical = canonical_raw(circuit_ref);
    set_u64(&mut noncanonical, 97, 1_900_000_180);
    noncanonical[97 * 32] = 1;
    assert!(matches!(
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, noncanonical),
        Err(error) if error.reason() == crate::errors::ZkErrorReason::InvalidProofEncoding
    ));
    Ok(())
}

#[test]
fn raw_public_inputs_reject_overrange_claim_value_length() {
    let circuit_ref = ZkCommonCredentialRootPersonaMode::PublicPersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    );
    let mut raw = canonical_raw(circuit_ref);
    set_u32(&mut raw, 321, 65);

    assert!(matches!(
        ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, raw),
        Err(error) if error.reason() == crate::errors::ZkErrorReason::InvalidProofEncoding
    ));
}

#[test]
fn raw_public_inputs_bind_every_common_credential_root_stage_to_request(
) -> Result<(), crate::errors::ZkError> {
    let expected = ZkSessionBinding {
        nonce_hash: [0x11; 32],
        audience_hash: [0x22; 32],
        transaction_data_hash: Some([0x33; 32]),
    };
    for persona_mode in [
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootPersonaMode::PublicPersona,
    ] {
        for slot in ZkCommonCredentialRootProofSlot::ALL {
            let circuit_ref = persona_mode.source_ref(ZkCredentialHashAlgorithm::Sha256, *slot);
            let mut raw = canonical_raw(circuit_ref);
            let start = match (circuit_ref.family, circuit_ref.stage) {
                (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => 98,
                (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus)
                | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage)
                | (
                    ZkCircuitFamily::CommonCredentialRootV1,
                    ZkCircuitStage::IssuerCredentialStatus,
                )
                | (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => 0,
                (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim)
                | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => 64,
                (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => {
                    128
                }
                _ => {
                    return Err(crate::errors::ZkError::new(
                        ZkErrorReason::UnsupportedCircuit,
                    ))
                }
            };
            for (position, byte) in expected.nonce_hash.iter().enumerate() {
                raw[(start + position) * 32 + 31] = *byte;
            }
            for (position, byte) in expected.audience_hash.iter().enumerate() {
                raw[(start + 32 + position) * 32 + 31] = *byte;
            }
            let transaction = expected.transaction_data_public_input();
            for (position, byte) in transaction.iter().enumerate() {
                raw[(start + 64 + position) * 32 + 31] = *byte;
            }
            let public_inputs =
                ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, raw)?;
            public_inputs.validate_session_binding(expected)?;
            for wrong in [
                ZkSessionBinding {
                    nonce_hash: [0x44; 32],
                    ..expected
                },
                ZkSessionBinding {
                    audience_hash: [0x44; 32],
                    ..expected
                },
                ZkSessionBinding {
                    transaction_data_hash: Some([0x44; 32]),
                    ..expected
                },
            ] {
                assert!(matches!(
                    public_inputs.validate_session_binding(wrong),
                    Err(error) if error.reason() == ZkErrorReason::BindingMismatch
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn status_proof_root_must_match_verified_authority_snapshot() -> Result<(), crate::errors::ZkError>
{
    let status_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::RootStatus,
    );
    let expected = [0x51; 32];
    let mut raw = canonical_raw(status_ref);
    for (index, byte) in expected.iter().enumerate() {
        raw[(96 + index) * 32 + 31] = *byte;
    }
    let status = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(status_ref, raw)?;
    status.validate_active_status_root(&expected)?;
    assert!(matches!(
        status.validate_active_status_root(&[0x52; 32]),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));

    let attestation_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::RootAttestation,
    );
    let attestation = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        attestation_ref,
        canonical_raw(attestation_ref),
    )?;
    assert!(matches!(
        attestation.validate_active_status_root(&expected),
        Err(error) if error.reason() == ZkErrorReason::UnsupportedCircuit
    ));
    Ok(())
}

#[test]
fn lineage_public_inputs_expose_selected_credential_binding_and_expiry(
) -> Result<(), crate::errors::ZkError> {
    let lineage_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::Lineage0,
    );
    let expected_binding = [0xb1; 32];
    let expected_expiry = 1_900_000_180;
    let mut raw = canonical_raw(lineage_ref);
    set_u64(&mut raw, 192, expected_expiry);
    set_bytes(&mut raw, 193, &expected_binding);

    let lineage = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(lineage_ref, raw)?;
    assert_eq!(lineage.lineage_expiry_unix()?, expected_expiry);
    assert_eq!(lineage.lineage_credential_binding()?, expected_binding);
    lineage.validate_lineage_credential_binding(&expected_binding, expected_expiry)?;
    assert!(matches!(
        lineage.validate_lineage_credential_binding(&[0xb2; 32], expected_expiry),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));
    assert!(matches!(
        lineage.validate_lineage_credential_binding(&expected_binding, expected_expiry + 1),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));

    let status_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCommonCredentialRootProofSlot::RootStatus,
    );
    let status = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        status_ref,
        canonical_raw(status_ref),
    )?;
    assert!(matches!(
        status.validate_lineage_credential_binding(&expected_binding, expected_expiry),
        Err(error) if error.reason() == ZkErrorReason::UnsupportedCircuit
    ));
    Ok(())
}

#[test]
fn issuer_status_public_inputs_expose_validation_time_only_for_status_stage(
) -> Result<(), crate::errors::ZkError> {
    let status_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
    );
    let mut raw = canonical_raw(status_ref);
    set_u64(&mut raw, 291, 1_900_000_012);
    let status = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(status_ref, raw)?;
    assert_eq!(status.issuer_status_validation_time_unix()?, 1_900_000_012);

    let lineage_ref = ZkCommonCredentialRootPersonaMode::PrivatePersona.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCommonCredentialRootProofSlot::Lineage0,
    );
    let lineage = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
        lineage_ref,
        canonical_raw(lineage_ref),
    )?;
    assert!(matches!(
        lineage.issuer_status_validation_time_unix(),
        Err(error) if error.reason() == ZkErrorReason::UnsupportedCircuit
    ));
    Ok(())
}

#[test]
fn raw_claim_disclosure_matches_exact_name_and_value_in_both_persona_modes(
) -> Result<(), crate::errors::ZkError> {
    let name_hash = [0x31; 32];
    let value = b"selected-value";
    for persona_mode in [
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootPersonaMode::PublicPersona,
    ] {
        let circuit_ref = persona_mode.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkCommonCredentialRootProofSlot::SelectedClaim0,
        );
        let offset = if persona_mode == ZkCommonCredentialRootPersonaMode::PrivatePersona {
            0
        } else {
            64
        };
        let mut raw = canonical_raw(circuit_ref);
        set_u32(
            &mut raw,
            offset + 257,
            u32::try_from(value.len())
                .map_err(|_| crate::errors::ZkError::new(ZkErrorReason::LengthOverflow))?,
        );
        for (index, byte) in value.iter().enumerate() {
            raw[(offset + 258 + index) * 32 + 31] = *byte;
        }
        for (index, byte) in name_hash.iter().enumerate() {
            raw[(offset + 322 + index) * 32 + 31] = *byte;
        }
        let inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, raw)?;
        inputs.validate_claim_disclosure(&name_hash, value)?;
        assert!(matches!(
            inputs.validate_claim_disclosure(&[0x32; 32], value),
            Err(error) if error.reason() == ZkErrorReason::BindingMismatch
        ));
        assert!(matches!(
            inputs.validate_claim_disclosure(&name_hash, b"wrong-value"),
            Err(error) if error.reason() == ZkErrorReason::BindingMismatch
        ));
    }
    Ok(())
}

fn canonical_raw(circuit_ref: ZkCircuitRef) -> Vec<u8> {
    let fields = match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => 258,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus) => 192,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => 257,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => 292,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => 354,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => 418,
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => 129,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession) => 193,
        _ => 0,
    };
    let mut raw = vec![0_u8; fields * 32];
    match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => {
            set_u32(&mut raw, 257, 1);
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicPersonaClaim) => {
            set_u32(&mut raw, 321, 1);
        }
        _ => {}
    }
    raw
}

fn set_u32(raw: &mut [u8], field_index: usize, value: u32) {
    let start = field_index * 32 + 28;
    raw[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

fn set_u64(raw: &mut [u8], field_index: usize, value: u64) {
    let start = field_index * 32 + 24;
    raw[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn set_bytes(raw: &mut [u8], field_index: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        raw[(field_index + offset) * 32 + 31] = *byte;
    }
}
