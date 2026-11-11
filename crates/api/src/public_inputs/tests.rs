// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkDecodedPublicInputs, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
    ZkSessionBinding, ZkSessionBindingPublicInputAbi,
};
use crate::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
};
use core::ops::Range;

const fn transaction_bound_session_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    )
}

fn encoded_inputs(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::Challenge)?,
        &binding.nonce_hash,
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::AudienceHash)?,
        &binding.audience_hash,
    )?;
    match descriptor.field_range(ZkPublicInputName::TransactionDataHash) {
        Ok(range) => write_field(&mut bytes, range, &binding.transaction_data_public_input())?,
        Err(error) if error.reason() == ZkErrorReason::InvalidPublicInputName => {}
        Err(error) => return Err(error),
    }
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::ExpiryUnix)?,
        &42_u64.to_be_bytes(),
    )?;
    ZkPublicInputs::try_from_bytes(bytes)
}

fn write_field(bytes: &mut [u8], range: Range<usize>, value: &[u8]) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(range)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

#[test]
fn compiler_derived_session_layout_has_expected_length() -> Result<(), ZkError> {
    let transaction_bound_private =
        ZkPublicInputDescriptor::for_circuit(transaction_bound_session_ref())?;
    assert_eq!(transaction_bound_private.encoded_len()?, 136);
    Ok(())
}

#[test]
fn every_imported_descriptor_has_session_fields() -> Result<(), ZkError> {
    for circuit_ref in ZkCircuitRef::ALL {
        if matches!(
            circuit_ref.family,
            ZkCircuitFamily::CommonCredentialRootV1 | ZkCircuitFamily::PersonaCredentialEvidenceV1
        ) {
            continue;
        }
        let descriptor = ZkPublicInputDescriptor::for_circuit(*circuit_ref)?;
        assert!(descriptor.encoded_len()? > 0);
        descriptor.field_range(ZkPublicInputName::Challenge)?;
        descriptor.field_range(ZkPublicInputName::AudienceHash)?;
        descriptor.field_range(ZkPublicInputName::ExpiryUnix)?;
        descriptor.field_range(ZkPublicInputName::TransactionDataHash)?;
        assert_eq!(
            ZkSessionBindingPublicInputAbi::for_circuit(*circuit_ref)?,
            ZkSessionBindingPublicInputAbi::V1ChallengeAudienceTransaction
        );
    }
    Ok(())
}

#[test]
fn compact_public_input_descriptor_rejects_common_credential_root_raw_abi() {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::Lineage,
    );
    let error = ZkPublicInputDescriptor::for_circuit(circuit_ref)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
}

#[test]
fn compact_public_input_descriptor_rejects_prepared_raw_abi() {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::PersonaCredentialEvidenceV1,
        ZkCircuitStage::EvidencePrivateClaim,
    );
    assert_eq!(
        ZkPublicInputDescriptor::for_circuit(circuit_ref)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UnsupportedCircuit)
    );
}

#[test]
fn versioned_session_binding_abi_declares_transaction_data_only_for_migrated_circuits() {
    assert_eq!(
        ZkSessionBindingPublicInputAbi::V1ChallengeAudience.fields(),
        &[
            ZkPublicInputName::Challenge,
            ZkPublicInputName::AudienceHash,
        ]
    );
    assert!(!ZkSessionBindingPublicInputAbi::V1ChallengeAudience.supports_transaction_data_hash());
    assert_eq!(
        ZkSessionBindingPublicInputAbi::V1ChallengeAudienceTransaction.fields(),
        &[
            ZkPublicInputName::Challenge,
            ZkPublicInputName::AudienceHash,
            ZkPublicInputName::TransactionDataHash,
        ]
    );
    assert!(
        ZkSessionBindingPublicInputAbi::V1ChallengeAudienceTransaction
            .supports_transaction_data_hash()
    );
}

#[test]
fn binding_validation_decodes_named_fields_instead_of_prefixes() -> Result<(), ZkError> {
    let binding = ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    };
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::CredentialEnvelope,
    );
    let public_inputs = encoded_inputs(circuit_ref, binding)?;

    let decoded = binding.decode_and_validate(circuit_ref, &public_inputs)?;
    assert_eq!(decoded.expiry_unix(), 42);
    assert_eq!(
        decoded,
        ZkDecodedPublicInputs::try_decode(circuit_ref, &public_inputs)?
    );
    Ok(())
}

#[test]
fn binding_validation_rejects_mismatches_at_every_digest_position() -> Result<(), ZkError> {
    let binding = ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    };
    let circuit_ref = transaction_bound_session_ref();
    for index in [0_usize, 15, 31] {
        let mut wrong_nonce = binding;
        wrong_nonce.nonce_hash[index] ^= 1;
        assert!(matches!(
            wrong_nonce.decode_and_validate(circuit_ref, &encoded_inputs(circuit_ref, binding)?),
            Err(error) if error.reason() == ZkErrorReason::BindingMismatch
        ));

        let mut wrong_audience = binding;
        wrong_audience.audience_hash[index] ^= 1;
        assert!(matches!(
            wrong_audience.decode_and_validate(
                circuit_ref,
                &encoded_inputs(circuit_ref, binding)?,
            ),
            Err(error) if error.reason() == ZkErrorReason::BindingMismatch
        ));
    }
    Ok(())
}

#[test]
fn supplied_absence_sentinel_fails_closed() -> Result<(), ZkError> {
    let binding = ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: Some(super::ABSENT_TRANSACTION_DATA_HASH),
    };
    let error = binding
        .validate_for_circuit(transaction_bound_session_ref())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn transaction_bound_session_requires_matching_nonzero_transaction_data() -> Result<(), ZkError> {
    let circuit_ref = transaction_bound_session_ref();
    let binding = ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: Some([3_u8; 32]),
    };
    let public_inputs = encoded_inputs(circuit_ref, binding)?;
    let decoded = binding.decode_and_validate(circuit_ref, &public_inputs)?;
    assert_eq!(
        decoded.transaction_data_hash(),
        binding.transaction_data_hash
    );

    let missing_transaction = ZkSessionBinding {
        transaction_data_hash: None,
        ..binding
    };
    assert!(matches!(
        missing_transaction.decode_and_validate(circuit_ref, &public_inputs),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));

    let wrong_transaction = ZkSessionBinding {
        transaction_data_hash: Some([4_u8; 32]),
        ..binding
    };
    assert!(matches!(
        wrong_transaction.decode_and_validate(circuit_ref, &public_inputs),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));

    let zero_transaction = ZkSessionBinding {
        transaction_data_hash: Some([0_u8; 32]),
        ..binding
    };
    assert!(matches!(
        zero_transaction.validate_for_circuit(circuit_ref),
        Err(error) if error.reason() == ZkErrorReason::BindingMismatch
    ));
    Ok(())
}

#[test]
fn decoder_rejects_wrong_exact_length() -> Result<(), ZkError> {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    );
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let public_inputs = ZkPublicInputs::try_from_bytes(vec![0_u8; descriptor.encoded_len()? - 1])?;
    let error = ZkDecodedPublicInputs::try_decode(circuit_ref, &public_inputs)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn compiler_derived_layout_lengths_cover_every_unique_v1_shape() -> Result<(), ZkError> {
    let cases = [
        (
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::Session,
            136,
        ),
        (
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::CredentialEnvelope,
            200,
        ),
        (
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::CredentialRoot,
            232,
        ),
        (
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::Claim,
            332,
        ),
        (
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::ClaimBundle4,
            268,
        ),
    ];

    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for (family, stage, expected_len) in cases {
            let circuit_ref = ZkCircuitRef::new(*credential_hash_algorithm, family, stage);
            let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
            assert_eq!(descriptor.encoded_len()?, expected_len);
        }
    }
    Ok(())
}

#[test]
fn public_inputs_reject_oversized_transport_value() {
    let public_inputs = vec![0_u8; super::MAX_PUBLIC_INPUT_BYTES.saturating_add(1)];
    let error = ZkPublicInputs::try_from_bytes(public_inputs)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::PublicInputsTooLarge);
}

#[test]
fn public_inputs_copy_borrowed_input_and_redact_debug() -> Result<(), ZkError> {
    let source = [171_u8, 205_u8];
    let public_inputs = ZkPublicInputs::try_copy_from_slice(&source)?;
    let debug = format!("{public_inputs:?}");

    assert_eq!(public_inputs.as_bytes(), source.as_slice());
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("171"));
    assert!(!debug.contains("205"));
    Ok(())
}

#[test]
fn public_inputs_reject_invalid_reported_lengths() {
    let empty = ZkPublicInputs::validate_length(0)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure));
    let oversized =
        ZkPublicInputs::validate_length(super::MAX_PUBLIC_INPUT_BYTES.saturating_add(1))
            .err()
            .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(empty.reason(), ZkErrorReason::EmptyInput);
    assert_eq!(oversized.reason(), ZkErrorReason::PublicInputsTooLarge);
}
