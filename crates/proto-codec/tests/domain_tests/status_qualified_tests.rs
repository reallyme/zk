// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::ABSENT_TRANSACTION_DATA_HASH,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::status_qualified::{
    decode_status_qualified_claim_proof_bundle, encode_status_qualified_claim_proof_bundle,
};

use super::claim_proof_bundle;

const FIELD_BYTES: usize = 32;
const FIELD_COUNT: usize = 292;

fn set_bytes(fields: &mut [u8], start: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        fields[(start + offset) * FIELD_BYTES + FIELD_BYTES - 1] = *byte;
    }
}

fn set_u64(fields: &mut [u8], field: usize, value: u64) {
    let start = field * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn status_package() -> pb::ZkCredentialStatusProofPackage {
    let mut raw_fields = vec![0_u8; FIELD_COUNT * FIELD_BYTES];
    set_bytes(&mut raw_fields, 0, &[1; 32]);
    set_bytes(&mut raw_fields, 32, &[2; 32]);
    set_bytes(&mut raw_fields, 64, &ABSENT_TRANSACTION_DATA_HASH);
    set_bytes(&mut raw_fields, 96, &[3; 32]);
    set_bytes(&mut raw_fields, 128, &[4; 32]);
    set_u64(&mut raw_fields, 160, 42);
    set_bytes(&mut raw_fields, 161, &[12; 32]);
    set_bytes(&mut raw_fields, 193, &[13; 32]);
    set_u64(&mut raw_fields, 225, 256);
    set_bytes(&mut raw_fields, 226, &[14; 32]);
    set_bytes(&mut raw_fields, 258, &[15; 32]);
    set_bytes(&mut raw_fields, 290, &[1]);
    set_u64(&mut raw_fields, 291, 40);
    let circuit_ref = pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        family: EnumValue::from(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1),
        stage: EnumValue::from(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ISSUER_CREDENTIAL_STATUS),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    };
    pb::ZkCredentialStatusProofPackage {
        circuit_ref: MessageField::some(circuit_ref.clone()),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        artifact_set_identity_sha256: MessageField::some(pb::ZkArtifactSetIdentity { value: vec![7;32], __buffa_unknown_fields: Default::default() }),
        proof: vec![0x51],
        public_inputs: MessageField::some(pb::ZkCommonCredentialRootRawPublicInputs {
            persona_mode: EnumValue::from(
                pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
            ),
            slot: EnumValue::from(
                pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ISSUER_CREDENTIAL_STATUS_0,
            ),
            circuit_ref: MessageField::some(circuit_ref),
            raw_fields,
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

fn wire_message() -> Result<pb::ZkStatusQualifiedClaimProofBundle, ZkError> {
    Ok(pb::ZkStatusQualifiedClaimProofBundle {
        claim_proof_bundle: MessageField::some(claim_proof_bundle()?),
        issuer_credential_status: MessageField::some(status_package()),
        __buffa_unknown_fields: Default::default(),
    })
}

fn encode_untrusted(message: &pb::ZkStatusQualifiedClaimProofBundle) -> Result<Vec<u8>, ZkError> {
    let mut bytes = Vec::new();
    message
        .try_encode_bounded(2 * 1024 * 1024, &mut bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
    Ok(bytes)
}

#[test]
fn status_qualified_protobuf_round_trips_canonically() -> Result<(), ZkError> {
    let wire = encode_untrusted(&wire_message()?)?;
    let bundle = decode_status_qualified_claim_proof_bundle(&wire)?;
    let encoded = encode_status_qualified_claim_proof_bundle(&bundle)?;
    assert_eq!(encoded.as_slice(), wire.as_slice());
    Ok(())
}

#[test]
fn status_qualified_protobuf_rejects_cross_credential_substitution() -> Result<(), ZkError> {
    let mut message = wire_message()?;
    let status = message.issuer_credential_status.get_or_insert_default();
    let raw = status.public_inputs.get_or_insert_default();
    set_bytes(&mut raw.raw_fields, 161, &[0x99]);
    let error = decode_status_qualified_claim_proof_bundle(&encode_untrusted(&message)?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn status_qualified_protobuf_requires_fifth_proof() -> Result<(), ZkError> {
    let mut message = wire_message()?;
    message.issuer_credential_status = MessageField::none();
    let error = decode_status_qualified_claim_proof_bundle(&encode_untrusted(&message)?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::MissingStage);
    Ok(())
}

mod verify_operation {
    use buffa::{EnumValue, Message, MessageField};
    use reallyme_zk_api::{
        claim_bundle::{
            verify_status_qualified_claim_proof_bundle_with,
            ZkPresentationBoundClaimBundleVerifier, ZkPresentationBoundClaimBundleVerifyRequest,
            ZkStatusQualifiedClaimProofBundleVerifyRequest,
        },
        errors::{ZkError, ZkErrorReason},
        issuer_status::{
            ZkIssuerCredentialStatusProof, ZkIssuerCredentialStatusVerifier,
            ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer,
            ZkIssuerStatusPurpose,
        },
        keys::ZkIssuerPublicKey,
        proofs::ZkProofSuite,
    };
    use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
    use reallyme_zk_proto_codec::{
        exchange::{
            decode_operation_request_kind, validate_operation_exchange, ZkProviderOperationKind,
        },
        operation::{decode_operation_request, ZkProviderOperation},
        result::{
            decode_operation_response,
            encode_status_qualified_claim_proof_bundle_verification_response,
            ZkProviderOperationOutcome, ZkProviderOperationResult,
        },
        status_qualified::decode_status_qualified_claim_proof_bundle,
    };

    use super::{encode_untrusted, wire_message};
    use crate::session_binding;

    const VERIFICATION_TIME_UNIX: u64 = 41;
    const STATUS_ROOT: [u8; 32] = [13; 32];
    const STATUS_LENGTH: u64 = 256;
    const STATUS_LIST_ID: [u8; 32] = [14; 32];
    const STATUS_URL_HASH: [u8; 32] = [15; 32];

    fn current_issuer_status() -> pb::ZkCommonCredentialRootIssuerStatusExpectation {
        pb::ZkCommonCredentialRootIssuerStatusExpectation {
            root: STATUS_ROOT.to_vec(),
            length: STATUS_LENGTH,
            list_id: STATUS_LIST_ID.to_vec(),
            url_hash: STATUS_URL_HASH.to_vec(),
            purpose: EnumValue::from(
                pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION,
            ),
            __buffa_unknown_fields: Default::default(),
        }
    }

    fn trusted_issuer() -> Result<ZkIssuerPublicKey, ZkError> {
        let bundle =
            decode_status_qualified_claim_proof_bundle(&encode_untrusted(&wire_message()?)?)?;
        Ok(bundle
            .claim_proof_bundle()
            .decode_claimed_statement()?
            .issuer())
    }

    fn operation() -> Result<pb::ZkStatusQualifiedClaimProofBundleVerifyOperation, ZkError> {
        let issuer = trusted_issuer()?;
        Ok(pb::ZkStatusQualifiedClaimProofBundleVerifyOperation {
            status_qualified_claim_proof_bundle: MessageField::some(wire_message()?),
            expected_binding: MessageField::some(session_binding()),
            trusted_issuers: vec![pb::ZkP256PublicKey {
                x: issuer.x.to_vec(),
                y: issuer.y.to_vec(),
                __buffa_unknown_fields: Default::default(),
            }],
            verification_time_unix: VERIFICATION_TIME_UNIX,
            expected_proof_suite: EnumValue::from(
                pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            current_issuer_status: MessageField::some(current_issuer_status()),
            expected_issuer: MessageField::some(pb::ZkP256PublicKey {
                x: issuer.x.to_vec(),
                y: issuer.y.to_vec(),
                __buffa_unknown_fields: Default::default(),
            }),
            __buffa_unknown_fields: Default::default(),
        })
    }

    fn request_bytes(
        operation: pb::ZkStatusQualifiedClaimProofBundleVerifyOperation,
    ) -> Result<Vec<u8>, ZkError> {
        let request = pb::ZkProviderOperationRequest {
            operation: Some(
                pb::zk_provider_operation_request::Operation::VerifyStatusQualifiedClaimProofBundle(
                    Box::new(operation),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        };
        let mut bytes = Vec::new();
        request
            .try_encode_bounded(8 * 1024 * 1024, &mut bytes)
            .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
        Ok(bytes)
    }

    fn decode_error(
        operation: pb::ZkStatusQualifiedClaimProofBundleVerifyOperation,
    ) -> Result<ZkErrorReason, ZkError> {
        Ok(decode_operation_request(&request_bytes(operation)?)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?
            .reason())
    }

    #[test]
    fn expected_status_issuer_is_required_and_must_be_trusted() -> Result<(), ZkError> {
        let mut missing = operation()?;
        missing.expected_issuer = MessageField::none();
        assert_eq!(decode_error(missing)?, ZkErrorReason::UntrustedIssuer);

        let mut malformed = operation()?;
        malformed.expected_issuer.get_or_insert_default().x = vec![1; 31];
        assert_eq!(
            decode_error(malformed)?,
            ZkErrorReason::InvalidProofEncoding
        );

        let mut other = operation()?;
        other.expected_issuer = MessageField::some(pb::ZkP256PublicKey {
            x: vec![21; 32],
            y: vec![22; 32],
            __buffa_unknown_fields: Default::default(),
        });
        assert_eq!(decode_error(other)?, ZkErrorReason::UntrustedIssuer);
        Ok(())
    }

    #[test]
    fn another_trusted_issuer_cannot_use_the_selected_status_feed() -> Result<(), ZkError> {
        let mut other = operation()?;
        let issuer = pb::ZkP256PublicKey {
            x: vec![21; 32],
            y: vec![22; 32],
            __buffa_unknown_fields: Default::default(),
        };
        other.trusted_issuers.push(issuer.clone());
        other.expected_issuer = MessageField::some(issuer);
        assert_eq!(decode_error(other)?, ZkErrorReason::BindingMismatch);
        Ok(())
    }

    struct AcceptingVerifier;

    impl ZkPresentationBoundClaimBundleVerifier for AcceptingVerifier {
        fn verify_presentation_bound_claim_bundle_evidence(
            &self,
            _request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
        ) -> Result<(), ZkError> {
            Ok(())
        }
    }

    impl ZkIssuerCredentialStatusVerifier for AcceptingVerifier {
        fn verify_issuer_credential_status(
            &self,
            _proof: &ZkIssuerCredentialStatusProof,
        ) -> Result<(), ZkError> {
            Ok(())
        }
    }

    struct FixedAuthority;

    impl ZkIssuerStatusAuthority for FixedAuthority {
        fn current_feed_for_issuer(
            &self,
            _issuer_key: &ZkIssuerPublicKey,
            _status_pointer: &ZkIssuerStatusListPointer,
            _verification_time_unix: u64,
        ) -> Result<ZkIssuerStatusFeed, ZkError> {
            Ok(ZkIssuerStatusFeed {
                root: STATUS_ROOT,
                length: STATUS_LENGTH,
                list_id: STATUS_LIST_ID,
                url_hash: STATUS_URL_HASH,
                purpose: ZkIssuerStatusPurpose::Revocation,
            })
        }
    }

    fn success_response(request_bytes: &[u8]) -> Result<Vec<u8>, ZkError> {
        let ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle {
            status_qualified_claim_proof_bundle,
            expected_proof_suite,
            expected_binding,
            trusted_issuers,
            verification_time_unix,
            current_issuer_status,
            expected_issuer: _,
        } = decode_operation_request(request_bytes)?
        else {
            return Err(ZkError::new(ZkErrorReason::MissingOperation));
        };
        let bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            status_qualified_claim_proof_bundle.claim_proof_bundle(),
            expected_proof_suite,
            expected_binding,
            &trusted_issuers,
            verification_time_unix,
        )?;
        let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
            bundle_request,
            status_qualified_claim_proof_bundle.issuer_credential_status(),
            &FixedAuthority,
            current_issuer_status.purpose,
        )?;
        let verification = verify_status_qualified_claim_proof_bundle_with(
            &AcceptingVerifier,
            &AcceptingVerifier,
            request,
        )?;
        Ok(
            encode_status_qualified_claim_proof_bundle_verification_response(
                request_bytes,
                &verification,
            )?
            .to_vec(),
        )
    }

    #[test]
    fn verify_operation_decodes_bundle_policy_and_current_status() -> Result<(), ZkError> {
        let bytes = request_bytes(operation()?)?;
        assert_eq!(
            decode_operation_request_kind(&bytes)?,
            ZkProviderOperationKind::VerifyStatusQualifiedClaimProofBundle
        );
        let ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle {
            expected_proof_suite,
            trusted_issuers,
            verification_time_unix,
            current_issuer_status,
            ..
        } = decode_operation_request(&bytes)?
        else {
            return Err(ZkError::new(ZkErrorReason::MissingOperation));
        };
        assert_eq!(expected_proof_suite, ZkProofSuite::PRODUCTION);
        assert_eq!(trusted_issuers, vec![trusted_issuer()?]);
        assert_eq!(verification_time_unix, VERIFICATION_TIME_UNIX);
        assert_eq!(current_issuer_status.root, STATUS_ROOT);
        assert_eq!(current_issuer_status.length, STATUS_LENGTH);
        assert_eq!(current_issuer_status.list_id, STATUS_LIST_ID);
        assert_eq!(current_issuer_status.url_hash, STATUS_URL_HASH);
        assert_eq!(
            current_issuer_status.purpose,
            ZkIssuerStatusPurpose::Revocation
        );
        Ok(())
    }

    #[test]
    fn verify_operation_requires_a_complete_current_status_list() -> Result<(), ZkError> {
        let mut missing = operation()?;
        missing.current_issuer_status = MessageField::none();
        assert_eq!(decode_error(missing)?, ZkErrorReason::InvalidProofEncoding);

        // A default-valued message must never stand in for an authenticated list.
        let mut defaulted = operation()?;
        defaulted.current_issuer_status = MessageField::some(Default::default());
        assert_eq!(
            decode_error(defaulted)?,
            ZkErrorReason::InvalidProofEncoding
        );

        type Mutation = fn(&mut pb::ZkCommonCredentialRootIssuerStatusExpectation);
        let mutations: [Mutation; 10] = [
            |feed| feed.root = vec![0; 32],
            |feed| feed.root = vec![13; 31],
            |feed| feed.root = vec![13; 33],
            |feed| feed.list_id = vec![0; 32],
            |feed| feed.list_id = Vec::new(),
            |feed| feed.url_hash = vec![0; 32],
            |feed| feed.url_hash = vec![15; 31],
            |feed| feed.length = 0,
            |feed| feed.length = 1_000_001,
            |feed| {
                feed.purpose = EnumValue::from(
                    pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_UNSPECIFIED,
                );
            },
        ];
        for mutate in mutations {
            let mut mutated = operation()?;
            mutate(mutated.current_issuer_status.get_or_insert_default());
            assert_eq!(decode_error(mutated)?, ZkErrorReason::InvalidProofEncoding);
        }

        let mut maximum = operation()?;
        maximum.current_issuer_status.get_or_insert_default().length = 1_000_000;
        decode_operation_request(&request_bytes(maximum)?)?;
        Ok(())
    }

    #[test]
    fn verify_operation_rejects_missing_bundle_policy_and_binding_mismatch() -> Result<(), ZkError>
    {
        let mut missing_bundle = operation()?;
        missing_bundle.status_qualified_claim_proof_bundle = MessageField::none();
        assert_eq!(
            decode_error(missing_bundle)?,
            ZkErrorReason::InvalidClaimProofBundle
        );

        let mut missing_status_proof = operation()?;
        missing_status_proof
            .status_qualified_claim_proof_bundle
            .get_or_insert_default()
            .issuer_credential_status = MessageField::none();
        assert_eq!(
            decode_error(missing_status_proof)?,
            ZkErrorReason::MissingStage
        );

        let mut no_issuers = operation()?;
        no_issuers.trusted_issuers.clear();
        assert_eq!(decode_error(no_issuers)?, ZkErrorReason::UntrustedIssuer);

        let mut duplicate_issuers = operation()?;
        let issuer = duplicate_issuers.trusted_issuers[0].clone();
        duplicate_issuers.trusted_issuers.push(issuer);
        assert_eq!(
            decode_error(duplicate_issuers)?,
            ZkErrorReason::UntrustedIssuer
        );

        let mut wrong_nonce = operation()?;
        wrong_nonce
            .expected_binding
            .get_or_insert_default()
            .nonce_hash = vec![9; 32];
        assert_eq!(decode_error(wrong_nonce)?, ZkErrorReason::BindingMismatch);

        let mut wrong_audience = operation()?;
        wrong_audience
            .expected_binding
            .get_or_insert_default()
            .audience_hash = vec![9; 32];
        assert_eq!(
            decode_error(wrong_audience)?,
            ZkErrorReason::BindingMismatch
        );

        let mut unspecified_suite = operation()?;
        unspecified_suite.expected_proof_suite =
            EnumValue::from(pb::ZkProofSuite::ZK_PROOF_SUITE_UNSPECIFIED);
        assert_eq!(
            decode_error(unspecified_suite)?,
            ZkErrorReason::UnsupportedProofSuite
        );
        Ok(())
    }

    #[test]
    fn status_qualified_response_round_trips_and_matches_its_request() -> Result<(), ZkError> {
        let request = request_bytes(operation()?)?;
        let response = success_response(&request)?;
        validate_operation_exchange(&request, &response)?;

        let ZkProviderOperationOutcome::Success(result) =
            decode_operation_response(&response)?.into_outcome()
        else {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        };
        let ZkProviderOperationResult::StatusQualifiedClaimProofBundleVerification(report) =
            *result
        else {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        };
        assert_eq!(report.verified_proof_count, 5);
        assert_eq!(report.proof_suite, ZkProofSuite::PRODUCTION);
        assert_eq!(report.status_purpose, ZkIssuerStatusPurpose::Revocation);
        Ok(())
    }

    fn mutate_report(
        response: &[u8],
        mutate: impl FnOnce(&mut pb::ZkStatusQualifiedClaimProofBundleVerification),
    ) -> Result<Vec<u8>, ZkError> {
        let mut message = pb::ZkProviderOperationResponse::decode_from_slice(response)
            .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
        let Some(pb::zk_provider_operation_response::Outcome::Result(result)) =
            message.outcome.as_mut()
        else {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        };
        let Some(
            pb::zk_provider_operation_result::Result::StatusQualifiedClaimProofBundleVerification(
                report,
            ),
        ) = result.result.as_mut()
        else {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        };
        mutate(report);
        let mut bytes = Vec::new();
        message
            .try_encode_bounded(8 * 1024 * 1024, &mut bytes)
            .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
        Ok(bytes)
    }

    #[test]
    fn status_qualified_report_must_be_complete_and_bound_to_the_request() -> Result<(), ZkError> {
        let request = request_bytes(operation()?)?;
        let response = success_response(&request)?;

        // A four-proof count, a missing statement, and an unspecified purpose
        // are not a status-qualified report.
        for (mutated, expected) in [
            (
                mutate_report(&response, |report| report.verified_proof_count = 4)?,
                ZkErrorReason::InvalidClaimProofBundle,
            ),
            (
                mutate_report(&response, |report| {
                    report.statement = MessageField::none();
                })?,
                ZkErrorReason::InvalidProofEncoding,
            ),
            (
                mutate_report(&response, |report| {
                    report.status_purpose = EnumValue::from(
                        pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_UNSPECIFIED,
                    );
                })?,
                ZkErrorReason::InvalidProofEncoding,
            ),
        ] {
            let error = decode_operation_response(&mutated)
                .err()
                .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
            assert_eq!(error.reason(), expected);
        }

        // Well-formed reports that disagree with the request are rejected by
        // exchange validation.
        for mutated in [
            mutate_report(&response, |report| {
                report.status_purpose =
                    EnumValue::from(pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_SUSPENSION);
            })?,
            mutate_report(&response, |report| {
                report.bundle_kind = EnumValue::from(
                    pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
                );
            })?,
            mutate_report(&response, |report| {
                if let Some(statement) = report.statement.as_option_mut() {
                    statement.claim_name_hash = vec![0x77; 32];
                }
            })?,
            mutate_report(&response, |report| {
                if let Some(statement) = report.statement.as_option_mut() {
                    statement.session_link_commitment = vec![0x77; 32];
                }
            })?,
        ] {
            let error = validate_operation_exchange(&request, &mutated)
                .err()
                .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
            assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
        }

        // A response for a different request is rejected.
        let mut other = operation()?;
        other.verification_time_unix = VERIFICATION_TIME_UNIX + 1;
        let error = validate_operation_exchange(&request_bytes(other)?, &response)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
        Ok(())
    }

    #[test]
    fn four_proof_report_cannot_answer_a_status_qualified_request() -> Result<(), ZkError> {
        let request = request_bytes(operation()?)?;
        let response = success_response(&request)?;
        let mut message = pb::ZkProviderOperationResponse::decode_from_slice(&response)
            .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
        let Some(pb::zk_provider_operation_response::Outcome::Result(result)) =
            message.outcome.as_mut()
        else {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        };
        let Some(
            pb::zk_provider_operation_result::Result::StatusQualifiedClaimProofBundleVerification(
                report,
            ),
        ) = result.result.take()
        else {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        };
        let mut statement = report
            .statement
            .into_option()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        result.result = Some(
            pb::zk_provider_operation_result::Result::ClaimProofBundleVerification(Box::new(
                pb::ZkPresentationBoundClaimBundleVerification {
                    bundle_kind: report.bundle_kind,
                    verified_stage_count: 4,
                    proof_suite: report.proof_suite,
                    statement: MessageField::some(pb::ZkPresentationBoundClaimStatement {
                        issuer: core::mem::take(&mut statement.issuer),
                        persona: core::mem::take(&mut statement.persona),
                        claim_name_hash: core::mem::take(&mut statement.claim_name_hash),
                        claim_value: core::mem::take(&mut statement.claim_value),
                        claim_value_length: statement.claim_value_length,
                        presentation_expiry_unix: statement.presentation_expiry_unix,
                        session_link_commitment: core::mem::take(
                            &mut statement.session_link_commitment,
                        ),
                        credential_binding: core::mem::take(&mut statement.credential_binding),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        );
        let mut downgraded = Vec::new();
        message
            .try_encode_bounded(8 * 1024 * 1024, &mut downgraded)
            .map_err(|_| ZkError::new(ZkErrorReason::MessageTooLarge))?;
        let error = validate_operation_exchange(&request, &downgraded)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
        Ok(())
    }
}
