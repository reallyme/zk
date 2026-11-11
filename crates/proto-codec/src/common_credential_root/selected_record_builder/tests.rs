// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    encode_common_credential_root_selected_record_presentation_request, subject_key,
    ZkCommonCredentialRootPresenterAuthorization, ZkCommonCredentialRootSelectedCredentialRecord,
    ZkCommonCredentialRootSelectedIssuerStatus,
    ZkCommonCredentialRootSelectedRecordPresentationInput, SIGNATURE_BYTES,
};
use buffa::DecodeOptions;
use crypto_core::{CryptoError, RngOutputKind};
use crypto_csprng::SecureRandom;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::MAX_PRESENTATION_LIFETIME_SECONDS,
    common_root::{
        build_common_credential_root_poseidon2_claims_commitment,
        build_common_credential_root_sha256_claims_commitment,
        common_credential_root_attestation_signing_digest,
        common_credential_root_issuer_status_opening, common_credential_root_root_commitment,
        derive_common_credential_root_attestation_id, derive_common_credential_root_v1_lineage,
        verify_root_status_snapshot, ZkCommonCredentialRootAttestationMaterial,
        ZkCommonCredentialRootAttestationTrustPolicy, ZkCommonCredentialRootClaim,
        ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootHolderAssurance,
        ZkCommonCredentialRootIssuerStatusOpening, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootProofSlot, ZkRootStatusSnapshot, ZkRootStatusTrustPolicy,
        ZkVerifiedRootStatusSnapshot,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusPurpose,
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::operation::decode_operation_request;

use pb::zk_common_credential_root_stage_prove_operation::Input as StageInput;
use pb::zk_provider_operation_request::Operation;

const NOW: u64 = 1_900_000_000;
const EXPIRY: u64 = NOW + 180;
const ATTESTATION_EXPIRES: u64 = NOW + MAX_PRESENTATION_LIFETIME_SECONDS;
const ROOT: [u8; 32] = [0x31; 32];
const POLICY: [u8; 32] = [0x32; 32];
const PERSONA_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x71; SIGNATURE_BYTES];
const FIRST_ROOT_BINDING_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x40; SIGNATURE_BYTES];
const FIRST_ISSUER_SUBJECT_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x44; SIGNATURE_BYTES];
const FIRST_SUBJECT_LINK_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x45; SIGNATURE_BYTES];
const FIRST_STATUS_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x48; SIGNATURE_BYTES];
const SECOND_ROOT_BINDING_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x50; SIGNATURE_BYTES];
const SECOND_ISSUER_SUBJECT_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x54; SIGNATURE_BYTES];
const SECOND_SUBJECT_LINK_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x55; SIGNATURE_BYTES];
const SECOND_STATUS_SIGNATURE: [u8; SIGNATURE_BYTES] = [0x58; SIGNATURE_BYTES];
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

struct FixedRng;

impl SecureRandom for FixedRng {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        output.fill(0xA5);
        Ok(())
    }
}

fn high_s_twin(mut signature: [u8; SIGNATURE_BYTES]) -> Result<[u8; SIGNATURE_BYTES], TestError> {
    let mut borrow = 0_u16;
    for index in (32..SIGNATURE_BYTES).rev() {
        let minuend = u16::from(P256_ORDER[index - 32]);
        let subtrahend = u16::from(signature[index]) + borrow;
        if minuend >= subtrahend {
            signature[index] =
                u8::try_from(minuend - subtrahend).map_err(|_| TestError::UnexpectedOperation)?;
            borrow = 0;
        } else {
            signature[index] = u8::try_from(256 + minuend - subtrahend)
                .map_err(|_| TestError::UnexpectedOperation)?;
            borrow = 1;
        }
    }
    Ok(signature)
}

fn presentation_from_bytes(
    bytes: &[u8],
) -> Result<pb::ZkCommonCredentialRootPresentationProveOperation, TestError> {
    let mut request = DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(bytes)
        .map_err(|_| TestError::UnexpectedOperation)?;
    match request.operation.take() {
        Some(Operation::ProveCommonCredentialRootPresentation(operation)) => Ok(*operation),
        _ => Err(TestError::UnexpectedOperation),
    }
}

struct Fixture {
    holder: ZkCommonCredentialRootHolderAssurance,
    snapshot: ZkVerifiedRootStatusSnapshot,
    signer: ZkIssuerPublicKey,
    first_claims: ZkCommonCredentialRootClaimsCommitment,
    second_claims: ZkCommonCredentialRootClaimsCommitment,
    first_status: ZkCommonCredentialRootIssuerStatusOpening,
    second_status: ZkCommonCredentialRootIssuerStatusOpening,
}

#[derive(Debug, Error)]
enum TestError {
    #[error("test crypto fixture failed")]
    Crypto(#[from] CryptoError),
    #[error("test zk fixture failed")]
    Zk(#[from] ZkError),
    #[error("test root assurance fixture failed")]
    RootAssurance,
    #[error("test root status fixture failed")]
    RootStatus,
    #[error("test credential fixture failed")]
    Credential,
    #[error("test public key shape invalid")]
    PublicKeyShape,
    #[error("expected builder rejection")]
    ExpectedFailure,
    #[error("unexpected operation kind")]
    UnexpectedOperation,
}

#[test]
fn selected_record_builder_emits_decodable_nine_stage_operation() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut rng = FixedRng;
    let bytes = encode_common_credential_root_selected_record_presentation_request(
        input(&fixture, false, false, NOW, EXPIRY)?,
        &mut rng,
    )?;
    let operation = decode_operation_request(&bytes)?;
    match operation {
        crate::operation::ZkProviderOperation::ProveCommonCredentialRootPresentation {
            stages,
            ..
        } => {
            assert_eq!(stages.len(), ZkCommonCredentialRootProofSlot::ALL.len());
        }
        _ => return Err(TestError::UnexpectedOperation),
    }
    Ok(())
}

#[test]
fn selected_record_builder_canonicalizes_high_s_witness_signatures() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut first_root = high_s_twin(FIRST_ROOT_BINDING_SIGNATURE)?;
    let mut first_subject = high_s_twin(FIRST_ISSUER_SUBJECT_SIGNATURE)?;
    let mut first_link = high_s_twin(FIRST_SUBJECT_LINK_SIGNATURE)?;
    let mut first_status = high_s_twin(FIRST_STATUS_SIGNATURE)?;
    let mut persona = high_s_twin(PERSONA_SIGNATURE)?;
    let second = record(
        &fixture,
        &fixture.second_claims,
        &fixture.second_status,
        0x50,
        false,
        false,
    )?;
    let first = ZkCommonCredentialRootSelectedCredentialRecord {
        issuer_public_key: fixture.signer,
        lineage_root: ROOT,
        envelope_hash: [0x40; 32],
        issuer_root_binding_signature: &first_root,
        claims: &fixture.first_claims,
        selected_claim_index: 1,
        subject_public_key: issuer(0x41),
        relationship_did_hash: [0x42; 32],
        relationship_nonce: [0x43; 32],
        issuer_subject_binding_signature: &first_subject,
        subject_link_signature: &first_link,
        issuer_status: ZkCommonCredentialRootSelectedIssuerStatus {
            root: common_credential_root_issuer_status_opening(&[0], 1, 0)
                .map_err(|_| TestError::RootStatus)?
                .0,
            length: 1,
            list_id: [0x46; 32],
            url_hash: [0x47; 32],
            purpose: ZkIssuerStatusPurpose::Revocation,
            issuer_validity_status_signature: &first_status,
            valid_from: NOW - 1,
            valid_until: NOW + MAX_PRESENTATION_LIFETIME_SECONDS + 1,
            status_index: 0,
            opening: &fixture.first_status,
        },
    };
    let request = ZkCommonCredentialRootSelectedRecordPresentationInput {
        persona_mode: ZkCommonCredentialRootPersonaMode::PrivatePersona,
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        proof_suite: ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        expected_binding: ZkSessionBinding {
            nonce_hash: [0x21; 32],
            audience_hash: [0x22; 32],
            transaction_data_hash: Some([0x23; 32]),
        },
        request_time_unix: NOW,
        status_validation_time_unix: NOW,
        presentation_expiry_unix: EXPIRY,
        active_status_snapshot: fixture.snapshot,
        holder_assurance: &fixture.holder,
        presenter_authorization: ZkCommonCredentialRootPresenterAuthorization::Private {
            persona_public_key: issuer(0x70),
            persona_signature: &persona,
        },
        records: [first, second],
    };
    let mut rng = FixedRng;
    let bytes =
        encode_common_credential_root_selected_record_presentation_request(request, &mut rng)?;
    let presentation = presentation_from_bytes(&bytes)?;

    let lineage = presentation
        .lineage_0
        .as_option()
        .ok_or(TestError::UnexpectedOperation)?;
    let lineage = match lineage
        .input
        .as_ref()
        .ok_or(TestError::UnexpectedOperation)?
    {
        StageInput::Lineage(input) => input,
        _ => return Err(TestError::UnexpectedOperation),
    };
    assert_eq!(
        lineage
            .witness
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .issuer_root_binding_signature
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .value,
        FIRST_ROOT_BINDING_SIGNATURE.to_vec()
    );

    let claim = presentation
        .selected_claim_0
        .as_option()
        .ok_or(TestError::UnexpectedOperation)?;
    let claim = match claim.input.as_ref().ok_or(TestError::UnexpectedOperation)? {
        StageInput::PrivatePersonaClaim(input) => input,
        _ => return Err(TestError::UnexpectedOperation),
    };
    let link = claim
        .link
        .as_option()
        .ok_or(TestError::UnexpectedOperation)?;
    assert_eq!(
        link.issuer_subject_binding_signature
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .value,
        FIRST_ISSUER_SUBJECT_SIGNATURE.to_vec()
    );
    assert_eq!(
        link.subject_link_signature
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .value,
        FIRST_SUBJECT_LINK_SIGNATURE.to_vec()
    );

    let session = presentation
        .session
        .as_option()
        .ok_or(TestError::UnexpectedOperation)?;
    let session = match session
        .input
        .as_ref()
        .ok_or(TestError::UnexpectedOperation)?
    {
        StageInput::PrivatePersonaSession(input) => input,
        _ => return Err(TestError::UnexpectedOperation),
    };
    assert_eq!(
        session
            .authorization
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .persona_signature
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .value,
        PERSONA_SIGNATURE.to_vec()
    );

    let status = presentation
        .issuer_credential_status_0
        .as_option()
        .ok_or(TestError::UnexpectedOperation)?;
    let status = match status
        .input
        .as_ref()
        .ok_or(TestError::UnexpectedOperation)?
    {
        StageInput::IssuerCredentialStatus(input) => input,
        _ => return Err(TestError::UnexpectedOperation),
    };
    assert_eq!(
        status
            .issuer_validity_status_signature
            .as_option()
            .ok_or(TestError::UnexpectedOperation)?
            .value,
        FIRST_STATUS_SIGNATURE.to_vec()
    );

    first_root.zeroize();
    first_subject.zeroize();
    first_link.zeroize();
    first_status.zeroize();
    persona.zeroize();
    Ok(())
}

#[test]
fn selected_record_builder_supports_hash_lanes_and_persona_modes() -> Result<(), TestError> {
    for credential_hash_algorithm in [
        ZkCredentialHashAlgorithm::Sha256,
        ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        for persona_mode in [
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCommonCredentialRootPersonaMode::PublicPersona,
        ] {
            let fixture = fixture_with_hash(credential_hash_algorithm)?;
            let mut request = input(&fixture, false, false, NOW, EXPIRY)?;
            request.persona_mode = persona_mode;
            request.credential_hash_algorithm = credential_hash_algorithm;
            request.presenter_authorization = match persona_mode {
                ZkCommonCredentialRootPersonaMode::PrivatePersona => {
                    ZkCommonCredentialRootPresenterAuthorization::Private {
                        persona_public_key: issuer(0x70),
                        persona_signature: &PERSONA_SIGNATURE,
                    }
                }
                ZkCommonCredentialRootPersonaMode::PublicPersona => {
                    ZkCommonCredentialRootPresenterAuthorization::Public {
                        persona_public_key: issuer(0x70),
                        persona_fresh_signature: &PERSONA_SIGNATURE,
                    }
                }
            };
            let mut rng = FixedRng;
            let bytes = encode_common_credential_root_selected_record_presentation_request(
                request, &mut rng,
            )?;
            let operation = decode_operation_request(&bytes)?;
            assert!(matches!(
                operation,
                crate::operation::ZkProviderOperation::ProveCommonCredentialRootPresentation { .. }
            ));
        }
    }
    Ok(())
}

#[test]
fn selected_record_private_record_owner_has_drop_cleanup() {
    assert!(core::mem::needs_drop::<
        ZkCommonCredentialRootSelectedCredentialRecord<'static>,
    >());
}

#[test]
fn selected_record_builder_rejects_wrong_record_root() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut rng = FixedRng;
    let error = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input(&fixture, true, false, NOW, EXPIRY)?,
            &mut rng,
        ),
    )?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn selected_record_builder_rejects_mismatched_issuer_status_opening() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut rng = FixedRng;
    let error = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input(&fixture, false, true, NOW, EXPIRY)?,
            &mut rng,
        ),
    )?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn selected_record_builder_rejects_stale_status_and_wrong_session() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut rng = FixedRng;
    let stale = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input(&fixture, false, false, NOW + 60, NOW + 120)?,
            &mut rng,
        ),
    )?;
    assert_eq!(stale.reason(), ZkErrorReason::PresentationExpired);

    let mut rng = FixedRng;
    let wrong_session = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input(&fixture, false, false, NOW, NOW)?,
            &mut rng,
        ),
    )?;
    assert_eq!(wrong_session.reason(), ZkErrorReason::PresentationExpired);
    Ok(())
}

#[test]
fn selected_record_builder_rejects_over_policy_proof_lifetime() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut rng = FixedRng;
    encode_common_credential_root_selected_record_presentation_request(
        input(
            &fixture,
            false,
            false,
            NOW,
            NOW + MAX_PRESENTATION_LIFETIME_SECONDS - 1,
        )?,
        &mut rng,
    )?;

    let mut rng = FixedRng;
    let error = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input(
                &fixture,
                false,
                false,
                NOW,
                NOW + MAX_PRESENTATION_LIFETIME_SECONDS + 1,
            )?,
            &mut rng,
        ),
    )?;
    assert_eq!(error.reason(), ZkErrorReason::PresentationExpiryTooFar);
    Ok(())
}

#[test]
fn selected_record_builder_rejects_attestation_expiry_boundary() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut rng = FixedRng;
    let error = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input(&fixture, false, false, NOW, ATTESTATION_EXPIRES)?,
            &mut rng,
        ),
    )?;
    assert_eq!(error.reason(), ZkErrorReason::PresentationExpired);
    Ok(())
}

#[test]
fn selected_record_builder_rejects_credential_expiry_boundary() -> Result<(), TestError> {
    let fixture = fixture()?;
    let mut request = input(&fixture, false, false, NOW, EXPIRY)?;
    request.records[0].issuer_status.valid_until = EXPIRY;
    let mut rng = FixedRng;
    let error = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(request, &mut rng),
    )?;
    assert_eq!(error.reason(), ZkErrorReason::PresentationExpired);
    Ok(())
}

#[test]
fn selected_record_builder_validates_current_status_at_presentation_time() -> Result<(), TestError>
{
    let fixture = fixture()?;
    let status_validation_time = NOW + 30;
    let mut rng = FixedRng;
    encode_common_credential_root_selected_record_presentation_request(
        input_with_status_time(
            &fixture,
            false,
            false,
            NOW,
            status_validation_time,
            NOW + 120,
        )?,
        &mut rng,
    )?;

    let mut rng = FixedRng;
    let error = expect_rejection(
        encode_common_credential_root_selected_record_presentation_request(
            input_with_status_time(&fixture, false, false, NOW, NOW - 1, NOW + 120)?,
            &mut rng,
        ),
    )?;
    assert_eq!(error.reason(), ZkErrorReason::PresentationExpired);
    Ok(())
}

fn expect_rejection(result: Result<Zeroizing<Vec<u8>>, ZkError>) -> Result<ZkError, TestError> {
    match result {
        Ok(_) => Err(TestError::ExpectedFailure),
        Err(error) => Ok(error),
    }
}

fn input<'a>(
    fixture: &'a Fixture,
    wrong_root: bool,
    wrong_issuer_status_root: bool,
    now: u64,
    expiry: u64,
) -> Result<ZkCommonCredentialRootSelectedRecordPresentationInput<'a>, TestError> {
    input_with_status_time(
        fixture,
        wrong_root,
        wrong_issuer_status_root,
        now,
        now,
        expiry,
    )
}

fn input_with_status_time<'a>(
    fixture: &'a Fixture,
    wrong_root: bool,
    wrong_issuer_status_root: bool,
    request_time: u64,
    status_validation_time: u64,
    expiry: u64,
) -> Result<ZkCommonCredentialRootSelectedRecordPresentationInput<'a>, TestError> {
    Ok(ZkCommonCredentialRootSelectedRecordPresentationInput {
        persona_mode: ZkCommonCredentialRootPersonaMode::PrivatePersona,
        credential_hash_algorithm: ZkCredentialHashAlgorithm::Sha256,
        proof_suite: ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        expected_binding: ZkSessionBinding {
            nonce_hash: [0x21; 32],
            audience_hash: [0x22; 32],
            transaction_data_hash: Some([0x23; 32]),
        },
        request_time_unix: request_time,
        status_validation_time_unix: status_validation_time,
        presentation_expiry_unix: expiry,
        active_status_snapshot: fixture.snapshot,
        holder_assurance: &fixture.holder,
        presenter_authorization: ZkCommonCredentialRootPresenterAuthorization::Private {
            persona_public_key: issuer(0x70),
            persona_signature: &PERSONA_SIGNATURE,
        },
        records: [
            record(
                fixture,
                &fixture.first_claims,
                &fixture.first_status,
                0x40,
                false,
                wrong_issuer_status_root,
            )?,
            record(
                fixture,
                &fixture.second_claims,
                &fixture.second_status,
                0x50,
                wrong_root,
                false,
            )?,
        ],
    })
}

fn record<'a>(
    fixture: &'a Fixture,
    claims: &'a ZkCommonCredentialRootClaimsCommitment,
    opening: &'a ZkCommonCredentialRootIssuerStatusOpening,
    marker: u8,
    wrong_root: bool,
    wrong_issuer_status_root: bool,
) -> Result<ZkCommonCredentialRootSelectedCredentialRecord<'a>, TestError> {
    let status = common_credential_root_issuer_status_opening(&[0], 1, 0)
        .map_err(|_| TestError::RootStatus)?
        .0;
    let (root_signature, issuer_subject_signature, subject_link_signature, status_signature) =
        if marker == 0x40 {
            (
                &FIRST_ROOT_BINDING_SIGNATURE,
                &FIRST_ISSUER_SUBJECT_SIGNATURE,
                &FIRST_SUBJECT_LINK_SIGNATURE,
                &FIRST_STATUS_SIGNATURE,
            )
        } else {
            (
                &SECOND_ROOT_BINDING_SIGNATURE,
                &SECOND_ISSUER_SUBJECT_SIGNATURE,
                &SECOND_SUBJECT_LINK_SIGNATURE,
                &SECOND_STATUS_SIGNATURE,
            )
        };
    Ok(ZkCommonCredentialRootSelectedCredentialRecord {
        issuer_public_key: fixture.signer,
        lineage_root: if wrong_root { [0x99; 32] } else { ROOT },
        envelope_hash: [marker; 32],
        issuer_root_binding_signature: root_signature,
        claims,
        selected_claim_index: 1,
        subject_public_key: issuer(marker + 1),
        relationship_did_hash: [marker + 2; 32],
        relationship_nonce: [marker + 3; 32],
        issuer_subject_binding_signature: issuer_subject_signature,
        subject_link_signature,
        issuer_status: ZkCommonCredentialRootSelectedIssuerStatus {
            root: if wrong_issuer_status_root {
                [0x88; 32]
            } else {
                status
            },
            length: 1,
            list_id: [marker + 6; 32],
            url_hash: [marker + 7; 32],
            purpose: ZkIssuerStatusPurpose::Revocation,
            issuer_validity_status_signature: status_signature,
            valid_from: NOW - 1,
            valid_until: NOW + MAX_PRESENTATION_LIFETIME_SECONDS + 1,
            status_index: 0,
            opening,
        },
    })
}

fn fixture() -> Result<Fixture, TestError> {
    fixture_with_hash(ZkCredentialHashAlgorithm::Sha256)
}

fn fixture_with_hash(
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<Fixture, TestError> {
    let (signature, signer, snapshot) = signed_assurance()?;
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
        ),
        assurance_policy_id: POLICY,
    };
    let holder = ZkCommonCredentialRootHolderAssurance::admit(
        material(signer, &signature),
        trust,
        snapshot,
        NOW,
        0,
        &[],
    )
    .map_err(|_| TestError::RootAssurance)?;
    let first_claims = claims(0x40, signer, credential_hash_algorithm)?;
    let second_claims = claims(0x50, signer, credential_hash_algorithm)?;
    let (_, first_status) = common_credential_root_issuer_status_opening(&[0], 1, 0)
        .map_err(|_| TestError::RootStatus)?;
    let (_, second_status) = common_credential_root_issuer_status_opening(&[0], 1, 0)
        .map_err(|_| TestError::RootStatus)?;
    Ok(Fixture {
        holder,
        snapshot,
        signer,
        first_claims,
        second_claims,
        first_status,
        second_status,
    })
}

fn claims(
    marker: u8,
    issuer_key: ZkIssuerPublicKey,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ZkCommonCredentialRootClaimsCommitment, TestError> {
    let subject = subject_key(issuer(marker + 1));
    let lineage = derive_common_credential_root_v1_lineage(
        &ROOT,
        issuer_key,
        "did:me:issuer-relationship",
        subject,
        &[marker + 3; 32],
    )
    .map_err(|_| TestError::Credential)?;
    let salt = [marker + 9; 16];
    let claim = ZkCommonCredentialRootClaim {
        name: "degree",
        value: b"verified",
        salt: &salt,
    };
    match credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            build_common_credential_root_sha256_claims_commitment(&lineage, &salt, &[claim])
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            build_common_credential_root_poseidon2_claims_commitment(&lineage, &salt, &[claim])
        }
        _ => return Err(TestError::Credential),
    }
    .map_err(|_| TestError::Credential)
}

fn signed_assurance(
) -> Result<([u8; 64], ZkIssuerPublicKey, ZkVerifiedRootStatusSnapshot), TestError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _) = crypto_p256::generate_p256_keypair_from_secret_key(&secret)?;
    let point = crypto_p256::decompress_public_key(&compressed)?;
    let signer = ZkIssuerPublicKey {
        x: point[1..33]
            .try_into()
            .map_err(|_| TestError::PublicKeyShape)?,
        y: point[33..65]
            .try_into()
            .map_err(|_| TestError::PublicKeyShape)?,
    };
    let commitment = common_credential_root_root_commitment(&ROOT)?;
    let digest = common_credential_root_attestation_signing_digest(
        &commitment,
        POLICY,
        NOW - 60,
        ATTESTATION_EXPIRES,
        7,
    )?;
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der)?;
    let id = derive_common_credential_root_attestation_id(material(signer, &signature))
        .map_err(|_| TestError::RootAssurance)?;
    let mut leaf = [0_u8; 38];
    leaf[..6].copy_from_slice(b"RMSTL2");
    leaf[6..].copy_from_slice(&id);
    let status_root = crypto_sha2_256::digest(&leaf).into_bytes();
    let status_digest =
        ZkRootStatusSnapshot::signing_digest_for_fields(status_root, NOW - 1, NOW + 60, 7);
    let status_digest = crypto_p256::P256Sha256Digest::new(status_digest);
    let status_der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &status_digest)?;
    let status_signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&status_der)?;
    let snapshot = ZkRootStatusSnapshot::try_from_authority_signed_parts(
        status_root,
        NOW - 1,
        NOW + 60,
        7,
        reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
        ),
        status_signature,
    )
    .map_err(|_| TestError::RootStatus)?;
    let verified = verify_root_status_snapshot(
        snapshot,
        ZkRootStatusTrustPolicy {
            authority: reallyme_zk_api::keys::ZkStatusAuthorityPublicKey::from(
                reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
            ),
            minimum_sequence: 7,
            maximum_age_seconds: 120,
        },
        NOW,
    )
    .map_err(|_| TestError::RootStatus)?;
    Ok((signature, signer, verified))
}

fn material<'a>(
    signer: ZkIssuerPublicKey,
    signature: &'a [u8; 64],
) -> ZkCommonCredentialRootAttestationMaterial<'a> {
    ZkCommonCredentialRootAttestationMaterial {
        reallyme_public_key: reallyme_zk_api::keys::ZkAttestationPublicKey::from(
            reallyme_zk_api::keys::ZkP256PublicKey::from(signer),
        ),
        assurance_policy_id: POLICY,
        request_time_unix: NOW,
        root: &ROOT,
        attestation_issued_unix: NOW - 60,
        attestation_expires_unix: ATTESTATION_EXPIRES,
        attestation_epoch: 7,
        attestation_signature: signature,
    }
}

fn issuer(marker: u8) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [marker; 32],
        y: [marker + 1; 32],
    }
}
