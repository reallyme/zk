// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    check_common_credential_root_v1_joins, derive_common_credential_root_attestation_id,
    derive_common_credential_root_presentation_joins,
    derive_common_credential_root_presentation_material, ZkCommonCredentialRootAttestationMaterial,
    ZkCommonCredentialRootClaimExpectation, ZkCommonCredentialRootIssuerStatusExpectation,
    ZkCommonCredentialRootJoinDerivationInputs, ZkCommonCredentialRootJoinGenerationError,
    ZkCommonCredentialRootJoinPolicy, ZkCommonCredentialRootPersonaMode,
    ZkCommonCredentialRootPresentationSalt, ZkCommonCredentialRootPublicInputs,
    ZkCommonCredentialRootRequestJoinContext, ZkCommonCredentialRootStageInputMaterial,
    ZkCommonCredentialRootStageSaltError, ZkCommonCredentialRootSubjectPublicKey,
    ZkIssuerStatusPurpose, ATTESTATION_FIELDS, CREDENTIAL_SUBJECT_CLAIM_FIELDS, FIELD_BYTES,
    ISSUER_CREDENTIAL_STATUS_FIELDS, LINEAGE_FIELDS, PRIVATE_SESSION_FIELDS, PUBLIC_CLAIM_FIELDS,
    PUBLIC_SESSION_FIELDS, RESERVED_LINEAGE_NAME_HASH, STATUS_FIELDS,
};
#[cfg(feature = "native")]
use super::{
    verify_common_credential_root_attestation_material,
    ZkCommonCredentialRootAttestationTrustPolicy,
};
use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
use crypto_csprng::SecureRandom;
#[cfg(feature = "native")]
use zeroize::Zeroizing;

use crate::{common_root::{ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootRawPublicInputs}, circuits::{ZkCredentialHashAlgorithm}, errors::{ZkError, ZkErrorReason}, keys::{ZkIssuerPublicKey}};

const REQUEST_TIME: u64 = 1_900_000_000;
const EXPIRY: u64 = REQUEST_TIME + 180;
const CHALLENGE: [u8; 32] = [0x11; 32];
const AUDIENCE: [u8; 32] = [0x22; 32];
const TRANSACTION: [u8; 32] = [0x33; 32];
const ROOT_JOIN: [u8; 32] = [0x44; 32];
const ATTESTATION_JOIN: [u8; 32] = [0x55; 32];
const STATUS_ROOT: [u8; 32] = [0x66; 32];
const POLICY_ID: [u8; 32] = [0x77; 32];
const SESSION_BINDING: [u8; 32] = [0x88; 32];
const FIRST_NAME: [u8; 32] = [0x91; 32];
const SECOND_NAME: [u8; 32] = [0x92; 32];
const FIRST_VALUE: &[u8] = b"degree";
const SECOND_VALUE: &[u8] = b"employed";

struct FixedRng {
    byte: u8,
}

impl SecureRandom for FixedRng {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        output.fill(self.byte);
        Ok(())
    }
}

struct FailingRng;

impl SecureRandom for FailingRng {
    fn fill_secure(&mut self, _output: &mut [u8], kind: RngOutputKind) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output: kind,
            kind: RngFailureKind::EntropyUnavailable,
        })
    }
}

fn issuer(marker: u8) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [marker; 32],
        y: [marker + 1; 32],
    }
}

struct Fixture {
    attestation: Vec<u8>,
    status: Vec<u8>,
    lineage: [Vec<u8>; 2],
    claims: [Vec<u8>; 2],
    session: Vec<u8>,
    issuer_status: [Vec<u8>; 2],
    mode: ZkCommonCredentialRootPersonaMode,
}

impl Fixture {
    fn new(mode: ZkCommonCredentialRootPersonaMode) -> Self {
        let (claim_count, session_count, claim_offset, session_offset) = match mode {
            ZkCommonCredentialRootPersonaMode::PrivatePersona => (
                CREDENTIAL_SUBJECT_CLAIM_FIELDS,
                PRIVATE_SESSION_FIELDS,
                0,
                0,
            ),
            ZkCommonCredentialRootPersonaMode::PublicPersona => {
                (PUBLIC_CLAIM_FIELDS, PUBLIC_SESSION_FIELDS, 64, 64)
            }
        };
        let mut fixture = Self {
            attestation: vec![0; ATTESTATION_FIELDS * FIELD_BYTES],
            status: vec![0; STATUS_FIELDS * FIELD_BYTES],
            lineage: [
                vec![0; LINEAGE_FIELDS * FIELD_BYTES],
                vec![0; LINEAGE_FIELDS * FIELD_BYTES],
            ],
            claims: [
                vec![0; claim_count * FIELD_BYTES],
                vec![0; claim_count * FIELD_BYTES],
            ],
            session: vec![0; session_count * FIELD_BYTES],
            issuer_status: [
                vec![0; ISSUER_CREDENTIAL_STATUS_FIELDS * FIELD_BYTES],
                vec![0; ISSUER_CREDENTIAL_STATUS_FIELDS * FIELD_BYTES],
            ],
            mode,
        };
        set_key(&mut fixture.attestation, 0, issuer(0xa0));
        set_bytes(&mut fixture.attestation, 64, &POLICY_ID);
        set_u64(&mut fixture.attestation, 96, REQUEST_TIME);
        set_u64(&mut fixture.attestation, 97, EXPIRY);
        set_request(&mut fixture.attestation, 98);
        set_bytes(&mut fixture.attestation, 194, &ROOT_JOIN);
        set_bytes(&mut fixture.attestation, 226, &ATTESTATION_JOIN);
        set_request(&mut fixture.status, 0);
        set_bytes(&mut fixture.status, 96, &STATUS_ROOT);
        set_bytes(&mut fixture.status, 128, &ROOT_JOIN);
        set_bytes(&mut fixture.status, 160, &ATTESTATION_JOIN);
        set_request(&mut fixture.session, session_offset);
        set_u64(&mut fixture.session, session_offset + 96, EXPIRY);
        set_bytes(&mut fixture.session, session_offset + 97, &SESSION_BINDING);
        if mode == ZkCommonCredentialRootPersonaMode::PublicPersona {
            set_key(&mut fixture.session, 0, issuer(0xb0));
        }
        for slot in 0..2 {
            let (issuer_key, name, value, credential, subject) = if slot == 0 {
                (
                    issuer(0xc0),
                    FIRST_NAME,
                    FIRST_VALUE,
                    [0xd1; 32],
                    [0xe1; 32],
                )
            } else {
                (
                    issuer(0xc2),
                    SECOND_NAME,
                    SECOND_VALUE,
                    [0xd2; 32],
                    [0xe2; 32],
                )
            };
            set_request(&mut fixture.lineage[slot], 0);
            set_bytes(&mut fixture.lineage[slot], 96, &ROOT_JOIN);
            set_key(&mut fixture.lineage[slot], 128, issuer_key);
            set_u64(&mut fixture.lineage[slot], 192, EXPIRY);
            set_bytes(&mut fixture.lineage[slot], 193, &credential);
            set_bytes(&mut fixture.lineage[slot], 225, &subject);

            set_request(&mut fixture.issuer_status[slot], 0);
            set_key(&mut fixture.issuer_status[slot], 96, issuer_key);
            set_u64(&mut fixture.issuer_status[slot], 160, EXPIRY);
            set_bytes(&mut fixture.issuer_status[slot], 161, &credential);
            set_bytes(&mut fixture.issuer_status[slot], 193, &[0xa1; 32]);
            set_u64(&mut fixture.issuer_status[slot], 225, 256);
            set_bytes(&mut fixture.issuer_status[slot], 226, &[0xa2; 32]);
            set_bytes(&mut fixture.issuer_status[slot], 258, &[0xa3; 32]);
            set_bytes(&mut fixture.issuer_status[slot], 290, &[1]);
            set_u64(&mut fixture.issuer_status[slot], 291, REQUEST_TIME);

            set_key(&mut fixture.claims[slot], 0, issuer_key);
            if mode == ZkCommonCredentialRootPersonaMode::PublicPersona {
                set_key(&mut fixture.claims[slot], 64, issuer(0xb0));
            }
            set_request(&mut fixture.claims[slot], claim_offset + 64);
            set_u64(&mut fixture.claims[slot], claim_offset + 160, EXPIRY);
            set_bytes(
                &mut fixture.claims[slot],
                claim_offset + 161,
                &SESSION_BINDING,
            );
            set_bytes(&mut fixture.claims[slot], claim_offset + 193, &credential);
            set_bytes(&mut fixture.claims[slot], claim_offset + 225, &subject);
            set_u32(
                &mut fixture.claims[slot],
                claim_offset + 257,
                u32::try_from(value.len()).unwrap_or_default(),
            );
            set_bytes(&mut fixture.claims[slot], claim_offset + 258, value);
            set_bytes(&mut fixture.claims[slot], claim_offset + 322, &name);
        }
        fixture
    }

    fn inputs(&self) -> ZkCommonCredentialRootPublicInputs<'_> {
        ZkCommonCredentialRootPublicInputs {
            attestation: &self.attestation,
            status: &self.status,
            lineage: [&self.lineage[0], &self.lineage[1]],
            selected_claim: [&self.claims[0], &self.claims[1]],
            session: &self.session,
            issuer_credential_status: [&self.issuer_status[0], &self.issuer_status[1]],
        }
    }

    fn policy(&self) -> ZkCommonCredentialRootJoinPolicy<'static> {
        ZkCommonCredentialRootJoinPolicy {
            challenge: CHALLENGE,
            audience_hash: AUDIENCE,
            transaction_data_hash: TRANSACTION,
            request_time_unix: REQUEST_TIME,
            status_validation_time_unix: REQUEST_TIME,
            status_validation_max_age_seconds: 120,
            attestation_signer: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(
                issuer(0xa0),
            )),
            assurance_policy_id: POLICY_ID,
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
            issuer_status: [ZkCommonCredentialRootIssuerStatusExpectation {
                root: [0xa1; 32],
                length: 256,
                list_id: [0xa2; 32],
                url_hash: [0xa3; 32],
                purpose: ZkIssuerStatusPurpose::Revocation,
            }; 2],
            persona_mode: self.mode,
        }
    }

    fn check(&self) -> Result<(), ZkError> {
        check_common_credential_root_v1_joins(self.inputs(), self.policy())
    }
}

#[test]
fn common_credential_root_joins_reject_mismatched_attestation_presentation_expiry() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_u64(&mut fixture.attestation, 97, EXPIRY + 1);

    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );
}

#[test]
fn common_credential_root_joins_accept_current_issuer_status_validation_time() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    let status_validation_time = REQUEST_TIME + 30;
    for issuer_status in &mut fixture.issuer_status {
        set_u64(issuer_status, 291, status_validation_time);
    }
    let mut policy = fixture.policy();
    policy.status_validation_time_unix = status_validation_time + 15;

    assert!(check_common_credential_root_v1_joins(fixture.inputs(), policy).is_ok());
}

#[test]
fn common_credential_root_joins_reject_status_validation_time_before_request() {
    let fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    let mut policy = fixture.policy();
    policy.status_validation_time_unix = REQUEST_TIME - 1;

    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::PresentationExpired)
    );
}

#[test]
fn common_credential_root_joins_reject_status_validation_time_at_expiry() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    for issuer_status in &mut fixture.issuer_status {
        set_u64(issuer_status, 291, EXPIRY);
    }

    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::PresentationExpired)
    );
}

#[test]
fn common_credential_root_joins_reject_presentation_expired_at_verifier_time() {
    let fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    let mut policy = fixture.policy();
    policy.status_validation_time_unix = EXPIRY;

    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::PresentationExpired)
    );
}

#[test]
fn common_credential_root_joins_reject_stale_status_validation_time() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    let status_validation_time = REQUEST_TIME + 30;
    for issuer_status in &mut fixture.issuer_status {
        set_u64(issuer_status, 291, status_validation_time);
    }
    let mut policy = fixture.policy();
    policy.status_validation_time_unix = status_validation_time + 121;

    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::PresentationExpired)
    );
}

#[test]
fn common_credential_root_joins_reject_future_status_validation_time() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    let status_validation_time = REQUEST_TIME + 30;
    for issuer_status in &mut fixture.issuer_status {
        set_u64(issuer_status, 291, status_validation_time);
    }
    let mut policy = fixture.policy();
    policy.status_validation_time_unix = status_validation_time - 1;

    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::PresentationExpired)
    );
}

fn set_bytes(fields: &mut [u8], first: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        let index = (first + offset) * FIELD_BYTES + FIELD_BYTES - 1;
        fields[index] = *byte;
    }
}

fn set_u64(fields: &mut [u8], index: usize, value: u64) {
    let start = index * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn set_u32(fields: &mut [u8], index: usize, value: u32) {
    let start = index * FIELD_BYTES + FIELD_BYTES - 4;
    fields[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

fn set_key(fields: &mut [u8], first: usize, key: ZkIssuerPublicKey) {
    set_bytes(fields, first, &key.x);
    set_bytes(fields, first + 32, &key.y);
}

fn set_request(fields: &mut [u8], first: usize) {
    set_bytes(fields, first, &CHALLENGE);
    set_bytes(fields, first + 32, &AUDIENCE);
    set_bytes(fields, first + 64, &TRANSACTION);
}

fn reason(result: Result<(), ZkError>) -> Option<ZkErrorReason> {
    result.err().map(|error| error.reason())
}

fn zk_reason<T>(result: Result<T, ZkError>) -> Option<ZkErrorReason> {
    result.err().map(|error| error.reason())
}

fn hex32(value: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let begin = index * 2;
        let pair = &value[begin..begin + 2];
        *byte = u8::from_str_radix(pair, 16).unwrap_or_default();
    }
    output
}

fn derivation_inputs<'a>(
    root: &'a [u8; 32],
    attestation_id: &'a [u8; 32],
    request: ZkCommonCredentialRootRequestJoinContext,
) -> ZkCommonCredentialRootJoinDerivationInputs<'a> {
    ZkCommonCredentialRootJoinDerivationInputs {
        request,
        root,
        attestation_id,
        subject_public_keys: [
            ZkCommonCredentialRootSubjectPublicKey {
                x: [0xc0; 32],
                y: [0xc1; 32],
            },
            ZkCommonCredentialRootSubjectPublicKey {
                x: [0xc2; 32],
                y: [0xc3; 32],
            },
        ],
    }
}

#[test]
fn derives_common_credential_root_attestation_and_presentation_join_vectors() -> Result<(), ZkError>
{
    let root: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let signature: [u8; 64] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
        0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
        0x7c, 0x7d, 0x7e, 0x7f,
    ];
    let attestation_id =
        derive_common_credential_root_attestation_id(ZkCommonCredentialRootAttestationMaterial {
            reallyme_public_key: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(
                issuer(0xa0),
            )),
            assurance_policy_id: POLICY_ID,
            request_time_unix: REQUEST_TIME,
            root: &root,
            attestation_issued_unix: REQUEST_TIME - 60,
            attestation_expires_unix: EXPIRY,
            attestation_epoch: 7,
            attestation_signature: &signature,
        })?;
    assert_eq!(
        attestation_id,
        hex32("cd0f03c0306d0677cc4e706ccb4aafd52630e9868e745182be90f310ed91060e")
    );

    let mut rng = FixedRng { byte: 0x6a };
    let salt = ZkCommonCredentialRootPresentationSalt::generate(&mut rng)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let joins = derive_common_credential_root_presentation_joins(
        salt,
        derivation_inputs(
            &root,
            &attestation_id,
            ZkCommonCredentialRootRequestJoinContext {
                challenge: CHALLENGE,
                audience_hash: AUDIENCE,
                transaction_data_hash: TRANSACTION,
            },
        ),
    )?;
    assert_eq!(
        joins.root_join,
        hex32("88153cfa0f21eb4339d11b74a3c2ac0ba54a8a95e0552e63380b559897511331")
    );
    assert_eq!(
        joins.attestation_join,
        hex32("57ba9a9f009e67b940d1156643d66ba542e8f44ad31db4cc19210f0d79b30526")
    );
    assert_eq!(
        joins.subject_joins[0],
        hex32("60ac23db792c1ad2f4287a64cebb2fad051901f8b15aa78b2fcbf3302bf6011e")
    );
    assert_eq!(
        joins.subject_joins[1],
        hex32("8b30ba57518d0bdbfa7ab7c5049aadf56b9c03197c6d437bf893ca4c253fc877")
    );
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn attestation_material_requires_the_exact_reallyme_signature() -> Result<(), ZkError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret[31] = 37;
    let (compressed, _owned_secret) = crypto_p256::generate_p256_keypair_from_secret_key(&secret)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProof))?;
    let point = crypto_p256::decompress_public_key(&compressed)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProof))?;
    let signer = ZkIssuerPublicKey {
        x: point[1..33]
            .try_into()
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProof))?,
        y: point[33..65]
            .try_into()
            .map_err(|_| ZkError::new(ZkErrorReason::InvalidProof))?,
    };
    let root = [0x34; 32];
    let placeholder_signature = [1_u8; 64];
    let digest = super::common_credential_root_attestation_digest(
        &ZkCommonCredentialRootAttestationMaterial {
            reallyme_public_key: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(
                signer,
            )),
            assurance_policy_id: POLICY_ID,
            request_time_unix: REQUEST_TIME,
            root: &root,
            attestation_issued_unix: REQUEST_TIME - 60,
            attestation_expires_unix: EXPIRY,
            attestation_epoch: 7,
            attestation_signature: &placeholder_signature,
        },
    )?;
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProof))?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&der)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProof))?;
    let valid = || ZkCommonCredentialRootAttestationMaterial {
        reallyme_public_key: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(
            signer,
        )),
        assurance_policy_id: POLICY_ID,
        request_time_unix: REQUEST_TIME,
        root: &root,
        attestation_issued_unix: REQUEST_TIME - 60,
        attestation_expires_unix: EXPIRY,
        attestation_epoch: 7,
        attestation_signature: &signature,
    };
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(signer)),
        assurance_policy_id: POLICY_ID,
    };
    assert!(verify_common_credential_root_attestation_material(valid(), trust).is_ok());
    let mut wrong = signature;
    wrong[0] ^= 1;
    assert_eq!(
        verify_common_credential_root_attestation_material(
            ZkCommonCredentialRootAttestationMaterial {
                attestation_signature: &wrong,
                ..valid()
            },
            trust
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProof)
    );
    assert_eq!(
        verify_common_credential_root_attestation_material(
            ZkCommonCredentialRootAttestationMaterial {
                assurance_policy_id: [0x78; 32],
                ..valid()
            },
            trust
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::BindingMismatch)
    );
    assert_eq!(
        verify_common_credential_root_attestation_material(
            valid(),
            ZkCommonCredentialRootAttestationTrustPolicy {
                signer: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(
                    ZkIssuerPublicKey {
                        x: [0x12; 32],
                        y: [0x34; 32],
                    }
                )),
                ..trust
            },
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::UntrustedIssuer)
    );
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn attestation_verifier_matches_the_noir_root_attestation_fixture() {
    // These bytes are from the SHA-256 root_attestation Prover.toml. Keep this
    // independent of the Rust signing helper to catch transcript drift.
    let signer = ZkIssuerPublicKey {
        x: [
            142, 83, 59, 111, 160, 191, 123, 70, 37, 187, 48, 102, 124, 1, 251, 96, 126, 249, 248,
            184, 168, 15, 239, 91, 48, 6, 40, 112, 49, 135, 178, 163,
        ],
        y: [
            115, 235, 29, 189, 224, 51, 24, 54, 109, 6, 159, 131, 166, 245, 144, 0, 83, 199, 54,
            51, 203, 4, 27, 33, 197, 94, 26, 134, 193, 244, 0, 180,
        ],
    };
    let policy = [
        173, 25, 39, 175, 180, 27, 210, 26, 184, 120, 153, 115, 39, 7, 247, 200, 170, 90, 117, 217,
        127, 74, 67, 69, 124, 188, 95, 132, 96, 149, 50, 29,
    ];
    let root = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let signature = [
        128, 62, 219, 73, 246, 210, 159, 5, 232, 114, 227, 99, 146, 186, 123, 234, 249, 56, 196,
        50, 131, 103, 156, 138, 218, 86, 187, 44, 207, 191, 220, 209, 36, 36, 248, 207, 215, 193,
        221, 92, 108, 152, 17, 146, 183, 215, 41, 150, 88, 52, 56, 144, 115, 121, 4, 106, 91, 70,
        115, 228, 120, 70, 7, 65,
    ];
    let material = || ZkCommonCredentialRootAttestationMaterial {
        reallyme_public_key: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(
            signer,
        )),
        assurance_policy_id: policy,
        request_time_unix: 1_900_000_000,
        root: &root,
        attestation_issued_unix: 1_800_000_000,
        attestation_expires_unix: 2_000_000_000,
        attestation_epoch: 3,
        attestation_signature: &signature,
    };
    let trust = ZkCommonCredentialRootAttestationTrustPolicy {
        signer: crate::keys::ZkAttestationPublicKey::from(crate::keys::ZkP256PublicKey::from(signer)),
        assurance_policy_id: policy,
    };
    assert_eq!(
        verify_common_credential_root_attestation_material(material(), trust),
        Ok(hex32(
            "dadfc597406191848a73813c26881cc910a2b1f89f1717b3489942199e359551"
        ))
    );
    assert_eq!(
        verify_common_credential_root_attestation_material(
            ZkCommonCredentialRootAttestationMaterial {
                attestation_epoch: 4,
                ..material()
            },
            trust,
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::InvalidProof)
    );
}

#[test]
fn rejects_degenerate_common_credential_root_salt_before_join_derivation() {
    let mut rng = FixedRng { byte: 0 };
    assert!(matches!(
        ZkCommonCredentialRootPresentationSalt::generate(&mut rng),
        Err(ZkCommonCredentialRootJoinGenerationError::DegenerateSalt)
    ));
}

#[test]
fn propagates_injected_rng_failure_without_backend_error_mapping() {
    let mut rng = FailingRng;
    assert!(matches!(
        ZkCommonCredentialRootPresentationSalt::generate(&mut rng),
        Err(ZkCommonCredentialRootJoinGenerationError::Random {
            source: CryptoError::Rng {
                output: RngOutputKind::Generic,
                kind: RngFailureKind::EntropyUnavailable
            }
        })
    ));
}

#[test]
fn fresh_salt_and_request_binding_changes_derived_joins() -> Result<(), ZkError> {
    let root = [0x55; 32];
    let attestation_id = [0x44; 32];
    let request = ZkCommonCredentialRootRequestJoinContext {
        challenge: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: TRANSACTION,
    };
    let mut first_rng = FixedRng { byte: 0x6a };
    let first_salt = ZkCommonCredentialRootPresentationSalt::generate(&mut first_rng)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let first = derive_common_credential_root_presentation_joins(
        first_salt,
        derivation_inputs(&root, &attestation_id, request),
    )?;

    let mut second_rng = FixedRng { byte: 0x6b };
    let second_salt = ZkCommonCredentialRootPresentationSalt::generate(&mut second_rng)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let second = derive_common_credential_root_presentation_joins(
        second_salt,
        derivation_inputs(&root, &attestation_id, request),
    )?;
    assert_ne!(first.root_join, second.root_join);
    assert_ne!(first.attestation_join, second.attestation_join);
    assert_ne!(first.subject_joins, second.subject_joins);

    let mut request_rng = FixedRng { byte: 0x6a };
    let request_salt = ZkCommonCredentialRootPresentationSalt::generate(&mut request_rng)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let mut changed_request = request;
    changed_request.challenge = [0x12; 32];
    let request_changed = derive_common_credential_root_presentation_joins(
        request_salt,
        derivation_inputs(&root, &attestation_id, changed_request),
    )?;
    assert_ne!(first.root_join, request_changed.root_join);
    assert_ne!(first.attestation_join, request_changed.attestation_join);
    assert_ne!(first.subject_joins, request_changed.subject_joins);
    Ok(())
}
