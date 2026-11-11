// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn rejects_invalid_common_credential_root_join_derivation_inputs(
) -> Result<(), ZkCommonCredentialRootJoinGenerationError> {
    let mut rng = FixedRng { byte: 1 };
    let salt = ZkCommonCredentialRootPresentationSalt::generate(&mut rng)?;
    let root = [0x55; 32];
    let attestation_id = [0; 32];
    assert_eq!(
        zk_reason(derive_common_credential_root_presentation_joins(
            salt,
            ZkCommonCredentialRootJoinDerivationInputs {
                request: ZkCommonCredentialRootRequestJoinContext {
                    challenge: CHALLENGE,
                    audience_hash: AUDIENCE,
                    transaction_data_hash: TRANSACTION,
                },
                root: &root,
                attestation_id: &attestation_id,
                subject_public_keys: [
                    ZkCommonCredentialRootSubjectPublicKey {
                        x: [0xc0; 32],
                        y: [0xc1; 32],
                    },
                    ZkCommonCredentialRootSubjectPublicKey {
                        x: [0xc0; 32],
                        y: [0xc1; 32],
                    },
                ],
            },
        )),
        Some(ZkErrorReason::BindingMismatch)
    );
    Ok(())
}

#[test]
fn both_persona_modes_join_when_all_verified_inputs_match() {
    assert!(
        Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona)
            .check()
            .is_ok()
    );
    assert!(
        Fixture::new(ZkCommonCredentialRootPersonaMode::PublicPersona)
            .check()
            .is_ok()
    );
}

#[test]
fn rejects_untrusted_assurance_and_status() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_key(&mut fixture.attestation, 0, issuer(0xa2));
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::UntrustedIssuer)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.status, 96, &[0x99; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.status, 160, &[0x99; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );
}

#[test]
fn rejects_replay_and_cross_credential_substitution() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.claims[1], 128, &[0x99; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.claims[1], 225, &[0x99; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.lineage[1], 193, &[0xd1; 32]);
    set_bytes(&mut fixture.claims[1], 193, &[0xd1; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::InvalidClaimProofBundle)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    fixture.claims.swap(0, 1);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::UntrustedIssuer)
    );
}

#[test]
fn rejects_claim_and_persona_substitution() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.claims[0], 258, b"forged");
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PublicPersona);
    set_key(&mut fixture.claims[1], 64, issuer(0xb2));
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.claims[0], 322, &RESERVED_LINEAGE_NAME_HASH);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );
}

#[test]
fn rejects_each_active_request_binding_and_wrong_claim_name() {
    for (field, replacement) in [(0, [0x99; 32]), (32, [0x98; 32]), (64, [0x97; 32])] {
        let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
        set_bytes(&mut fixture.status, field, &replacement);
        assert_eq!(
            reason(fixture.check()),
            Some(ZkErrorReason::BindingMismatch)
        );
    }

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.session, 97, &[0x96; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.claims[1], 322, &[0x95; 32]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::BindingMismatch)
    );
}

#[test]
fn rejects_invalid_verifier_owned_policy_before_reading_proofs() {
    let fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    let mut policy = fixture.policy();
    policy.request_time_unix = 0;
    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::PresentationExpired)
    );

    let mut policy = fixture.policy();
    policy.claims[0].value = b"";
    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::ClaimPayloadTooLarge)
    );

    let mut policy = fixture.policy();
    policy.claims[0].value = &[0x42; 65];
    assert_eq!(
        reason(check_common_credential_root_v1_joins(
            fixture.inputs(),
            policy
        )),
        Some(ZkErrorReason::ClaimPayloadTooLarge)
    );
}

#[test]
fn rejects_expiry_and_malformed_fields() {
    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_u64(&mut fixture.session, 96, REQUEST_TIME);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::PresentationExpired)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_u64(&mut fixture.session, 96, REQUEST_TIME + 301);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::PresentationExpiryTooFar)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    fixture.attestation[0] = 1;
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    fixture.lineage[0].pop();
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_bytes(&mut fixture.claims[0], 258 + FIRST_VALUE.len(), &[1]);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );

    let mut fixture = Fixture::new(ZkCommonCredentialRootPersonaMode::PrivatePersona);
    set_u32(&mut fixture.claims[0], 257, 65);
    assert_eq!(
        reason(fixture.check()),
        Some(ZkErrorReason::InvalidProofEncoding)
    );
}

/// Runs after `circuits/test-common-credential-root-joined-claims.sh` has generated and
/// cryptographically verified the candidate proofs. This checks that the Rust
/// decoder and policy composition agree with the real Noir public-input ABI.
#[test]
#[ignore = "requires generated and verified common-credential-root candidate proof outputs"]
fn generated_candidate_public_inputs_join_in_both_lanes_and_persona_modes() -> Result<(), ZkError> {
    use std::path::{Path, PathBuf};

    fn hash(value: &str) -> Result<[u8; 32], ZkError> {
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let begin = index * 2;
            let pair = value
                .get(begin..begin + 2)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        }
        Ok(bytes)
    }

    fn read(path: &Path) -> Result<Vec<u8>, ZkError> {
        std::fs::read(path).map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))
    }

    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let signer = ZkIssuerPublicKey {
        x: hash("8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3")?,
        y: hash("73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4")?,
    };
    let university = ZkIssuerPublicKey {
        x: hash("3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1")?,
        y: hash("9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740")?,
    };
    let employer = ZkIssuerPublicKey {
        x: hash("47776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73e")?,
        y: hash("aa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc")?,
    };
    for lane in ["sha256", "poseidon2"] {
        let credential_hash_algorithm = match lane {
            "sha256" => ZkCredentialHashAlgorithm::Sha256,
            "poseidon2" => ZkCredentialHashAlgorithm::Poseidon2,
            _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        };
        let family = repository
            .join("circuits")
            .join(lane)
            .join("families/common_credential_root_v1");
        let attestation =
            read(&family.join("root_attestation/target/attestation-proof/public_inputs"))?;
        let status = read(&family.join("root_status/target/status-proof/public_inputs"))?;
        let lineage = [
            read(&family.join("lineage/target/lineage-proof/public_inputs"))?,
            read(&family.join("lineage/target/lineage-proof-employer/public_inputs"))?,
        ];
        for mode in [
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCommonCredentialRootPersonaMode::PublicPersona,
        ] {
            let persona_mode = mode;
            let mode_name = match mode {
                ZkCommonCredentialRootPersonaMode::PrivatePersona => "private",
                ZkCommonCredentialRootPersonaMode::PublicPersona => "public",
            };
            let claims = [
                read(&family.join(format!(
                    "{mode_name}_persona_claim/target/proof/public_inputs"
                )))?,
                read(&family.join(format!(
                    "{mode_name}_persona_claim/target/proof-employer/public_inputs"
                )))?,
            ];
            let session = read(&repository.join(format!(
                "circuits/{lane}/families/{mode_name}_persona_claim_v1/session/target/common-credential-root-session-proof/public_inputs"
            )))?;
            let mut issuer_status = [
                vec![0_u8; ISSUER_CREDENTIAL_STATUS_FIELDS * FIELD_BYTES],
                vec![0_u8; ISSUER_CREDENTIAL_STATUS_FIELDS * FIELD_BYTES],
            ];
            for role in 0..2 {
                let lineage_fields = super::Fields::new(&lineage[role], LINEAGE_FIELDS)?;
                set_bytes(&mut issuer_status[role], 0, &lineage_fields.bytes32(0)?);
                set_bytes(&mut issuer_status[role], 32, &lineage_fields.bytes32(32)?);
                set_bytes(&mut issuer_status[role], 64, &lineage_fields.bytes32(64)?);
                set_key(&mut issuer_status[role], 96, lineage_fields.key(128)?);
                set_u64(&mut issuer_status[role], 160, lineage_fields.u64(192)?);
                set_bytes(&mut issuer_status[role], 161, &lineage_fields.bytes32(193)?);
                set_bytes(&mut issuer_status[role], 193, &[0xa1; 32]);
                set_u64(&mut issuer_status[role], 225, 256);
                set_bytes(&mut issuer_status[role], 226, &[0xa2; 32]);
                set_bytes(&mut issuer_status[role], 258, &[0xa3; 32]);
                set_bytes(&mut issuer_status[role], 290, &[1]);
                set_u64(&mut issuer_status[role], 291, 1_900_000_000);
            }
            for (slot, raw) in [
                (
                    ZkCommonCredentialRootProofSlot::RootAttestation,
                    attestation.as_slice(),
                ),
                (
                    ZkCommonCredentialRootProofSlot::RootStatus,
                    status.as_slice(),
                ),
                (
                    ZkCommonCredentialRootProofSlot::Lineage0,
                    lineage[0].as_slice(),
                ),
                (
                    ZkCommonCredentialRootProofSlot::Lineage1,
                    lineage[1].as_slice(),
                ),
                (
                    ZkCommonCredentialRootProofSlot::SelectedClaim0,
                    claims[0].as_slice(),
                ),
                (
                    ZkCommonCredentialRootProofSlot::SelectedClaim1,
                    claims[1].as_slice(),
                ),
                (ZkCommonCredentialRootProofSlot::Session, session.as_slice()),
                (
                    ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
                    issuer_status[0].as_slice(),
                ),
                (
                    ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1,
                    issuer_status[1].as_slice(),
                ),
            ] {
                let circuit_ref = persona_mode.source_ref(credential_hash_algorithm, slot);
                let _validated =
                    ZkCommonCredentialRootRawPublicInputs::try_copy_from_slice(circuit_ref, raw)?;
            }
            let inputs = ZkCommonCredentialRootPublicInputs {
                attestation: &attestation,
                status: &status,
                lineage: [&lineage[0], &lineage[1]],
                selected_claim: [&claims[0], &claims[1]],
                session: &session,
                issuer_credential_status: [&issuer_status[0], &issuer_status[1]],
            };
            let policy = || -> Result<ZkCommonCredentialRootJoinPolicy<'static>, ZkError> {
                Ok(ZkCommonCredentialRootJoinPolicy {
                    challenge: hash(
                        "079218fa88fc77937eabd22a503fcbc388214e8a57b15d7094d139c3735f085f",
                    )?,
                    audience_hash: hash(
                        "4014008db00389b6cd1b90155ab0a04f3d7de8499d78711ad16c590ab60c6733",
                    )?,
                    transaction_data_hash: hash(
                        "540f76b8e8e352e49fe0e4e3aa0ae642c56266ccc3043feaba7c6bbed282acc2",
                    )?,
                    request_time_unix: 1_900_000_000,
                    status_validation_time_unix: 1_900_000_000,
                    status_validation_max_age_seconds: 120,
                    attestation_signer: crate::keys::ZkAttestationPublicKey::from(
                        crate::keys::ZkP256PublicKey::from(signer),
                    ),
                    assurance_policy_id: hash(
                        "ad1927afb41bd21ab87899732707f7c8aa5a75d97f4a43457cbc5f846095321d",
                    )?,
                    status_root: hash(
                        "b2079dd0ae99debe99a236712b550503afcd60eab87c7cdec364dc6152e02feb",
                    )?,
                    claims: [
                        ZkCommonCredentialRootClaimExpectation {
                            issuer: university,
                            claim_name_hash: hash(
                                "052daff789976063a34b2ff97e457d57474e6c86f6a0ab6b92dc574c23c5216b",
                            )?,
                            value: b"verified:university",
                        },
                        ZkCommonCredentialRootClaimExpectation {
                            issuer: employer,
                            claim_name_hash: hash(
                                "971a3625e73d57a42c2ec6713264895ded73ce552ebb7617689a0daad97b9002",
                            )?,
                            value: b"verified:employer",
                        },
                    ],
                    issuer_status: [ZkCommonCredentialRootIssuerStatusExpectation {
                        root: [0xa1; 32],
                        length: 256,
                        list_id: [0xa2; 32],
                        url_hash: [0xa3; 32],
                        purpose: ZkIssuerStatusPurpose::Revocation,
                    }; 2],
                    persona_mode: mode,
                })
            };
            assert!(check_common_credential_root_v1_joins(inputs, policy()?).is_ok());

            let different_subject = read(&family.join(format!(
                "{mode_name}_persona_claim/target/proof-other-subject/public_inputs"
            )))?;
            let substituted_subject = ZkCommonCredentialRootPublicInputs {
                attestation: &attestation,
                status: &status,
                lineage: [&lineage[0], &lineage[1]],
                selected_claim: [&different_subject, &claims[1]],
                session: &session,
                issuer_credential_status: [&issuer_status[0], &issuer_status[1]],
            };
            assert_eq!(
                reason(check_common_credential_root_v1_joins(
                    substituted_subject,
                    policy()?
                )),
                Some(ZkErrorReason::BindingMismatch)
            );

            let different_persona = read(&family.join(format!(
                "{mode_name}_persona_claim/target/proof-different-persona/public_inputs"
            )))?;
            let substituted_persona = ZkCommonCredentialRootPublicInputs {
                attestation: &attestation,
                status: &status,
                lineage: [&lineage[0], &lineage[1]],
                selected_claim: [&claims[0], &different_persona],
                session: &session,
                issuer_credential_status: [&issuer_status[0], &issuer_status[1]],
            };
            assert_eq!(
                reason(check_common_credential_root_v1_joins(
                    substituted_persona,
                    policy()?
                )),
                Some(ZkErrorReason::BindingMismatch)
            );

            let different_attestation = read(
                &family.join("root_attestation/target/attestation-proof-other/public_inputs"),
            )?;
            let substituted_attestation = ZkCommonCredentialRootPublicInputs {
                attestation: &different_attestation,
                status: &status,
                lineage: [&lineage[0], &lineage[1]],
                selected_claim: [&claims[0], &claims[1]],
                session: &session,
                issuer_credential_status: [&issuer_status[0], &issuer_status[1]],
            };
            assert_eq!(
                reason(check_common_credential_root_v1_joins(
                    substituted_attestation,
                    policy()?
                )),
                Some(ZkErrorReason::BindingMismatch)
            );
        }
    }
    Ok(())
}
