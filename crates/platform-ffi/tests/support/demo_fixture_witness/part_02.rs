// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn exercise_generated_common_credential_root_verify_path(
    context: &PlatformContextGuard,
    lane: &'static str,
    mode: &'static str,
    proofs: Vec<
        reallyme_zk_proto_codec::common_credential_root::ZkCommonCredentialRootRawProofPackage,
    >,
) -> Result<(), TestError> {
    require_mobile_common_root_public_input_parity(lane, mode, &proofs)?;
    let request =
        generated_common_credential_root_verify_request(lane, mode, &proofs).map_err(|cause| {
            TestError::Fixture {
                bundle_kind: mode,
                stage: lane,
                operation: "build_generated_common_credential_root_verify_request",
                cause: Box::new(cause),
            }
        })?;
    let result =
        dispatch_success(context, request.clone()).map_err(|cause| TestError::Fixture {
            bundle_kind: mode,
            stage: lane,
            operation: "verify_generated_common_credential_root_success",
            cause: Box::new(cause),
        })?;
    match result {
        ZkProviderOperationResult::CommonCredentialRootVerification(report) => {
            let expected_count = u8::try_from(ZkCommonCredentialRootProofSlot::ALL.len())
                .map_err(|_| TestError::Domain(ZkErrorReason::LengthOverflow))?;
            if report.verified_proof_count != expected_count {
                return Err(TestError::UnexpectedResponse);
            }
        }
        _ => return Err(TestError::UnexpectedResponse),
    }
    assert_claim_proof_bundle_verify_failure(
        context,
        tamper_common_credential_root_proof(request.clone())?,
        ZkErrorReason::InvalidProof,
    )
    .map_err(|cause| TestError::Fixture {
        bundle_kind: mode,
        stage: lane,
        operation: "verify_generated_common_credential_root_tampered_proof",
        cause: Box::new(cause),
    })?;
    assert_claim_proof_bundle_verify_failure(
        context,
        tamper_common_credential_root_challenge(request)?,
        ZkErrorReason::BindingMismatch,
    )
    .map_err(|cause| TestError::Fixture {
        bundle_kind: mode,
        stage: lane,
        operation: "verify_generated_common_credential_root_tampered_challenge",
        cause: Box::new(cause),
    })
}

fn generated_common_credential_root_verify_request(
    lane: &'static str,
    mode: &'static str,
    proofs: &[reallyme_zk_proto_codec::common_credential_root::ZkCommonCredentialRootRawProofPackage],
) -> Result<pb::ZkProviderOperationRequest, TestError> {
    if proofs.len() != ZkCommonCredentialRootProofSlot::ALL.len() {
        return Err(TestError::Domain(ZkErrorReason::MissingStage));
    }
    let fixture_root = common_credential_root_fixture_root()?;
    let common_credential_root = fixture_root
        .join(lane)
        .join("families/common_credential_root_v1");
    let attestation = read_toml(common_credential_root.join("root_attestation/Prover.toml"))
        .map_err(|cause| TestError::Fixture {
            bundle_kind: mode,
            stage: lane,
            operation: "read_root_attestation_toml",
            cause: Box::new(cause),
        })?;
    let status =
        read_toml(common_credential_root.join("root_status/Prover.toml")).map_err(|cause| {
            TestError::Fixture {
                bundle_kind: mode,
                stage: lane,
                operation: "read_root_status_toml",
                cause: Box::new(cause),
            }
        })?;
    let claim_root = common_credential_root.join(format!("{mode}_persona_claim"));
    let first_claim =
        read_toml(claim_root.join("Prover.toml")).map_err(|cause| TestError::Fixture {
            bundle_kind: mode,
            stage: lane,
            operation: "read_first_claim_toml",
            cause: Box::new(cause),
        })?;
    let second_claim =
        read_toml(claim_root.join("ProverEmployer.toml")).map_err(|cause| TestError::Fixture {
            bundle_kind: mode,
            stage: lane,
            operation: "read_second_claim_toml",
            cause: Box::new(cause),
        })?;
    let issuer_status_root = common_credential_root.join("issuer_credential_status");
    let first_issuer_status =
        read_toml(issuer_status_root.join("Prover.toml")).map_err(|cause| TestError::Fixture {
            bundle_kind: mode,
            stage: lane,
            operation: "read_first_issuer_status_toml",
            cause: Box::new(cause),
        })?;
    let second_issuer_status =
        read_toml(issuer_status_root.join("ProverEmployer.toml")).map_err(|cause| {
            TestError::Fixture {
                bundle_kind: mode,
                stage: lane,
                operation: "read_second_issuer_status_toml",
                cause: Box::new(cause),
            }
        })?;

    let profile = match mode {
        "private" => pb::ZkCommonCredentialRootPersonaMode::PrivatePersonaV1,
        "public" => pb::ZkCommonCredentialRootPersonaMode::PublicPersonaV1,
        _ => return Err(TestError::UnexpectedResponse),
    };
    let credential_hash_algorithm = match lane {
        "sha256" => pb::ZkCredentialHashAlgorithm::Sha256,
        "poseidon2" => pb::ZkCredentialHashAlgorithm::Poseidon2,
        _ => return Err(TestError::UnexpectedResponse),
    };
    let challenge = toml_bytes(&attestation, "challenge", 32)?;
    let audience_hash = toml_bytes(&attestation, "audience_hash", 32)?;
    let transaction_data_hash = toml_bytes(&attestation, "transaction_data_hash", 32)?;

    let mut presentation_proofs = Vec::new();
    presentation_proofs
        .try_reserve_exact(proofs.len())
        .map_err(|_| TestError::Domain(ZkErrorReason::ResourceExhausted))?;
    for proof in proofs {
        presentation_proofs.push(
            common_credential_root_raw_proof_package_to_proto(proof)
                .map_err(|error| TestError::Domain(error.reason()))?,
        );
    }

    let presentation = pb::ZkCommonCredentialRootPresentation {
        persona_mode: EnumValue::from(profile),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm),
        proof_suite: EnumValue::from(pb::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa),
        session_binding: MessageField::some(common_credential_root_session_binding_proto(
            challenge.clone(),
            audience_hash.clone(),
            &transaction_data_hash,
        )),
        proofs: presentation_proofs,
        __buffa_unknown_fields: Default::default(),
    };
    let policy = pb::ZkCommonCredentialRootJoinPolicy {
        challenge,
        audience_hash,
        transaction_data_hash,
        request_time_unix: toml_u64(&attestation, "request_unix")?,
        status_validation_time_unix: toml_u64(&attestation, "request_unix")?,
        status_validation_max_age_seconds: 120,
        attestation_signer: MessageField::some(pb::ZkP256PublicKey {
            x: toml_bytes(&attestation, "reallyme_x", 32)?,
            y: toml_bytes(&attestation, "reallyme_y", 32)?,
            __buffa_unknown_fields: Default::default(),
        }),
        assurance_policy_id: toml_bytes(&attestation, "assurance_policy_id", 32)?,
        status_root: toml_bytes(&status, "active_status_root", 32)?,
        claims: vec![
            common_credential_root_claim_policy(&first_claim)?,
            common_credential_root_claim_policy(&second_claim)?,
        ],
        issuer_status: vec![
            common_credential_root_issuer_status_policy(&first_issuer_status)?,
            common_credential_root_issuer_status_policy(&second_issuer_status)?,
        ],
        __buffa_unknown_fields: Default::default(),
    };
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::VerifyCommonCredentialRoot(Box::new(
                pb::ZkCommonCredentialRootVerifyOperation {
                    presentation: MessageField::some(presentation),
                    join_policy: MessageField::some(policy),
                    expected_proof_suite: EnumValue::from(
                        pb::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn common_credential_root_issuer_status_policy(
    fixture: &toml::Value,
) -> Result<pb::ZkCommonCredentialRootIssuerStatusExpectation, TestError> {
    let slot = fixture.get("slot").ok_or(TestError::UnexpectedResponse)?;
    let purpose = u32::try_from(toml_u64(slot, "status_purpose")?)
        .map_err(|_| TestError::Domain(ZkErrorReason::LengthOverflow))?;
    Ok(pb::ZkCommonCredentialRootIssuerStatusExpectation {
        root: toml_bytes(slot, "status_root", 32)?,
        length: toml_u64(slot, "status_length")?,
        list_id: toml_bytes(slot, "status_list_id", 32)?,
        url_hash: toml_bytes(slot, "status_url_hash", 32)?,
        purpose: EnumValue::from(match purpose {
            1 => pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION,
            2 => pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_SUSPENSION,
            _ => return Err(TestError::UnexpectedResponse),
        }),
        __buffa_unknown_fields: Default::default(),
    })
}

fn common_credential_root_session_binding_proto(
    nonce_hash: Vec<u8>,
    audience_hash: Vec<u8>,
    transaction_data_hash: &[u8],
) -> pb::ZkSessionBinding {
    let transaction_data_hash = if transaction_data_hash == ABSENT_TRANSACTION_DATA_HASH {
        Vec::new()
    } else {
        transaction_data_hash.to_vec()
    };
    pb::ZkSessionBinding {
        nonce_hash,
        audience_hash,
        transaction_data_hash,
        __buffa_unknown_fields: Default::default(),
    }
}

fn common_credential_root_claim_policy(
    fixture: &TomlValue,
) -> Result<pb::ZkCommonCredentialRootClaimExpectation, TestError> {
    let value_length = toml_u32(fixture, "val_len")?;
    let padded_value = toml_bytes(fixture, "val_pub", 64)?;
    let value_len = usize::try_from(value_length)
        .map_err(|_| TestError::Domain(ZkErrorReason::LengthOverflow))?;
    if value_len > padded_value.len() {
        return Err(TestError::Domain(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(pb::ZkCommonCredentialRootClaimExpectation {
        issuer: MessageField::some(pb::ZkP256PublicKey {
            x: toml_bytes(fixture, "pk_issuer_x", 32)?,
            y: toml_bytes(fixture, "pk_issuer_y", 32)?,
            __buffa_unknown_fields: Default::default(),
        }),
        claim_name_hash: toml_bytes(fixture, "name_hash", 32)?,
        claim_value: padded_value[..value_len].to_vec(),
        claim_value_length: value_length,
        __buffa_unknown_fields: Default::default(),
    })
}

fn read_toml(path: PathBuf) -> Result<TomlValue, TestError> {
    let text = fs::read_to_string(path).map_err(|_| TestError::Io)?;
    toml::from_str::<TomlValue>(&text).map_err(|_| TestError::Decode)
}

fn toml_bytes(fixture: &TomlValue, key: &str, length: usize) -> Result<Vec<u8>, TestError> {
    let values = fixture
        .get(key)
        .and_then(TomlValue::as_array)
        .ok_or(TestError::Decode)?;
    if values.len() != length {
        return Err(TestError::Domain(ZkErrorReason::InvalidProofEncoding));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| TestError::Domain(ZkErrorReason::ResourceExhausted))?;
    for value in values {
        let integer = value.as_integer().ok_or(TestError::Decode)?;
        let byte = u8::try_from(integer)
            .map_err(|_| TestError::Domain(ZkErrorReason::InvalidProofEncoding))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn toml_u64(fixture: &TomlValue, key: &str) -> Result<u64, TestError> {
    let value = fixture
        .get(key)
        .and_then(TomlValue::as_integer)
        .ok_or(TestError::Decode)?;
    u64::try_from(value).map_err(|_| TestError::Domain(ZkErrorReason::InvalidProofEncoding))
}

fn toml_u32(fixture: &TomlValue, key: &str) -> Result<u32, TestError> {
    let value = toml_u64(fixture, key)?;
    u32::try_from(value).map_err(|_| TestError::Domain(ZkErrorReason::InvalidProofEncoding))
}

fn assert_claim_proof_bundle_verify_failure(
    context: &PlatformContextGuard,
    request: pb::ZkProviderOperationRequest,
    expected: ZkErrorReason,
) -> Result<(), TestError> {
    let actual = dispatch_failure_reason(context, request)?;
    if actual == expected {
        Ok(())
    } else {
        Err(TestError::Provider(actual))
    }
}

fn require_consistent_binding(
    slot: &mut Option<ZkSessionBinding>,
    value: ZkSessionBinding,
) -> Result<(), TestError> {
    if let Some(existing) = slot {
        if *existing != value {
            return Err(TestError::Domain(ZkErrorReason::BindingMismatch));
        }
    } else {
        *slot = Some(value);
    }
    Ok(())
}

fn stage_witness(
    context: &PlatformContextGuard,
    paths: &DemoPaths,
    profile: DemoProfile,
    stage: DemoStage,
) -> Result<reallyme_zk_proto_codec::result::ZkStageWitnessReport, TestError> {
    let input = paths.read_fixture(profile, stage)?;
    let result = dispatch_success(context, witness_request(profile, stage, input))?;
    match result {
        ZkProviderOperationResult::StageWitness(report) => Ok(*report),
        _ => Err(TestError::UnexpectedResponse),
    }
}

// Mobile samples compare these public fields before composing a presentation.
// Keep the fixture and independently generated witness paths in lockstep.
fn require_mobile_common_root_public_input_parity(
    lane: &'static str,
    mode: &'static str,
    proofs: &[reallyme_zk_proto_codec::common_credential_root::ZkCommonCredentialRootRawProofPackage],
) -> Result<(), TestError> {
    let request = read_provider_request(
        common_credential_root_mobile_fixture_root()?
            .join(format!("common-credential-root-{lane}-{mode}.pb")),
    )?;
    let Some(pb::zk_provider_operation_request::Operation::VerifyCommonCredentialRoot(operation)) =
        request.operation
    else {
        return Err(TestError::UnexpectedResponse);
    };
    let expected = operation
        .presentation
        .as_option()
        .ok_or(TestError::UnexpectedResponse)?;
    if expected.proofs.len() != proofs.len() {
        return Err(TestError::UnexpectedResponse);
    }
    for (slot, (actual, expected)) in proofs.iter().zip(&expected.proofs).enumerate() {
        if actual.public_inputs().as_bytes() != expected.public_inputs.raw_fields.as_slice() {
            return Err(TestError::CommonCredentialRootStageFixture {
                lane,
                mode,
                slot: u8::try_from(slot)
                    .map_err(|_| TestError::Domain(ZkErrorReason::LengthOverflow))?,
                operation: "generated_public_inputs_match_mobile_fixture",
                cause: Box::new(TestError::UnexpectedResponse),
            });
        }
    }
    Ok(())
}
