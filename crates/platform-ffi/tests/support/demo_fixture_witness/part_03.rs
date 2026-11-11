// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn dispatch_success(
    context: &PlatformContextGuard,
    request: pb::ZkProviderOperationRequest,
) -> Result<ZkProviderOperationResult, TestError> {
    let request = request.encode_to_vec();
    let result =
        unsafe { reallyme_zk_platform_dispatch(context.as_ptr(), request.as_ptr(), request.len()) };
    if result.status_code != REALLYME_ZK_PLATFORM_STATUS_OK {
        return Err(TestError::DispatchStatus);
    }
    if result.output.ptr.is_null() || result.output.len == 0 {
        return Err(TestError::EmptyResponse);
    }
    let response_bytes =
        unsafe { std::slice::from_raw_parts(result.output.ptr, result.output.len) };
    let outcome = decode_operation_response(response_bytes)
        .map_err(|_| TestError::Decode)?
        .into_outcome();
    let destroy_status = unsafe { reallyme_zk_platform_buffer_destroy(result.output) };
    if destroy_status.status_code != REALLYME_ZK_PLATFORM_STATUS_OK {
        return Err(TestError::BufferDestroy);
    }
    match outcome {
        ZkProviderOperationOutcome::Success(result) => Ok(*result),
        ZkProviderOperationOutcome::Failure(error) => Err(TestError::Provider(error.reason())),
    }
}

fn read_provider_request(path: PathBuf) -> Result<pb::ZkProviderOperationRequest, TestError> {
    let bytes = fs::read(path).map_err(|_| TestError::Io)?;
    DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(bytes.as_slice())
        .map_err(|_| TestError::Decode)
}

fn common_credential_root_mobile_fixture_root() -> Result<PathBuf, TestError> {
    Ok(repo_root()?.join("vectors/common-credential-root-mobile-fixtures-v1"))
}

fn common_credential_root_fixture_root() -> Result<PathBuf, TestError> {
    if let Some(path) = env::var_os(COMMON_CREDENTIAL_ROOT_FIXTURE_ROOT_ENV) {
        return Ok(PathBuf::from(path));
    }
    Ok(repo_root()?.join("circuits"))
}

fn common_credential_root_stage_request_root() -> Result<PathBuf, TestError> {
    if let Some(path) = env::var_os(COMMON_CREDENTIAL_ROOT_STAGE_REQUEST_ROOT_ENV) {
        return Ok(PathBuf::from(path));
    }
    Ok(repo_root()?.join("vectors/common-credential-root-stage-requests-v1"))
}

fn repo_root() -> Result<PathBuf, TestError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(std::path::Path::to_path_buf)
        .ok_or(TestError::Io)
}

fn dispatch_failure_reason(
    context: &PlatformContextGuard,
    request: pb::ZkProviderOperationRequest,
) -> Result<ZkErrorReason, TestError> {
    let request = request.encode_to_vec();
    let result =
        unsafe { reallyme_zk_platform_dispatch(context.as_ptr(), request.as_ptr(), request.len()) };
    if result.status_code != REALLYME_ZK_PLATFORM_STATUS_OK {
        return Err(TestError::DispatchStatus);
    }
    if result.output.ptr.is_null() || result.output.len == 0 {
        return Err(TestError::EmptyResponse);
    }
    let response_bytes =
        unsafe { std::slice::from_raw_parts(result.output.ptr, result.output.len) };
    let outcome = decode_operation_response(response_bytes)
        .map_err(|_| TestError::Decode)?
        .into_outcome();
    let destroy_status = unsafe { reallyme_zk_platform_buffer_destroy(result.output) };
    if destroy_status.status_code != REALLYME_ZK_PLATFORM_STATUS_OK {
        return Err(TestError::BufferDestroy);
    }
    match outcome {
        ZkProviderOperationOutcome::Success(_) => Err(TestError::UnexpectedResponse),
        ZkProviderOperationOutcome::Failure(error) => Ok(error.reason()),
    }
}

fn witness_request(
    profile: DemoProfile,
    stage: DemoStage,
    input: pb::ZkStageWitnessInput,
) -> pb::ZkProviderOperationRequest {
    pb::ZkProviderOperationRequest {
        operation: Some(pb::zk_provider_operation_request::Operation::WitnessStage(
            Box::new(pb::ZkStageWitnessOperation {
                circuit_ref: MessageField::some(circuit_ref(profile, stage)),
                proof_suite: proof_suite(),
                input: MessageField::some(input),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        __buffa_unknown_fields: Default::default(),
    }
}

fn release_request(
    handle: &reallyme_zk_proto_codec::operation::ZkNativeStageWitnessHandle,
) -> pb::ZkProviderOperationRequest {
    pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::ReleaseStageWitness(Box::new(
                pb::ZkStageWitnessReleaseOperation {
                    witness_handle: MessageField::some(witness_handle_to_proto(handle)),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn prove_request(
    witness: &reallyme_zk_proto_codec::result::ZkStageWitnessReport,
) -> pb::ZkProviderOperationRequest {
    pb::ZkProviderOperationRequest {
        operation: Some(pb::zk_provider_operation_request::Operation::ProveStage(
            Box::new(pb::ZkStageProveOperation {
                circuit_ref: MessageField::some(circuit_ref_to_proto(
                    witness.witness_handle.circuit_ref,
                )),
                witness: MessageField::none(),
                public_inputs: MessageField::some(pb::ZkPublicInputs {
                    encoded: witness.public_inputs.as_bytes().to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }),
                session_binding: MessageField::some(session_binding_to_proto(
                    witness.session_binding,
                )),
                proof_suite: proof_suite(),
                witness_handle: MessageField::some(witness_handle_to_proto(
                    &witness.witness_handle,
                )),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        __buffa_unknown_fields: Default::default(),
    }
}

fn prove_retained_claim_proof_bundle_request(
    profile: DemoProfile,
    session_binding: ZkSessionBinding,
    witness_handles: &[reallyme_zk_proto_codec::operation::ZkNativeStageWitnessHandle],
) -> pb::ZkProviderOperationRequest {
    let mut stage_witness_handles = Vec::new();
    stage_witness_handles.reserve_exact(witness_handles.len());
    for handle in witness_handles {
        stage_witness_handles.push(witness_handle_to_proto(handle));
    }
    pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::ProveRetainedClaimProofBundle(Box::new(
                pb::ZkRetainedClaimProofBundleProveOperation {
                    bundle_kind: EnumValue::from(profile.bundle_kind),
                    credential_hash_algorithm: EnumValue::from(
                        pb::ZkCredentialHashAlgorithm::Sha256,
                    ),
                    session_binding: MessageField::some(session_binding_to_proto(session_binding)),
                    witness_bundle: MessageField::some(pb::ZkRetainedClaimProofBundleWitness {
                        bundle_kind: EnumValue::from(profile.bundle_kind),
                        credential_hash_algorithm: EnumValue::from(
                            pb::ZkCredentialHashAlgorithm::Sha256,
                        ),
                        stage_witness_handles,
                        __buffa_unknown_fields: Default::default(),
                    }),
                    proof_suite: proof_suite(),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn verify_request(
    proof: &reallyme_zk_api::proofs::ZkProof,
    session_binding: ZkSessionBinding,
) -> Result<pb::ZkProviderOperationRequest, TestError> {
    let proof = proof_package_to_proto(proof)?;
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(pb::zk_provider_operation_request::Operation::VerifyStage(
            Box::new(pb::ZkStageVerifyOperation {
                proof: MessageField::some(proof),
                expected_binding: MessageField::some(session_binding_to_proto(session_binding)),
                expected_proof_suite: proof_suite(),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn verify_claim_proof_bundle_request(
    profile: DemoProfile,
    bundle: &ZkClaimProofBundle,
    session_binding: ZkSessionBinding,
    trusted_issuer: ZkIssuerPublicKey,
    verification_time_unix: u64,
) -> Result<pb::ZkProviderOperationRequest, TestError> {
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::VerifyClaimProofBundle(Box::new(
                pb::ZkClaimProofBundleVerifyOperation {
                    claim_proof_bundle: MessageField::some(claim_proof_bundle_to_proto(
                        profile, bundle,
                    )?),
                    expected_binding: MessageField::some(session_binding_to_proto(session_binding)),
                    trusted_issuers: vec![issuer_public_key_to_proto(trusted_issuer)],
                    verification_time_unix,
                    credential_status_checked_at_unix: 0,
                    expected_proof_suite: proof_suite(),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn verify_claim_proof_bundle_proto_request(
    claim_proof_bundle: pb::ZkClaimProofBundle,
    session_binding: ZkSessionBinding,
    trusted_issuer: ZkIssuerPublicKey,
    verification_time_unix: u64,
) -> pb::ZkProviderOperationRequest {
    pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::VerifyClaimProofBundle(Box::new(
                pb::ZkClaimProofBundleVerifyOperation {
                    claim_proof_bundle: MessageField::some(claim_proof_bundle),
                    expected_binding: MessageField::some(session_binding_to_proto(session_binding)),
                    trusted_issuers: vec![issuer_public_key_to_proto(trusted_issuer)],
                    verification_time_unix,
                    credential_status_checked_at_unix: 0,
                    expected_proof_suite: proof_suite(),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn claim_proof_bundle_to_proto(
    profile: DemoProfile,
    bundle: &ZkClaimProofBundle,
) -> Result<pb::ZkClaimProofBundle, TestError> {
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(bundle.stage_proofs().len())
        .map_err(|_| TestError::Domain(ZkErrorReason::ResourceExhausted))?;
    for stage_proof in bundle.stage_proofs() {
        stages.push(pb::ZkClaimProofBundleStageProofPackage {
            bundle_kind: EnumValue::from(profile.bundle_kind),
            stage: EnumValue::from(stage_to_proto(stage_proof.stage())),
            proof: MessageField::some(proof_package_to_proto(stage_proof.proof())?),
            __buffa_unknown_fields: Default::default(),
        });
    }
    Ok(pb::ZkClaimProofBundle {
        bundle_kind: EnumValue::from(profile.bundle_kind),
        format_version: 1,
        stages,
        session_binding: MessageField::some(session_binding_to_proto(bundle.session_binding())),
        credential_hash_algorithm: EnumValue::from(pb::ZkCredentialHashAlgorithm::Sha256),
        proof_suite: proof_suite(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn proof_package_to_proto(proof: &ZkProof) -> Result<pb::ZkProofPackage, TestError> {
    let encoded = encode_exact_proof(proof).map_err(|_| TestError::EncodeProof)?;
    DecodeOptions::new()
        .decode_from_slice::<pb::ZkProofPackage>(encoded.as_slice())
        .map_err(|_| TestError::Decode)
}

fn wrong_issuer(issuer: ZkIssuerPublicKey) -> ZkIssuerPublicKey {
    let mut wrong = issuer;
    wrong.x[0] ^= 0xff;
    wrong
}

fn mutate_nonce(mut binding: ZkSessionBinding) -> ZkSessionBinding {
    binding.nonce_hash[0] ^= 0xff;
    binding
}

fn mutate_audience(mut binding: ZkSessionBinding) -> ZkSessionBinding {
    binding.audience_hash[0] ^= 0xff;
    binding
}

fn mutate_transaction_data(mut binding: ZkSessionBinding) -> ZkSessionBinding {
    binding.transaction_data_hash = Some([0xa5; 32]);
    binding
}

fn tampered_claim_proof_bundle(
    mut bundle: pb::ZkClaimProofBundle,
) -> Result<pb::ZkClaimProofBundle, TestError> {
    let stage = bundle
        .stages
        .get_mut(0)
        .ok_or(TestError::Domain(ZkErrorReason::MissingStage))?;
    let proof = stage
        .proof
        .as_option_mut()
        .ok_or(TestError::Domain(ZkErrorReason::InvalidClaimProofBundle))?;
    let byte = proof
        .proof
        .get_mut(0)
        .ok_or(TestError::Domain(ZkErrorReason::InvalidProofEncoding))?;
    *byte ^= 0x01;
    Ok(bundle)
}

fn malformed_claim_proof_bundle(
    mut bundle: pb::ZkClaimProofBundle,
) -> Result<pb::ZkClaimProofBundle, TestError> {
    let stage = bundle
        .stages
        .get_mut(0)
        .ok_or(TestError::Domain(ZkErrorReason::MissingStage))?;
    let proof = stage
        .proof
        .as_option_mut()
        .ok_or(TestError::Domain(ZkErrorReason::InvalidClaimProofBundle))?;
    proof.proof.clear();
    Ok(bundle)
}

fn tamper_common_credential_root_proof(
    mut request: pb::ZkProviderOperationRequest,
) -> Result<pb::ZkProviderOperationRequest, TestError> {
    let operation = request
        .operation
        .as_mut()
        .ok_or(TestError::Domain(ZkErrorReason::MissingOperation))?;
    let pb::zk_provider_operation_request::Operation::VerifyCommonCredentialRoot(verify) =
        operation
    else {
        return Err(TestError::UnexpectedResponse);
    };
    let presentation = verify
        .presentation
        .as_option_mut()
        .ok_or(TestError::Domain(ZkErrorReason::InvalidClaimProofBundle))?;
    let proof = presentation
        .proofs
        .get_mut(0)
        .ok_or(TestError::Domain(ZkErrorReason::MissingStage))?;
    let byte = proof
        .proof
        .get_mut(0)
        .ok_or(TestError::Domain(ZkErrorReason::InvalidProofEncoding))?;
    *byte ^= 0x01;
    Ok(request)
}

fn tamper_common_credential_root_challenge(
    mut request: pb::ZkProviderOperationRequest,
) -> Result<pb::ZkProviderOperationRequest, TestError> {
    let operation = request
        .operation
        .as_mut()
        .ok_or(TestError::Domain(ZkErrorReason::MissingOperation))?;
    let pb::zk_provider_operation_request::Operation::VerifyCommonCredentialRoot(verify) =
        operation
    else {
        return Err(TestError::UnexpectedResponse);
    };
    let policy = verify
        .join_policy
        .as_option_mut()
        .ok_or(TestError::Domain(ZkErrorReason::InvalidClaimProofBundle))?;
    let byte = policy
        .challenge
        .get_mut(0)
        .ok_or(TestError::Domain(ZkErrorReason::BindingMismatch))?;
    *byte ^= 0x01;
    Ok(request)
}

fn circuit_ref(profile: DemoProfile, stage: DemoStage) -> pb::ZkCircuitRef {
    pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(pb::ZkCredentialHashAlgorithm::Sha256),
        family: EnumValue::from(profile.family),
        stage: EnumValue::from(stage.circuit_stage),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    }
}

fn circuit_ref_to_proto(circuit_ref: ZkCircuitRef) -> pb::ZkCircuitRef {
    pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(match circuit_ref.credential_hash_algorithm {
            reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::Poseidon2 => {
                pb::ZkCredentialHashAlgorithm::Poseidon2
            }
            reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::Sha256 => {
                pb::ZkCredentialHashAlgorithm::Sha256
            }
            _ => pb::ZkCredentialHashAlgorithm::Unspecified,
        }),
        family: EnumValue::from(match circuit_ref.family {
            reallyme_zk_api::circuits::ZkCircuitFamily::CredentialSubjectClaimV1 => {
                pb::ZkCircuitFamily::CredentialSubjectClaimV1
            }
            reallyme_zk_api::circuits::ZkCircuitFamily::PrivatePersonaClaimV1 => {
                pb::ZkCircuitFamily::PrivatePersonaClaimV1
            }
            _ => pb::ZkCircuitFamily::Unspecified,
        }),
        stage: EnumValue::from(match circuit_ref.stage {
            reallyme_zk_api::circuits::ZkCircuitStage::Session => pb::ZkCircuitStage::Session,
            reallyme_zk_api::circuits::ZkCircuitStage::CredentialEnvelope => {
                pb::ZkCircuitStage::CredentialEnvelope
            }
            reallyme_zk_api::circuits::ZkCircuitStage::CredentialRoot => pb::ZkCircuitStage::CredentialRoot,
            reallyme_zk_api::circuits::ZkCircuitStage::Claim => pb::ZkCircuitStage::Claim,
            reallyme_zk_api::circuits::ZkCircuitStage::ClaimBundle4 => pb::ZkCircuitStage::ClaimBundle4,
            _ => pb::ZkCircuitStage::Unspecified,
        }),
        circuit_revision: circuit_ref.revision,
        __buffa_unknown_fields: Default::default(),
    }
}

fn witness_handle_to_proto(
    handle: &reallyme_zk_proto_codec::operation::ZkNativeStageWitnessHandle,
) -> pb::ZkStageWitnessHandle {
    pb::ZkStageWitnessHandle {
        native_handle_id: handle.native_handle_id,
        circuit_ref: MessageField::some(circuit_ref_to_proto(handle.circuit_ref)),
        encoding: EnumValue::from(pb::ZkWitnessEncoding::NoirWitnessStackV1),
        __buffa_unknown_fields: Default::default(),
    }
}

fn session_binding_to_proto(binding: ZkSessionBinding) -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding
            .transaction_data_hash
            .map(|hash| hash.to_vec())
            .unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proof_suite() -> EnumValue<pb::ZkProofSuite> {
    EnumValue::from(pb::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa)
}

fn issuer_public_key_to_proto(key: ZkIssuerPublicKey) -> pb::ZkP256PublicKey {
    pb::ZkP256PublicKey {
        x: key.x.to_vec(),
        y: key.y.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

const fn stage_to_proto(stage: ZkClaimProofBundleStage) -> pb::ZkClaimProofBundleStage {
    match stage {
        ZkClaimProofBundleStage::Session => pb::ZkClaimProofBundleStage::Session,
        ZkClaimProofBundleStage::CredentialEnvelope => {
            pb::ZkClaimProofBundleStage::CredentialEnvelope
        }
        ZkClaimProofBundleStage::CredentialRoot => pb::ZkClaimProofBundleStage::CredentialRoot,
        ZkClaimProofBundleStage::Claim => pb::ZkClaimProofBundleStage::Claim,
        _ => pb::ZkClaimProofBundleStage::Unspecified,
    }
}
