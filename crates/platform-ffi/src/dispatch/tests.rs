// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{collections::BTreeMap, env, fs, io::Read, path::PathBuf};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    common_root::ZkCommonCredentialRootProofSlot,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::ZkPersonaCredentialEvidenceSourceStage,
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::exchange::validate_operation_exchange;
use reallyme_zk_proto_codec::release::decode_release_index;
use reallyme_zk_proto_codec::result::{
    decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult,
};

use super::{dispatch_operation, PlatformContext, PlatformCrsMode};

const DEMO_ASSET_ROOT_ENV: &str = "REALLYME_ZK_DEMO_ASSET_ROOT";

mod status_qualified_native;
const DEFAULT_DEMO_ASSET_RELATIVE_ROOT: &str =
    "release-artifacts/modern-v1-bb-6.0.0/ios-demo-resources/zk_demo";

/// Exercise the actual mobile operation boundary with proof bytes generated
/// from the reviewed prepared sources. The fixture table is transient and is
/// supplied only by the linked-proof script after it independently verifies
/// every proof with the pinned Barretenberg command-line tool.
#[test]
#[ignore = "requires generated prepared proofs and staged mobile release assets"]
fn mobile_package_verifies_prepared_proofs_from_exact_candidate() -> Result<(), ZkError> {
    let evidence_path = env::var_os("REALLYME_PREPARED_LINKED_EVIDENCE")
        .ok_or(ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let evidence = fs::read_to_string(evidence_path)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = demo_asset_root(&repository);
    let release_index_bytes = read(&root.join("release-index.pb"))?;
    let release_index = decode_release_index(&release_index_bytes)?;
    let release_index_digest = Digest32::sha256(&release_index_bytes);
    let g2 = read(&root.join("crs/bn254_g2"))?;
    let mut g1_file = fs::File::open(root.join("crs/bn254_g1.prover"))
        .map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let mut g1_prefix = [0_u8; 64];
    g1_file
        .read_exact(&mut g1_prefix)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let artifact_root = root.join("artifacts");
    let path = artifact_root.to_string_lossy();
    let context = PlatformContext::try_new(
        path.as_bytes(),
        &release_index_bytes,
        release_index_digest.as_bytes(),
        &g1_prefix,
        &g2,
        PlatformCrsMode::VerifierOnly,
    )?;
    let mut verified_count = 0_usize;
    let mut groups: BTreeMap<
        (&str, &str),
        BTreeMap<&str, pb::ZkPersonaCredentialEvidenceStageProof>,
    > = BTreeMap::new();
    for row in evidence.lines() {
        let fields: Vec<&str> = row.split('\t').collect();
        let [lane, profile_name, stage_name, _, _, proof_path, public_inputs_path, _] =
            fields.as_slice()
        else {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        };
        let credential_hash_algorithm = match *lane {
            "sha256" => ZkCredentialHashAlgorithm::Sha256,
            "poseidon2" => ZkCredentialHashAlgorithm::Poseidon2,
            _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        };
        let mode = match *profile_name {
            "public" => pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1,
            "private" => {
                pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
            }
            _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        };
        let (stage, slot) = match *stage_name {
            "issuer_envelope" => (
                ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
                pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_ISSUER_ENVELOPE,
            ),
            "claim_root" => (
                ZkPersonaCredentialEvidenceSourceStage::ClaimRoot,
                pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CLAIM_ROOT,
            ),
            "signed_validity" => (
                ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
                pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SIGNED_VALIDITY,
            ),
            "public_claim" if *profile_name == "public" => (
                ZkPersonaCredentialEvidenceSourceStage::PublicClaim,
                pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
            ),
            "private_claim" if *profile_name == "private" => (
                ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
                pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_SELECTED_CLAIM,
            ),
            "current_state" => (
                ZkPersonaCredentialEvidenceSourceStage::CurrentState,
                pb::ZkPersonaCredentialEvidenceProofSlot::ZK_PERSONA_CREDENTIAL_EVIDENCE_PROOF_SLOT_CURRENT_STATE,
            ),
            _ => return Err(ZkError::new(ZkErrorReason::StageMismatch)),
        };
        let circuit_ref = stage.source_ref(credential_hash_algorithm);
        let pin = release_index
            .persona_credential_evidence_artifacts()
            .iter()
            .find(|pin| pin.circuit_ref() == circuit_ref)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let proof = read(&PathBuf::from(proof_path))?;
        let public_inputs = read(&PathBuf::from(public_inputs_path))?;
        let package = pb::ZkPersonaCredentialEvidenceStageProof {
            mode: EnumValue::from(mode),
            proof_slot: EnumValue::from(slot),
            circuit_ref: MessageField::some(prepared_circuit_ref_to_proto(circuit_ref)?),
            proof,
            public_inputs: MessageField::some(pb::ZkPersonaCredentialEvidenceRawPublicInputs {
                mode: EnumValue::from(mode),
                proof_slot: EnumValue::from(slot),
                circuit_ref: MessageField::some(prepared_circuit_ref_to_proto(circuit_ref)?),
                raw_fields: public_inputs,
                __buffa_unknown_fields: Default::default(),
            }),
            artifact_set_identity_sha256: MessageField::some(pb::ZkArtifactSetIdentity {
                value: pin.artifact_identity_sha256().as_bytes().to_vec(),
                __buffa_unknown_fields: Default::default(),
            }),
            proof_suite: EnumValue::from(
                pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            __buffa_unknown_fields: Default::default(),
        };
        let request = prepared_verify_request(package.clone());
        let response = dispatch_operation(&context, &request)?;
        validate_operation_exchange(&request, response.as_slice())?;
        let outcome = decode_operation_response(response.as_slice())?.into_outcome();
        assert!(matches!(
            outcome,
            ZkProviderOperationOutcome::Success(result)
                if matches!(*result, ZkProviderOperationResult::PersonaCredentialEvidenceStageVerification(_))
        ));
        let mut altered = package.clone();
        let first = altered
            .proof
            .first_mut()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        *first ^= 1;
        let response = dispatch_operation(&context, &prepared_verify_request(altered))?;
        assert!(matches!(
            decode_operation_response(response.as_slice())?.into_outcome(),
            ZkProviderOperationOutcome::Failure(_)
        ));
        let mut altered = package.clone();
        let nested = altered
            .public_inputs
            .as_option_mut()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        let last = nested
            .raw_fields
            .last_mut()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        *last ^= 1;
        let response = dispatch_operation(&context, &prepared_verify_request(altered))?;
        assert!(matches!(
            decode_operation_response(response.as_slice())?.into_outcome(),
            ZkProviderOperationOutcome::Failure(_)
        ));
        groups
            .entry((lane, profile_name))
            .or_default()
            .insert(stage_name, package);
        verified_count = verified_count
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    assert_eq!(verified_count, 20);
    assert_eq!(groups.len(), 4);
    for ((_, profile_name), mut stages) in groups {
        let take = |stages: &mut BTreeMap<&str, pb::ZkPersonaCredentialEvidenceStageProof>, key| {
            stages
                .remove(key)
                .ok_or(ZkError::new(ZkErrorReason::MissingStage))
        };
        let issuer = take(&mut stages, "issuer_envelope")?;
        let root = take(&mut stages, "claim_root")?;
        let validity = take(&mut stages, "signed_validity")?;
        let claim = take(
            &mut stages,
            if profile_name == "public" {
                "public_claim"
            } else {
                "private_claim"
            },
        )?;
        let status = take(&mut stages, "current_state")?;
        assert!(stages.is_empty());
        verify_prepared_signing_mobile_boundary(
            &context,
            pb::ZkPersonaCredentialEvidenceProofSet {
                issuer_envelope: MessageField::some(issuer),
                claim_root: MessageField::some(root),
                signed_validity: MessageField::some(validity),
                selected_claim: MessageField::some(claim),
                ..Default::default()
            },
            status,
            profile_name,
        )?;
    }
    Ok(())
}

fn verify_prepared_signing_mobile_boundary(
    context: &PlatformContext,
    evidence: pb::ZkPersonaCredentialEvidenceProofSet,
    status: pb::ZkPersonaCredentialEvidenceStageProof,
    profile_name: &str,
) -> Result<(), ZkError> {
    const NOW_UNIX: u64 = 1_800_000_001;
    let mut request = pb::ZkPersonaCredentialEvidenceVerifierRequestV1::default();
    request.protocol = EnumValue::from(
        pb::ZkPersonaCredentialEvidenceRequestProtocol::ZK_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_PROTOCOL_REALLYME_DIRECT_V1,
    );
    request.response_mode =
        EnumValue::from(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT);
    request.nonce = vec![1_u8; 32];
    request.audience_sha256 = vec![2_u8; 32];
    request.transaction_data_sha256 = vec![3_u8; 32];
    request.requested_claims_sha256 = vec![4_u8; 32];
    request.verifier_policy_sha256 = vec![5_u8; 32];
    request.transport_context_sha256 = vec![6_u8; 32];
    request.issued_at_unix = NOW_UNIX - 1;
    request.expires_at_unix = NOW_UNIX + 60;
    let signing_request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::PreparePersonaCredentialEvidencePresentationSigning(Box::new(
                pb::ZkPersonaCredentialEvidencePresentationSigningOperation {
                    evidence_proof_set: MessageField::some(evidence.clone()),
                    current_state: MessageField::some(status.clone()),
                    verifier_request: MessageField::some(request.clone()),
                    now_unix: NOW_UNIX,
                    ..Default::default()
                },
            )),
        ),
        ..Default::default()
    }
    .encode_to_vec();
    let signing_response = dispatch_operation(context, &signing_request)?;
    validate_operation_exchange(&signing_request, &signing_response)?;
    let digest = match decode_operation_response(&signing_response)?.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            ZkProviderOperationResult::PersonaCredentialEvidencePresentationSigningChallenge(
                digest,
            ) => digest,
            _ => return Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(error) => return Err(error),
    };
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    secret[31] = if profile_name == "public" { 17 } else { 19 };
    let digest = crypto_p256::P256Sha256Digest::new(*digest);
    let signature_der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let signature = crypto_p256::p256_ecdsa_der_to_jose_signature(&signature_der)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    let assembly_request =
        |request: pb::ZkPersonaCredentialEvidenceVerifierRequestV1,
         current_state: pb::ZkPersonaCredentialEvidenceStageProof| {
            let mut operation =
                pb::ZkPersonaCredentialEvidencePresentationAssembleOperation::default();
            operation.evidence_proof_set = MessageField::some(evidence.clone());
            operation.current_state = MessageField::some(current_state);
            operation.verifier_request = MessageField::some(request);
            operation.now_unix = NOW_UNIX;
            operation.holder_signature_p256_raw = signature.to_vec();
            pb::ZkProviderOperationRequest {
                operation: Some(
                    pb::zk_provider_operation_request::Operation::AssemblePersonaCredentialEvidencePresentation(
                        Box::new(operation),
                    ),
                ),
                ..Default::default()
            }
            .encode_to_vec()
        };
    let canonical = assembly_request(request.clone(), status.clone());
    let assembled = dispatch_operation(context, &canonical)?;
    validate_operation_exchange(&canonical, &assembled)?;
    assert!(matches!(
        decode_operation_response(&assembled)?.into_outcome(),
        ZkProviderOperationOutcome::Success(result)
            if matches!(*result, ZkProviderOperationResult::PersonaCredentialEvidencePresentation(_))
    ));
    let mut changed_request = request.clone();
    changed_request.nonce[0] ^= 1;
    let changed = assembly_request(changed_request, status.clone());
    let rejected = dispatch_operation(context, &changed)?;
    assert!(matches!(
        decode_operation_response(&rejected)?.into_outcome(),
        ZkProviderOperationOutcome::Failure(_)
    ));
    let mut changed_status = status;
    let first = changed_status
        .proof
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    *first ^= 1;
    let changed = assembly_request(request, changed_status);
    let rejected = dispatch_operation(context, &changed)?;
    assert!(matches!(
        decode_operation_response(&rejected)?.into_outcome(),
        ZkProviderOperationOutcome::Failure(_)
    ));
    Ok(())
}

fn prepared_verify_request(package: pb::ZkPersonaCredentialEvidenceStageProof) -> Vec<u8> {
    pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::VerifyPersonaCredentialEvidenceStage(
                Box::new(pb::ZkPersonaCredentialEvidenceStageVerifyOperation {
                    proof: MessageField::some(package),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec()
}

fn prepared_circuit_ref_to_proto(circuit_ref: ZkCircuitRef) -> Result<pb::ZkCircuitRef, ZkError> {
    let credential_hash_algorithm = match circuit_ref.credential_hash_algorithm {
        ZkCredentialHashAlgorithm::Sha256 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        }
        _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    };
    let stage = match circuit_ref.stage {
        reallyme_zk_api::circuits::ZkCircuitStage::EvidenceIssuerEnvelope => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE
        }
        reallyme_zk_api::circuits::ZkCircuitStage::EvidenceClaimRoot => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT
        }
        reallyme_zk_api::circuits::ZkCircuitStage::EvidenceSignedValidity => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY
        }
        reallyme_zk_api::circuits::ZkCircuitStage::EvidencePublicClaim => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM
        }
        reallyme_zk_api::circuits::ZkCircuitStage::EvidencePrivateClaim => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM
        }
        reallyme_zk_api::circuits::ZkCircuitStage::EvidenceCurrentState => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE
        }
        _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    };
    Ok(pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm),
        family: EnumValue::from(
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1,
        ),
        stage: EnumValue::from(stage),
        circuit_revision: circuit_ref.revision,
        __buffa_unknown_fields: Default::default(),
    })
}

/// Requires the pinned local BB library, generated candidate proof outputs,
/// and staged mobile release assets. Run explicitly after the source tests.
#[test]
#[ignore = "requires generated common-credential-root candidate fixtures and staged mobile assets"]
fn mobile_package_verifies_both_hashes_and_persona_modes() -> Result<(), ZkError> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = demo_asset_root(&repository);
    let artifact_root = root.join("artifacts");
    let release_index = read(&root.join("release-index.pb"))?;
    let release_index_digest = Digest32::sha256(&release_index);
    let g2 = read(&root.join("crs/bn254_g2"))?;
    let mut g1_file = fs::File::open(root.join("crs/bn254_g1.prover"))
        .map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let mut g1_prefix = [0_u8; 64];
    g1_file
        .read_exact(&mut g1_prefix)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let path = artifact_root.to_string_lossy();
    let context = PlatformContext::try_new(
        path.as_bytes(),
        &release_index,
        release_index_digest.as_bytes(),
        &g1_prefix,
        &g2,
        PlatformCrsMode::VerifierOnly,
    )?;
    for lane in ["sha256", "poseidon2"] {
        for mode in ["private", "public"] {
            let fixture = repository.join(format!(
                "vectors/common-credential-root-mobile-fixtures-v1/common-credential-root-{lane}-{mode}.pb"
            ));
            let request = read(&fixture)?;
            let response = dispatch_operation(&context, &request)?;
            let outcome = decode_operation_response(response.as_slice())?.into_outcome();
            match outcome {
                ZkProviderOperationOutcome::Failure(error) => return Err(error),
                ZkProviderOperationOutcome::Success(result) => {
                    assert!(matches!(
                        *result,
                        ZkProviderOperationResult::CommonCredentialRootVerification(report)
                            if report.verified_proof_count == 9
                    ));
                }
            }

            // Tamper both new issuer-status proofs as well as the first stage.
            // A stale verifier that silently ignores appended slots must fail.
            for tampered_slot in [0_usize, 7, 8] {
                let mut tampered = pb::ZkProviderOperationRequest::decode(&mut request.as_slice())
                    .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
                if let Some(
                    pb::zk_provider_operation_request::Operation::VerifyCommonCredentialRoot(
                        operation,
                    ),
                ) = tampered.operation.as_mut()
                {
                    let mut presentation = operation
                        .presentation
                        .take()
                        .ok_or(ZkError::new(ZkErrorReason::InvalidClaimProofBundle))?;
                    let proof = presentation
                        .proofs
                        .get_mut(tampered_slot)
                        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
                    let byte = proof
                        .proof
                        .first_mut()
                        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
                    *byte ^= 1;
                    operation.presentation = buffa::MessageField::some(presentation);
                } else {
                    return Err(ZkError::new(ZkErrorReason::MissingOperation));
                }
                let tampered_request = tampered.encode_to_vec();
                let response = dispatch_operation(&context, &tampered_request)?;
                let outcome = decode_operation_response(response.as_slice())?.into_outcome();
                assert!(matches!(outcome, ZkProviderOperationOutcome::Failure(_)));
            }
        }
    }
    Ok(())
}

/// Uses the synthetic source fixture through the same protobuf and linked
/// provider path that the mobile facades call. The provider verifies its own
/// output before returning it, then the test checks the typed response.
#[test]
#[ignore = "requires pinned full CRS and staged common-credential-root mobile artifacts"]
fn mobile_package_proves_common_credential_root_attestation_from_typed_input() -> Result<(), ZkError>
{
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = demo_asset_root(&repository);
    let artifact_root = root.join("artifacts");
    let release_index = read(&root.join("release-index.pb"))?;
    let release_index_digest = Digest32::sha256(&release_index);
    let g1 = root.join("crs/bn254_g1.prover");
    let g2 = root.join("crs/bn254_g2");
    let artifact_root_bytes = artifact_root.to_string_lossy();
    let g1_bytes = g1.to_string_lossy();
    let g2_bytes = g2.to_string_lossy();
    let context = PlatformContext::try_new_from_crs_files(
        artifact_root_bytes.as_bytes(),
        &release_index,
        release_index_digest.as_bytes(),
        g1_bytes.as_bytes(),
        g2_bytes.as_bytes(),
        PlatformCrsMode::FullProver,
    )?;
    let fixture_path = repository
        .join("circuits/sha256/families/common_credential_root_v1/root_attestation/Prover.toml");
    let fixture = fs::read_to_string(fixture_path)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let values: toml::Table =
        toml::from_str(&fixture).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let array32 = |name| fixture_bytes::<32>(&values, name);
    let array64 = |name| fixture_bytes::<64>(&values, name);
    let challenge = array32("challenge")?;
    let audience = array32("audience_hash")?;
    let transaction = array32("transaction_data_hash")?;
    let input = pb::ZkCommonCredentialRootAttestationInput {
        presentation: MessageField::some(pb::ZkInputPresentationContext {
            challenge: MessageField::some(input_bytes32(challenge)),
            audience_hash: MessageField::some(input_bytes32(audience)),
            transaction_data_hash: MessageField::some(input_bytes32(transaction)),
            expiry_unix: fixture_u64(&values, "presentation_expiry_unix")?,
            ..Default::default()
        }),
        reallyme_public_key: MessageField::some(pb::ZkInputP256PublicKey {
            x: MessageField::some(input_bytes32(array32("reallyme_x")?)),
            y: MessageField::some(input_bytes32(array32("reallyme_y")?)),
            ..Default::default()
        }),
        assurance_policy_id: MessageField::some(input_bytes32(array32("assurance_policy_id")?)),
        request_unix: fixture_u64(&values, "request_unix")?,
        root_join: MessageField::some(input_bytes32(array32("root_join")?)),
        attestation_join: MessageField::some(input_bytes32(array32("attestation_join")?)),
        root: MessageField::some(input_bytes32(array32("root")?)),
        attestation_issued_unix: fixture_u64(&values, "attestation_issued_unix")?,
        attestation_expires_unix: fixture_u64(&values, "attestation_expires_unix")?,
        attestation_epoch: fixture_u32(&values, "attestation_epoch")?,
        attestation_signature: MessageField::some(input_bytes64(array64("attestation_signature")?)),
        join_salt: MessageField::some(input_bytes32(array32("join_salt")?)),
        ..Default::default()
    };
    let request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(Box::new(
                pb::ZkCommonCredentialRootStageProveOperation {
                    persona_mode: EnumValue::from(
                        pb::ZkCommonCredentialRootPersonaMode::ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_PRIVATE_PERSONA_V1,
                    ),
                    slot: EnumValue::from(
                        pb::ZkCommonCredentialRootProofSlot::ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_ROOT_ATTESTATION,
                    ),
                    circuit_ref: MessageField::some(pb::ZkCircuitRef {
                        credential_hash_algorithm: EnumValue::from(pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256),
                        family: EnumValue::from(
                            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_COMMON_CREDENTIAL_ROOT_V1,
                        ),
                        stage: EnumValue::from(
                            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_ROOT_ATTESTATION,
                        ),
                        circuit_revision: 1,
                        ..Default::default()
                    }),
                    proof_suite: EnumValue::from(
                        pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                    ),
                    expected_binding: MessageField::some(session_binding(
                        challenge,
                        audience,
                        transaction,
                    )),
                    input: Some(input.into()),
                    ..Default::default()
                },
            )),
        ),
        ..Default::default()
    }
    .encode_to_vec();
    let decoded = reallyme_zk_proto_codec::operation::decode_operation_request(request.as_slice())?;
    assert!(matches!(
        decoded,
        reallyme_zk_proto_codec::operation::ZkProviderOperation::ProveCommonCredentialRootStage { .. }
    ));
    let response = dispatch_operation(&context, request.as_slice())?;
    let outcome = decode_operation_response(response.as_slice())?.into_outcome();
    assert!(matches!(
        outcome,
        ZkProviderOperationOutcome::Success(result)
            if matches!(*result, ZkProviderOperationResult::CommonCredentialRootStageProof(_))
    ));
    Ok(())
}

/// Exercises all source-stage witnesses and linked proofs in the exact mobile
/// artifact package. Each response has already been cryptographically checked
/// by the native backend before it reaches the protobuf boundary.
#[test]
#[ignore = "requires generated synthetic stage requests, pinned full CRS, and mobile artifacts"]
fn mobile_package_proves_every_common_credential_root_stage() -> Result<(), ZkError> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = demo_asset_root(&repository);
    let artifact_root = root.join("artifacts");
    let release_index = read(&root.join("release-index.pb"))?;
    let release_index_digest = Digest32::sha256(&release_index);
    let g1 = root.join("crs/bn254_g1.prover");
    let g2 = root.join("crs/bn254_g2");
    let artifact_root_bytes = artifact_root.to_string_lossy();
    let g1_bytes = g1.to_string_lossy();
    let g2_bytes = g2.to_string_lossy();
    let context = PlatformContext::try_new_from_crs_files(
        artifact_root_bytes.as_bytes(),
        &release_index,
        release_index_digest.as_bytes(),
        g1_bytes.as_bytes(),
        g2_bytes.as_bytes(),
        PlatformCrsMode::FullProver,
    )?;
    for lane in ["sha256", "poseidon2"] {
        for mode in ["private", "public"] {
            let stage_count = u8::try_from(ZkCommonCredentialRootProofSlot::ALL.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
            for slot in 0..stage_count {
                let request = read(&repository.join(format!(
                    "vectors/common-credential-root-stage-requests-v1/{lane}-{mode}-{slot}.pb"
                )))?;
                let _decoded = reallyme_zk_proto_codec::operation::decode_operation_request(
                    request.as_slice(),
                )?;
                let response = dispatch_operation(&context, request.as_slice())?;
                match decode_operation_response(response.as_slice())?.into_outcome() {
                    ZkProviderOperationOutcome::Success(result)
                        if matches!(
                            *result,
                            ZkProviderOperationResult::CommonCredentialRootStageProof(_)
                        ) => {}
                    ZkProviderOperationOutcome::Success(_) => {
                        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
                    }
                    ZkProviderOperationOutcome::Failure(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

fn input_bytes32(value: [u8; 32]) -> pb::ZkInputBytes32 {
    let mut message = pb::ZkInputBytes32::default();
    message.value = value.to_vec();
    message
}

fn input_bytes64(value: [u8; 64]) -> pb::ZkInputBytes64 {
    let mut message = pb::ZkInputBytes64::default();
    message.value = value.to_vec();
    message
}

fn session_binding(
    nonce_hash: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
) -> pb::ZkSessionBinding {
    let mut binding = pb::ZkSessionBinding::default();
    binding.nonce_hash = nonce_hash.to_vec();
    binding.audience_hash = audience_hash.to_vec();
    binding.transaction_data_hash = transaction_data_hash.to_vec();
    binding
}

fn fixture_bytes<const N: usize>(values: &toml::Table, name: &str) -> Result<[u8; N], ZkError> {
    let source = values
        .get(name)
        .and_then(toml::Value::as_array)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let mut bytes = [0_u8; N];
    if source.len() != N {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    for (destination, item) in bytes.iter_mut().zip(source) {
        let value = item
            .as_integer()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        *destination =
            u8::try_from(value).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    }
    Ok(bytes)
}

fn fixture_u64(values: &toml::Table, name: &str) -> Result<u64, ZkError> {
    let value = values
        .get(name)
        .and_then(toml::Value::as_integer)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    u64::try_from(value).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

fn fixture_u32(values: &toml::Table, name: &str) -> Result<u32, ZkError> {
    let value = fixture_u64(values, name)?;
    u32::try_from(value).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

fn read(path: &std::path::Path) -> Result<Vec<u8>, ZkError> {
    fs::read(path).map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))
}

fn demo_asset_root(repository: &std::path::Path) -> PathBuf {
    match env::var_os(DEMO_ASSET_ROOT_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => repository.join(DEFAULT_DEMO_ASSET_RELATIVE_ROOT),
    }
}
