// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{env, fs, path::Path};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver,
        ZkClaimProofBundleStage, ZkClaimProofBundleWitness, ZkStatusQualifiedClaimProofBundle,
    },
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_backend_bb::{
    BarretenbergArtifactResolver, BarretenbergBundleProvider,
    BarretenbergCommonCredentialRootArtifactResolver, NativeBarretenbergBackend,
};
use reallyme_zk_noir_witness_core::{
    generate_witness_from_artifact_json_and_toml, CompiledProgramArtifactJson,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    exchange::validate_operation_exchange,
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
    status_qualified::encode_status_qualified_claim_proof_bundle,
};
use zeroize::Zeroizing;

use super::{demo_asset_root, dispatch_operation, fixture_bytes, fixture_u64, read};
use crate::{
    context::{PlatformContext, PlatformCrsMode},
    dispatch::backend_adapter::BorrowedPlatformBackend,
};

const FIXTURE_ROOT_ENV: &str = "REALLYME_ZK_STATUS_QUALIFIED_FIXTURE_ROOT";

enum NativeTestError {
    Setup(ZkError),
    ProofGeneration(ZkError),
    Envelope(ZkError),
    Dispatch(ZkError),
    Verification(ZkError),
}

impl core::fmt::Debug for NativeTestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (stage, error) = match self {
            Self::Setup(error) => ("Setup", error),
            Self::ProofGeneration(error) => ("ProofGeneration", error),
            Self::Envelope(error) => ("Envelope", error),
            Self::Dispatch(error) => ("Dispatch", error),
            Self::Verification(error) => ("Verification", error),
        };
        formatter.debug_tuple(stage).field(error).finish()
    }
}

impl From<ZkError> for NativeTestError {
    fn from(error: ZkError) -> Self {
        Self::Setup(error)
    }
}

/// Direct and private credentials use different trusted issuers. Each negative
/// request keeps its status metadata unchanged while selecting the other issuer,
/// so a feed's issuer binding must survive the protobuf boundary.
#[test]
#[ignore = "requires synthetic direct/private fixtures, pinned mobile artifacts and full prover CRS"]
fn five_real_proofs_cross_status_qualified_dispatch_with_issuer_isolation(
) -> Result<(), NativeTestError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture_root = env::var_os(FIXTURE_ROOT_ENV)
        .map(std::path::PathBuf::from)
        .ok_or(ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let assets = demo_asset_root(&repository);
    let artifact_root = assets.join("artifacts");
    let index = read(&assets.join("release-index.pb"))?;
    let context = PlatformContext::try_new_from_crs_files(
        artifact_root.to_string_lossy().as_bytes(),
        &index,
        Digest32::sha256(&index).as_bytes(),
        assets
            .join("crs/bn254_g1.prover")
            .to_string_lossy()
            .as_bytes(),
        assets.join("crs/bn254_g2").to_string_lossy().as_bytes(),
        PlatformCrsMode::FullProver,
    )?;
    let first = read_values(&fixture_root.join("direct/credential-a/claim/Prover.toml"))?;
    let second = read_values(&fixture_root.join("credential-b/claim/Prover.toml"))?;
    let issuers = [issuer(&first)?, issuer(&second)?];
    assert_ne!(issuers[0], issuers[1]);

    for (kind, credential, session, expected_issuer, other_issuer) in [
        (
            ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            "direct/credential-a",
            "direct/session",
            issuers[0],
            issuers[1],
        ),
        (
            ZkClaimProofBundleKind::PrivatePersonaClaimV1,
            "credential-b",
            "session",
            issuers[1],
            issuers[0],
        ),
    ] {
        let credential_root = fixture_root.join(credential);
        let claim = read_values(&credential_root.join("claim/Prover.toml"))?;
        let status_values =
            read_values(&credential_root.join("issuer_credential_status/Prover.toml"))?;
        let status = status_values
            .get("slot")
            .and_then(toml::Value::as_table)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        let binding = ZkSessionBinding {
            nonce_hash: fixture_bytes(&claim, "challenge")?,
            audience_hash: fixture_bytes(&claim, "audience_hash")?,
            transaction_data_hash: Some(fixture_bytes(&claim, "transaction_data_hash")?),
        };
        let bundle = prove_bundle(
            &context,
            kind,
            &credential_root,
            &fixture_root.join(session),
            binding,
        )
        .map_err(NativeTestError::ProofGeneration)?;
        let encoded = encode_status_qualified_claim_proof_bundle(&bundle)
            .map_err(NativeTestError::Envelope)?;
        let operation = pb::ZkStatusQualifiedClaimProofBundleVerifyOperation {
            status_qualified_claim_proof_bundle: MessageField::some(
                pb::ZkStatusQualifiedClaimProofBundle::decode(&mut encoded.as_slice())
                    .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?,
            ),
            expected_binding: MessageField::some(super::session_binding(
                binding.nonce_hash,
                binding.audience_hash,
                binding.transaction_data_public_input(),
            )),
            expected_issuer: MessageField::some(key(expected_issuer)),
            trusted_issuers: issuers.iter().copied().map(key).collect(),
            verification_time_unix: fixture_u64(status, "verifier_now")?,
            expected_proof_suite: EnumValue::from(
                pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            current_issuer_status: MessageField::some(
                pb::ZkCommonCredentialRootIssuerStatusExpectation {
                    root: fixture_bytes::<32>(status, "status_root")?.to_vec(),
                    length: fixture_u64(status, "status_length")?,
                    list_id: fixture_bytes::<32>(status, "status_list_id")?.to_vec(),
                    url_hash: fixture_bytes::<32>(status, "status_url_hash")?.to_vec(),
                    purpose: EnumValue::from(
                        pb::ZkIssuerStatusPurpose::ZK_ISSUER_STATUS_PURPOSE_REVOCATION,
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            ),
            __buffa_unknown_fields: Default::default(),
        };
        let response = dispatch(&context, operation.clone()).map_err(NativeTestError::Dispatch)?;
        match response {
            ZkProviderOperationOutcome::Success(result) => match *result {
                ZkProviderOperationResult::StatusQualifiedClaimProofBundleVerification(report) => {
                    assert_eq!(report.verified_proof_count, 5);
                    assert_eq!(report.statement.issuer(), expected_issuer);
                }
                _ => {
                    return Err(NativeTestError::Verification(ZkError::new(
                        ZkErrorReason::BackendFailure,
                    )))
                }
            },
            ZkProviderOperationOutcome::Failure(error) => {
                return Err(NativeTestError::Verification(error))
            }
        }
        let mut wrong_issuer = operation.clone();
        wrong_issuer.expected_issuer = MessageField::some(key(other_issuer));
        require_failure(&context, wrong_issuer, ZkErrorReason::BindingMismatch)?;

        let mut tampered = operation.clone();
        let proof = &mut tampered
            .status_qualified_claim_proof_bundle
            .get_or_insert_default()
            .issuer_credential_status
            .get_or_insert_default()
            .proof;
        tamper_middle_scalar(proof)?;
        require_failure(&context, tampered, ZkErrorReason::InvalidProof)?;

        let mut wrong_root = operation;
        let root = &mut wrong_root
            .current_issuer_status
            .get_or_insert_default()
            .root;
        let first = root
            .first_mut()
            .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
        *first ^= 1;
        require_failure(&context, wrong_root, ZkErrorReason::BindingMismatch)?;
    }
    Ok(())
}

fn tamper_middle_scalar(proof: &mut [u8]) -> Result<(), ZkError> {
    // The pinned UltraHonk format places sumcheck scalars in the middle and
    // curve commitments at the tail. Keep scalar encoding canonical: changing
    // a curve coordinate would test decoder exceptions instead of proof rejection.
    const FIELD_BYTES: usize = 32;
    let start = proof
        .len()
        .checked_div(FIELD_BYTES)
        .and_then(|fields| fields.checked_div(2))
        .and_then(|middle| middle.checked_mul(FIELD_BYTES))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let end = start
        .checked_add(FIELD_BYTES)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let field = proof
        .get_mut(start..end)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let was_zero = field.iter().all(|byte| *byte == 0);
    field.fill(0);
    if was_zero {
        *field
            .last_mut()
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))? = 1;
    }
    Ok(())
}

fn prove_bundle(
    context: &PlatformContext,
    kind: ZkClaimProofBundleKind,
    credential: &Path,
    session: &Path,
    binding: ZkSessionBinding,
) -> Result<ZkStatusQualifiedClaimProofBundle, ZkError> {
    let lane = ZkCredentialHashAlgorithm::Sha256;
    let resolver = context.resolver(kind, lane, ZkProofSuite::PRODUCTION)?;
    let mut witnesses = Vec::new();
    for stage in ZkClaimProofBundleStage::ALL {
        let circuit = kind.source_ref(lane, *stage);
        let artifacts =
            resolver.resolve_stage_artifacts(kind, *stage, circuit, ZkProofSuite::PRODUCTION)?;
        let directory = if *stage == ZkClaimProofBundleStage::Session {
            session.to_path_buf()
        } else {
            credential.join(circuit.stage.source_dir())
        };
        witnesses.push(witness(
            circuit,
            artifacts.bytecode().as_bytes(),
            &directory.join("Prover.toml"),
        )?);
    }
    let witnesses = ZkClaimProofBundleWitness::try_from_stage_witnesses(kind, lane, witnesses)?;
    let provider =
        BarretenbergBundleProvider::new(BorrowedPlatformBackend::new(context.backend()), resolver);
    let request = ZkClaimProofBundleProveRequest::try_new(
        kind,
        lane,
        ZkProofSuite::PRODUCTION,
        &witnesses,
        binding,
    )?;
    let bundle = provider.prove_claim_proof_bundle(request)?;

    let circuit = ZkCircuitRef::new(
        lane,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::IssuerCredentialStatus,
    );
    let artifacts = context.resolve_common_credential_root_artifacts(
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
        circuit,
        ZkProofSuite::PRODUCTION,
    )?;
    let witness = witness(
        circuit,
        artifacts.bytecode().as_bytes(),
        &credential.join("issuer_credential_status/Prover.toml"),
    )?;
    let provider = BarretenbergBundleProvider::new(NativeBarretenbergBackend::try_new()?, context);
    let status = provider.prove_issuer_credential_status(lane, &witness, binding)?;
    ZkStatusQualifiedClaimProofBundle::try_from_parts(bundle, status)
}

fn witness(circuit: ZkCircuitRef, bytecode: &[u8], path: &Path) -> Result<ZkWitness, ZkError> {
    let source = Zeroizing::new(
        fs::read_to_string(path).map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?,
    );
    let artifact = CompiledProgramArtifactJson::try_from_bytes(bytecode)
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    let witness = generate_witness_from_artifact_json_and_toml(artifact, source.as_str())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit, witness.into_zeroizing_bytes())
}

fn read_values(path: &Path) -> Result<toml::Table, ZkError> {
    let source = Zeroizing::new(
        fs::read_to_string(path).map_err(|_| ZkError::new(ZkErrorReason::BackendUnavailable))?,
    );
    toml::from_str(source.as_str()).map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))
}

fn issuer(values: &toml::Table) -> Result<ZkIssuerPublicKey, ZkError> {
    Ok(ZkIssuerPublicKey {
        x: fixture_bytes(values, "pk_issuer_x")?,
        y: fixture_bytes(values, "pk_issuer_y")?,
    })
}

fn key(issuer: ZkIssuerPublicKey) -> pb::ZkP256PublicKey {
    pb::ZkP256PublicKey {
        x: issuer.x.to_vec(),
        y: issuer.y.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn dispatch(
    context: &PlatformContext,
    operation: pb::ZkStatusQualifiedClaimProofBundleVerifyOperation,
) -> Result<ZkProviderOperationOutcome, ZkError> {
    let request = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::VerifyStatusQualifiedClaimProofBundle(
                Box::new(operation),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec();
    let response = dispatch_operation(context, &request)?;
    let decoded = decode_operation_response(&response)?;
    if decoded.request_sha256() != Digest32::sha256(&request) {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    let outcome = decoded.into_outcome();
    // An intentionally invalid negative request cannot pass request admission.
    // Successful replies still require the complete request/result join check.
    if matches!(outcome, ZkProviderOperationOutcome::Success(_)) {
        validate_operation_exchange(&request, &response)?;
    }
    Ok(outcome)
}

fn require_failure(
    context: &PlatformContext,
    operation: pb::ZkStatusQualifiedClaimProofBundleVerifyOperation,
    expected: ZkErrorReason,
) -> Result<(), ZkError> {
    match dispatch(context, operation)? {
        ZkProviderOperationOutcome::Failure(error) => {
            assert_eq!(error.reason(), expected);
            Ok(())
        }
        ZkProviderOperationOutcome::Success(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}
