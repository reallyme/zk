// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{
        ZkCircuitFamily as DomainFamily, ZkCircuitRef as DomainRef, ZkCircuitStage as DomainStage,
        ZkCredentialHashAlgorithm,
    },
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkClaimProofBundleWitness},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkSessionBinding, ZkWitness,
    },
};
use reallyme_zk_artifact_package::{
    quarantine_incomplete_artifact_package, ArtifactPackage, ArtifactPackageCoordinates,
    ArtifactPackageError, ArtifactPackageErrorReason, ArtifactPackageInput,
    ArtifactPackageMaterial, ArtifactSourceFile, ArtifactVectorFile, CanonicalBundleVectorFile,
    SealedArtifactPackage, INCOMPLETE_ARTIFACT_PACKAGE_QUARANTINE_DIRECTORY, MAX_VECTOR_FILE_BYTES,
};
use reallyme_zk_artifacts::{ArtifactToolchain, Digest32};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::capability_registry::build_capability_registry;
use reallyme_zk_proto_codec::release::ReleaseArtifactPin;
use reallyme_zk_proto_codec::vector::{BundleProvingVectorInput, StageProvingVectorInput};

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const PROGRAM: &[u8] = br#"{"bytecode":"AA=="}"#;
const VERIFICATION_KEY: &[u8] = b"bounded-verification-key";

fn domain_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [11; 32],
        audience_hash: [22; 32],
        transaction_data_hash: None,
    }
}

fn domain_public_inputs(
    circuit_ref: DomainRef,
) -> Result<reallyme_zk_api::proofs::ZkPublicInputs, ZkError> {
    let binding = domain_binding();
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut encoded = vec![0_u8; descriptor.encoded_len()?];
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&binding.nonce_hash);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&binding.audience_hash);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&binding.transaction_data_public_input());
    reallyme_zk_api::proofs::ZkPublicInputs::try_from_bytes(encoded)
}

fn valid_vector_bytes() -> Result<Vec<u8>, ArtifactPackageError> {
    let domain_ref = DomainRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        DomainFamily::CredentialSubjectClaimV1,
        DomainStage::Session,
    );
    let descriptor = ZkPublicInputDescriptor::for_circuit(domain_ref)?;
    let binding = domain_binding();
    let mut encoded_inputs = vec![0_u8; descriptor.encoded_len()?];
    encoded_inputs
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&binding.nonce_hash);
    encoded_inputs
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&binding.audience_hash);
    encoded_inputs
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&binding.transaction_data_public_input());
    let proto_ref = || pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        family: EnumValue::from(pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
        stage: EnumValue::from(pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    };
    let proto_binding = || pb::ZkSessionBinding {
        nonce_hash: vec![11; 32],
        audience_hash: vec![22; 32],
        transaction_data_hash: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let proto_inputs = || pb::ZkPublicInputs {
        encoded: encoded_inputs.clone(),
        __buffa_unknown_fields: Default::default(),
    };
    let operation = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::ProveStage(Box::new(
                pb::ZkStageProveOperation {
                    circuit_ref: MessageField::some(proto_ref()),
                    witness: MessageField::some(pb::ZkWitness {
                        encoded: vec![1, 2, 3],
                        circuit_ref: MessageField::some(proto_ref()),
                        encoding: EnumValue::from(
                            pb::ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1,
                        ),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    witness_handle: MessageField::none(),
                    public_inputs: MessageField::some(proto_inputs()),
                    session_binding: MessageField::some(proto_binding()),
                    proof_suite: EnumValue::from(
                        pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let expected = pb::ZkExpectedStageProofShape {
        bundle_kind: EnumValue::from(
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        stage: EnumValue::from(pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION),
        metadata: MessageField::some(pb::ZkProofMetadata {
            circuit_id: EnumValue::from(pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
            circuit_id_string: "rm-zk-credential-subject-claim-v1".to_owned(),
            verification_key_sha256: vec![9; 32],
            circuit_ref: MessageField::some(proto_ref()),
            proof_suite: EnumValue::from(
                pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            __buffa_unknown_fields: Default::default(),
        }),
        public_inputs: MessageField::some(proto_inputs()),
        session_binding: MessageField::some(proto_binding()),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(pb::ZkProvingVectorSet {
        format_version: 1,
        bundle_kind: EnumValue::from(
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        credential_hash_algorithm: EnumValue::from(
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        vectors: vec![pb::ZkProvingVector {
            vector_number: 1,
            mutation: EnumValue::from(pb::ZkProvingVectorMutation::ZK_PROVING_VECTOR_MUTATION_NONE),
            base_operation: MessageField::some(operation),
            expected_outcome: Some(
                pb::__buffa::oneof::zk_proving_vector::ExpectedOutcome::StageProof(Box::new(
                    expected,
                )),
            ),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec())
}

fn build_package_with_vector_path(
    vector_path: &Path,
) -> Result<ArtifactPackage, ArtifactPackageError> {
    build_package_with_vector_path_and_hash(vector_path, ZkCredentialHashAlgorithm::Sha256)
}

fn build_package_with_vector_path_and_hash(
    vector_path: &Path,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ArtifactPackage, ArtifactPackageError> {
    let sources = [
        ArtifactSourceFile::try_new(Path::new("Nargo.toml"), b"[package]\nname='circuit'\n")?,
        ArtifactSourceFile::try_new(Path::new("src/main.nr"), b"fn main() {}\n")?,
    ];
    let vector_bytes = valid_vector_bytes()?;
    let vectors = [ArtifactVectorFile::try_new(vector_path, &vector_bytes)?];
    let capability_registry = build_capability_registry()?;
    let material = ArtifactPackageMaterial::try_new(
        &sources,
        PROGRAM,
        VERIFICATION_KEY,
        &capability_registry,
        &vectors,
    )?;
    let toolchain = ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?;
    let coordinates = ArtifactPackageCoordinates::new(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        credential_hash_algorithm,
        toolchain,
    );
    ArtifactPackage::build(ArtifactPackageInput::new(coordinates, material))
}

#[test]
fn package_rejects_vector_from_another_hash_lane() -> Result<(), ArtifactPackageError> {
    let error = build_package_with_vector_path_and_hash(
        Path::new("positive/session.pb"),
        ZkCredentialHashAlgorithm::Poseidon2,
    )
    .err()
    .ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))?;

    assert_eq!(error.reason(), ArtifactPackageErrorReason::PackageMismatch);
    Ok(())
}

#[test]
fn canonical_real_bundle_vector_enters_package_through_zeroizing_owner(
) -> Result<(), ArtifactPackageError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let session_ref =
        bundle_kind.source_ref(credential_hash_algorithm, ZkClaimProofBundleStage::Session);
    let envelope_ref = bundle_kind.source_ref(
        credential_hash_algorithm,
        ZkClaimProofBundleStage::CredentialEnvelope,
    );
    let root_ref = bundle_kind.source_ref(
        credential_hash_algorithm,
        ZkClaimProofBundleStage::CredentialRoot,
    );
    let claim_ref =
        bundle_kind.source_ref(credential_hash_algorithm, ZkClaimProofBundleStage::Claim);
    let session_inputs = domain_public_inputs(session_ref)?;
    let envelope_inputs = domain_public_inputs(envelope_ref)?;
    let root_inputs = domain_public_inputs(root_ref)?;
    let claim_inputs = domain_public_inputs(claim_ref)?;
    let witness_bundle = ZkClaimProofBundleWitness::try_from_stage_witnesses(
        bundle_kind,
        credential_hash_algorithm,
        vec![
            ZkWitness::try_from_noir_witness_stack_v1(session_ref, vec![1, 2, 3])?,
            ZkWitness::try_from_noir_witness_stack_v1(envelope_ref, vec![4, 5, 6])?,
            ZkWitness::try_from_noir_witness_stack_v1(root_ref, vec![7, 8, 9])?,
            ZkWitness::try_from_noir_witness_stack_v1(claim_ref, vec![10, 11, 12])?,
        ],
    )?;
    let stages = [
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkClaimProofBundleStage::Session,
            [41; 32],
            &session_inputs,
            domain_binding(),
        )?,
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkClaimProofBundleStage::CredentialEnvelope,
            [42; 32],
            &envelope_inputs,
            domain_binding(),
        )?,
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkClaimProofBundleStage::CredentialRoot,
            [43; 32],
            &root_inputs,
            domain_binding(),
        )?,
        StageProvingVectorInput::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkClaimProofBundleStage::Claim,
            [44; 32],
            &claim_inputs,
            domain_binding(),
        )?,
    ];
    let proof_suite = ZkProofSuite::PRODUCTION;
    let vector_input = BundleProvingVectorInput::try_new_for_suite(
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        &witness_bundle,
        domain_binding(),
        stages,
    )?;
    let vector_owner =
        CanonicalBundleVectorFile::try_from_input(Path::new("positive/bundle.pb"), vector_input)?;
    let vectors = [vector_owner.as_artifact_vector_file()?];
    let sources = [
        ArtifactSourceFile::try_new(Path::new("Nargo.toml"), b"[package]\nname='circuit'\n")?,
        ArtifactSourceFile::try_new(Path::new("src/main.nr"), b"fn main() {}\n")?,
    ];
    let capability_registry = build_capability_registry()?;
    let material = ArtifactPackageMaterial::try_new(
        &sources,
        PROGRAM,
        VERIFICATION_KEY,
        &capability_registry,
        &vectors,
    )?;
    let coordinates = ArtifactPackageCoordinates::new_for_suite(
        bundle_kind,
        ZkClaimProofBundleStage::Session,
        credential_hash_algorithm,
        proof_suite,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
    );

    let package = ArtifactPackage::build(ArtifactPackageInput::new(coordinates, material))?;

    assert_eq!(package.manifest().proof_suite(), proof_suite);
    assert_eq!(package.manifest().digests().vector_set_sha256.len(), 1);
    Ok(())
}

fn temporary_root() -> Result<PathBuf, ArtifactPackageError> {
    let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "reallyme-zk-artifact-package-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

#[test]
fn package_manifest_hashes_exact_canonical_bytes() -> Result<(), ArtifactPackageError> {
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    let expected = Digest32::sha256(package.manifest_bytes());
    let registry = build_capability_registry()?;

    assert_eq!(
        package.manifest().manifest_sha256().as_bytes(),
        expected.as_bytes()
    );
    assert_eq!(
        package.manifest().digests().capability_registry_sha256,
        registry.sha256()
    );
    Ok(())
}

#[test]
fn package_layout_is_typed_and_versioned() -> Result<(), ArtifactPackageError> {
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    let layout = package.layout(Path::new("artifacts"))?;
    let manifest_component = package
        .manifest()
        .manifest_sha256()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(
        layout.directory().parent(),
        Some(Path::new(
            "artifacts/v1/sha256/credential_subject_claim_v1/session"
        ))
    );
    assert_eq!(
        layout.directory().file_name(),
        Some(std::ffi::OsStr::new(&manifest_component))
    );
    assert_eq!(layout.manifest(), layout.directory().join("manifest.pb"));
    Ok(())
}

#[test]
fn persisted_package_round_trips_and_refuses_overwrite() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    package.check(&root)?;

    let error = package
        .write_new(&root)
        .err()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ))?;
    assert_eq!(
        error.reason(),
        ArtifactPackageErrorReason::PackageAlreadyExists
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn interrupted_out_of_tree_atomic_temp_does_not_block_package_admission(
) -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    let layout = package.layout(&root)?;
    let temporary_parent = layout
        .directory()
        .parent()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
    fs::write(
        temporary_parent.join(".reallyme-zk-artifact-package.manifest.pb.interrupted.partial"),
        b"orphan",
    )?;

    package.check(&root)?;
    let manifest = package.manifest();
    let pin = ReleaseArtifactPin::try_new(
        manifest.bundle_kind(),
        manifest.stage(),
        manifest.circuit_ref(),
        manifest.manifest_sha256(),
    )?;
    let sealed = SealedArtifactPackage::load_and_check(&root, pin)?;
    assert_eq!(sealed.manifest(), manifest);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn sealed_package_reopens_from_exact_release_pin() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    let manifest = package.manifest();
    let pin = ReleaseArtifactPin::try_new(
        manifest.bundle_kind(),
        manifest.stage(),
        manifest.circuit_ref(),
        manifest.manifest_sha256(),
    )?;

    let sealed = SealedArtifactPackage::load_and_check(&root, pin)?;

    assert_eq!(sealed.manifest(), manifest);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn interrupted_manifestless_package_is_quarantined_and_retryable(
) -> Result<(), ArtifactPackageError> {
    let root = fs::canonicalize(temporary_root()?)?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    let manifest = package.manifest();
    let pin = ReleaseArtifactPin::try_new(
        manifest.bundle_kind(),
        manifest.stage(),
        manifest.circuit_ref(),
        manifest.manifest_sha256(),
    )?;
    let layout = package.layout(&root)?;
    fs::create_dir_all(layout.vectors())?;
    fs::write(layout.directory().join("partial-copy"), [7_u8, 8, 9])?;

    let summary = quarantine_incomplete_artifact_package(&root, pin)?;

    assert_eq!(summary.pin, pin);
    assert_eq!(summary.preserved_entry_count, 2);
    assert!(!layout.directory().try_exists()?);
    let relative = layout
        .directory()
        .strip_prefix(&root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InvalidRelativePath))?;
    let preserved = root
        .join(INCOMPLETE_ARTIFACT_PACKAGE_QUARANTINE_DIRECTORY)
        .join(relative)
        .join("package")
        .join("partial-copy");
    assert_eq!(fs::read(preserved)?, [7_u8, 8, 9]);

    package.write_new(&root)?;
    package.check(&root)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn sealed_package_rejects_tampered_vector_bytes() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    let manifest = package.manifest();
    let pin = ReleaseArtifactPin::try_new(
        manifest.bundle_kind(),
        manifest.stage(),
        manifest.circuit_ref(),
        manifest.manifest_sha256(),
    )?;
    let vector = package.layout(&root)?.vectors().join("positive/session.pb");
    fs::write(vector, b"tampered")?;
    let reason = SealedArtifactPackage::load_and_check(&root, pin)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ArtifactPackageErrorReason::PackageMismatch));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn verifier_rejects_tampered_artifact_bytes() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    fs::write(package.layout(&root)?.program(), b"tampered-program")?;

    let error = package.check(&root).err().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMissing,
    ))?;
    assert_eq!(error.reason(), ArtifactPackageErrorReason::PackageMismatch);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn verifier_rejects_unexpected_package_files() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    fs::write(
        package.layout(&root)?.directory().join("unexpected.bin"),
        b"x",
    )?;

    let error = package.check(&root).err().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMissing,
    ))?;
    assert_eq!(error.reason(), ArtifactPackageErrorReason::PackageMismatch);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn verifier_rejects_symlinked_package_payloads() -> Result<(), ArtifactPackageError> {
    use std::os::unix::fs::symlink;

    let root = temporary_root()?;
    let package = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    package.write_new(&root)?;
    let program = package.layout(&root)?.program();
    let external = root.join("external-program.json");
    fs::write(&external, PROGRAM)?;
    fs::remove_file(&program)?;
    symlink(&external, &program)?;

    let error = package.check(&root).err().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMissing,
    ))?;
    assert_eq!(error.reason(), ArtifactPackageErrorReason::PackageMismatch);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn vector_paths_are_bound_into_manifest_identity() -> Result<(), ArtifactPackageError> {
    let positive = build_package_with_vector_path(Path::new("positive/session.pb"))?;
    let negative = build_package_with_vector_path(Path::new("negative/session.pb"))?;

    assert_ne!(
        positive.manifest().manifest_sha256(),
        negative.manifest().manifest_sha256()
    );
    Ok(())
}

#[test]
fn malicious_and_non_protobuf_vector_paths_fail_closed() {
    let traversing = ArtifactVectorFile::try_new(Path::new("../escape.pb"), b"vector")
        .err()
        .map(|error| error.reason());
    let wrong_extension = ArtifactVectorFile::try_new(Path::new("positive/vector.json"), b"vector")
        .err()
        .map(|error| error.reason());

    assert_eq!(
        traversing,
        Some(ArtifactPackageErrorReason::InvalidRelativePath)
    );
    assert_eq!(
        wrong_extension,
        Some(ArtifactPackageErrorReason::InvalidRelativePath)
    );
}

#[test]
fn noncanonical_source_order_fails_closed() -> Result<(), ArtifactPackageError> {
    let sources = [
        ArtifactSourceFile::try_new(Path::new("src/z.nr"), b"z")?,
        ArtifactSourceFile::try_new(Path::new("src/a.nr"), b"a")?,
    ];
    let vector_bytes = valid_vector_bytes()?;
    let vectors = [ArtifactVectorFile::try_new(
        Path::new("positive/session.pb"),
        &vector_bytes,
    )?];
    let capability_registry = build_capability_registry()?;
    let error = ArtifactPackageMaterial::try_new(
        &sources,
        PROGRAM,
        VERIFICATION_KEY,
        &capability_registry,
        &vectors,
    )
    .err()
    .ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))?;

    assert_eq!(
        error.reason(),
        ArtifactPackageErrorReason::NonCanonicalFileOrder
    );
    Ok(())
}

#[test]
fn oversized_vector_input_fails_before_package_allocation() {
    let oversized = vec![0_u8; MAX_VECTOR_FILE_BYTES + 1];
    let reason = ArtifactVectorFile::try_new(Path::new("positive/oversized.pb"), &oversized)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ArtifactPackageErrorReason::InputTooLarge));
}

#[test]
fn arbitrary_protobuf_named_bytes_are_not_package_vectors() {
    let reason = ArtifactVectorFile::try_new(
        Path::new("positive/not-a-vector.pb"),
        b"canonical-looking-bytes",
    )
    .err()
    .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::MalformedProtobuf
        ))
    );
}
