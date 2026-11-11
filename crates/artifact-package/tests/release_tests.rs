// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::{
        ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
    },
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ABSENT_TRANSACTION_DATA_HASH,
    },
};
use reallyme_zk_artifact_package::{
    assemble_release_index, ArtifactPackageError, ArtifactPackageErrorReason,
    ReleaseArtifactManifestFile, ReleaseVerificationVectorFile, SealedRelease,
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactToolchain, ArtifactVersion, Digest32, ProductionArtifactManifest,
    ProductionArtifactManifestDraft,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{artifact::seal_artifact_manifest, release::decode_release_index};

const NONCE: [u8; 32] = [11; 32];
const AUDIENCE: [u8; 32] = [22; 32];
static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct ReleaseFixture {
    manifest_bytes: Vec<Vec<u8>>,
    vector_bytes: Vec<Vec<u8>>,
}

fn proto_hash(hash: ZkCredentialHashAlgorithm) -> pb::ZkCredentialHashAlgorithm {
    match hash {
        ZkCredentialHashAlgorithm::Sha256 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256
        }
        ZkCredentialHashAlgorithm::Poseidon2 => {
            pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2
        }
        _ => pb::ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_UNSPECIFIED,
    }
}

fn proto_profile(bundle_kind: ZkClaimProofBundleKind) -> pb::ZkClaimProofBundleKind {
    match bundle_kind {
        ZkClaimProofBundleKind::CredentialSubjectClaimV1 => {
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkClaimProofBundleKind::PrivatePersonaClaimV1 => {
            pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1
        }
        _ => pb::ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_UNSPECIFIED,
    }
}

fn proto_production_stage(stage: ZkClaimProofBundleStage) -> pb::ZkClaimProofBundleStage {
    match stage {
        ZkClaimProofBundleStage::Session => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_SESSION
        }
        ZkClaimProofBundleStage::CredentialEnvelope => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkClaimProofBundleStage::CredentialRoot => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CREDENTIAL_ROOT
        }
        ZkClaimProofBundleStage::Claim => {
            pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM
        }
        _ => pb::ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_UNSPECIFIED,
    }
}

fn proto_family(family: ZkCircuitFamily) -> pb::ZkCircuitFamily {
    match family {
        ZkCircuitFamily::CredentialSubjectClaimV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkCircuitFamily::PrivatePersonaClaimV1 => {
            pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_PRIVATE_PERSONA_CLAIM_V1
        }
        _ => pb::ZkCircuitFamily::ZK_CIRCUIT_FAMILY_UNSPECIFIED,
    }
}

fn proto_circuit_stage(stage: ZkCircuitStage) -> pb::ZkCircuitStage {
    match stage {
        ZkCircuitStage::Session => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        ZkCircuitStage::CredentialEnvelope => {
            pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE
        }
        ZkCircuitStage::CredentialRoot => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT,
        ZkCircuitStage::Claim => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM,
        ZkCircuitStage::ClaimBundle4 => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM_BUNDLE_4,
        _ => pb::ZkCircuitStage::ZK_CIRCUIT_STAGE_UNSPECIFIED,
    }
}

fn proto_circuit_id(id: ZkCircuitId) -> pb::ZkCircuitId {
    match id {
        ZkCircuitId::CredentialSubjectClaimV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1
        }
        ZkCircuitId::PrivatePersonaClaimV1 => {
            pb::ZkCircuitId::ZK_CIRCUIT_ID_PRIVATE_PERSONA_CLAIM_V1
        }
        _ => pb::ZkCircuitId::ZK_CIRCUIT_ID_UNSPECIFIED,
    }
}

fn proto_ref(reference: ZkCircuitRef) -> pb::ZkCircuitRef {
    pb::ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(proto_hash(reference.credential_hash_algorithm)),
        family: EnumValue::from(proto_family(reference.family)),
        stage: EnumValue::from(proto_circuit_stage(reference.stage)),
        circuit_revision: reference.revision,
        __buffa_unknown_fields: Default::default(),
    }
}

fn binding() -> pb::ZkSessionBinding {
    pb::ZkSessionBinding {
        nonce_hash: NONCE.to_vec(),
        audience_hash: AUDIENCE.to_vec(),
        transaction_data_hash: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn public_inputs(reference: ZkCircuitRef) -> Result<pb::ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(reference)?;
    let mut encoded = vec![0_u8; descriptor.encoded_len()?];
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::Challenge)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&NONCE);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::AudienceHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&AUDIENCE);
    encoded
        .get_mut(descriptor.field_range(ZkPublicInputName::TransactionDataHash)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
        .copy_from_slice(&ABSENT_TRANSACTION_DATA_HASH);
    Ok(pb::ZkPublicInputs {
        encoded,
        __buffa_unknown_fields: Default::default(),
    })
}

fn digest(marker: u8) -> Digest32 {
    Digest32::from_bytes([marker; 32])
}

fn build_manifests(
    toolchain: ArtifactToolchain,
) -> Result<(Vec<Vec<u8>>, Vec<ProductionArtifactManifest>), ArtifactPackageError> {
    let mut bytes = Vec::new();
    let mut manifests = Vec::new();
    let mut marker = 1_u8;
    for hash in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                let reference = bundle_kind.source_ref(*hash, *stage);
                let draft = ProductionArtifactManifestDraft::try_new(
                    *bundle_kind,
                    *stage,
                    reference,
                    ZkProofSuite::PRODUCTION,
                    toolchain,
                    circuit_ref_capabilities(reference)?,
                    ArtifactDigests {
                        noir_source_sha256: digest(marker),
                        bytecode_sha256: digest(marker.wrapping_add(32)),
                        verification_key_sha256: digest(marker.wrapping_add(64)),
                        capability_registry_sha256: digest(250),
                        vector_set_sha256: vec![digest(marker.wrapping_add(96))],
                    },
                )?;
                let sealed = seal_artifact_manifest(draft)?;
                let (manifest, protobuf) = sealed.into_parts();
                bytes.push(protobuf.encode_to_vec());
                manifests.push(manifest);
                marker = marker
                    .checked_add(1)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            }
        }
    }
    Ok((bytes, manifests))
}

fn verification_vector_bytes(
    hash: ZkCredentialHashAlgorithm,
    bundle_kind: ZkClaimProofBundleKind,
    manifests: &[ProductionArtifactManifest],
) -> Result<Vec<u8>, ArtifactPackageError> {
    let session_manifest = manifests
        .first()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let reference = bundle_kind.source_ref(hash, ZkClaimProofBundleStage::Session);
    let proof = pb::ZkProofPackage {
        circuit_id: EnumValue::from(proto_circuit_id(bundle_kind.circuit_id())),
        circuit_id_string: bundle_kind.circuit_id().as_str().to_owned(),
        proof: vec![31, 32, 33],
        public_inputs: MessageField::some(public_inputs(reference)?),
        artifact_identity: Some(
            pb::ZkArtifactManifestDigest {
                value: session_manifest.manifest_sha256().as_bytes().to_vec(),
                __buffa_unknown_fields: Default::default(),
            }
            .into(),
        ),
        named_public_inputs: Vec::new(),
        circuit_ref: MessageField::some(proto_ref(reference)),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let operation = pb::ZkProviderOperationRequest {
        operation: Some(
            pb::__buffa::oneof::zk_provider_operation_request::Operation::VerifyStage(Box::new(
                pb::ZkStageVerifyOperation {
                    proof: MessageField::some(proof),
                    expected_binding: MessageField::some(binding()),
                    expected_proof_suite: EnumValue::from(
                        pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };
    let expected = pb::ZkProviderOperationResponse {
        outcome: Some(
            pb::__buffa::oneof::zk_provider_operation_response::Outcome::Result(Box::new(
                pb::ZkProviderOperationResult {
                    result: Some(
                        pb::__buffa::oneof::zk_provider_operation_result::Result::StageVerification(
                            Box::new(pb::ZkVerification {
                                circuit_id: EnumValue::from(proto_circuit_id(bundle_kind.circuit_id())),
                                circuit_ref: MessageField::some(proto_ref(reference)),
                                bundle_kind: EnumValue::from(proto_profile(bundle_kind)),
                                proof_suite: EnumValue::from(
                                    pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                                ),
                                __buffa_unknown_fields: Default::default(),
                            }),
                        ),
                    ),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        request_sha256: Digest32::sha256(&operation.encode_to_vec())
            .as_bytes()
            .to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let artifact_manifests = manifests
        .iter()
        .map(|manifest| pb::ZkReleaseArtifactPin {
            bundle_kind: EnumValue::from(proto_profile(bundle_kind)),
            stage: EnumValue::from(proto_production_stage(manifest.stage())),
            circuit_ref: MessageField::some(proto_ref(manifest.circuit_ref())),
            artifact_manifest_sha256: MessageField::some(pb::ZkArtifactManifestDigest {
                value: manifest.manifest_sha256().as_bytes().to_vec(),
                __buffa_unknown_fields: Default::default(),
            }),
            __buffa_unknown_fields: Default::default(),
        })
        .collect();
    Ok(pb::ZkVerificationVectorSet {
        format_version: 1,
        bundle_kind: EnumValue::from(proto_profile(bundle_kind)),
        credential_hash_algorithm: EnumValue::from(proto_hash(hash)),
        proof_suite: EnumValue::from(
            pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        artifact_manifests,
        vectors: vec![pb::ZkVerificationVector {
            vector_number: 1,
            mutation: EnumValue::from(
                pb::ZkVerificationVectorMutation::ZK_VERIFICATION_VECTOR_MUTATION_NONE,
            ),
            base_operation: MessageField::some(operation),
            expected_response: MessageField::some(expected),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec())
}

fn release_fixture() -> Result<ReleaseFixture, ArtifactPackageError> {
    let toolchain = ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?;
    let (manifest_bytes, manifests) = build_manifests(toolchain)?;
    let mut vector_bytes = Vec::new();
    let mut offset = 0_usize;
    for hash in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            let end = offset
                .checked_add(ZkClaimProofBundleStage::ALL.len())
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let group = manifests
                .get(offset..end)
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            vector_bytes.push(verification_vector_bytes(*hash, *bundle_kind, group)?);
            offset = end;
        }
    }
    Ok(ReleaseFixture {
        manifest_bytes,
        vector_bytes,
    })
}

fn assemble(
    fixture: &ReleaseFixture,
) -> Result<reallyme_zk_artifact_package::AssembledReleaseIndex, ArtifactPackageError> {
    let manifests = fixture
        .manifest_bytes
        .iter()
        .map(|bytes| ReleaseArtifactManifestFile::try_new(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let vectors = fixture
        .vector_bytes
        .iter()
        .map(|bytes| ReleaseVerificationVectorFile::try_new(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    assemble_release_index("0.1.0", manifests, vectors)
}

fn temporary_root() -> Result<PathBuf, ArtifactPackageError> {
    let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "reallyme-zk-release-test-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

#[test]
fn complete_release_matrix_assembles_and_round_trips() -> Result<(), ArtifactPackageError> {
    let fixture = release_fixture()?;
    let assembled = assemble(&fixture)?;
    let decoded = decode_release_index(assembled.canonical_bytes())?;

    assert_eq!(decoded, *assembled.index());
    assert!(assembled
        .sha256()
        .matches_sha256(assembled.canonical_bytes()));
    assert_eq!(
        decoded.artifact_manifests().len(),
        ZkCredentialHashAlgorithm::ALL.len()
            * ZkClaimProofBundleKind::ALL.len()
            * ZkClaimProofBundleStage::ALL.len()
    );
    assert_eq!(
        decoded.verification_vectors().len(),
        ZkCredentialHashAlgorithm::ALL.len() * ZkClaimProofBundleKind::ALL.len()
    );
    Ok(())
}

#[test]
fn reordered_manifest_matrix_fails_closed() -> Result<(), ArtifactPackageError> {
    let mut fixture = release_fixture()?;
    fixture.manifest_bytes.swap(0, 1);
    let reason = assemble(&fixture).err().map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::ArtifactMismatch
        ))
    );
    Ok(())
}

#[test]
fn reordered_verification_vector_matrix_fails_closed() -> Result<(), ArtifactPackageError> {
    let mut fixture = release_fixture()?;
    fixture.vector_bytes.swap(0, 1);
    let reason = assemble(&fixture).err().map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::ArtifactMismatch
        ))
    );
    Ok(())
}

#[test]
fn noncanonical_manifest_and_vector_bytes_never_reach_assembly() -> Result<(), ArtifactPackageError>
{
    let mut fixture = release_fixture()?;
    fixture.manifest_bytes[0].extend_from_slice(&[0x18, 0x01]);
    fixture.vector_bytes[0].extend_from_slice(&[0x08, 0x01]);

    let manifest_reason = ReleaseArtifactManifestFile::try_new(&fixture.manifest_bytes[0])
        .err()
        .map(|error| error.reason());
    let vector_reason = ReleaseVerificationVectorFile::try_new(&fixture.vector_bytes[0])
        .err()
        .map(|error| error.reason());

    assert_eq!(
        manifest_reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::MalformedProtobuf
        ))
    );
    assert_eq!(
        vector_reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::MalformedProtobuf
        ))
    );
    Ok(())
}

#[test]
fn release_persistence_is_create_new_and_index_committed_last() -> Result<(), ArtifactPackageError>
{
    let fixture = release_fixture()?;
    let assembled = assemble(&fixture)?;
    let root = temporary_root()?;

    assembled.write_new(&root)?;
    assembled.check(&root)?;
    let layout = assembled.layout(&root)?;
    assert!(layout.index().is_file());
    for hash in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            assert!(layout.verification_vector(*hash, *bundle_kind).is_file());
        }
    }
    let second_write = assembled.write_new(&root).err().map(|error| error.reason());
    assert_eq!(
        second_write,
        Some(ArtifactPackageErrorReason::PackageAlreadyExists)
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn candidate_release_admission_rejects_interrupted_atomic_root_partial(
) -> Result<(), ArtifactPackageError> {
    let fixture = release_fixture()?;
    let assembled = assemble(&fixture)?;
    let root = temporary_root()?;
    assembled.write_new(&root)?;
    fs::write(
        root.join(".reallyme-zk-artifact-package.index.pb.interrupted.partial"),
        b"orphan",
    )?;

    assembled.check(&root)?;
    let version = ArtifactVersion::try_from_token("0.1.0")?;
    assert_eq!(
        SealedRelease::load_candidate_and_check(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn candidate_release_admission_rejects_unreferenced_release_file(
) -> Result<(), ArtifactPackageError> {
    let fixture = release_fixture()?;
    let assembled = assemble(&fixture)?;
    let root = temporary_root()?;
    assembled.write_new(&root)?;
    fs::write(root.join("unreferenced.bin"), b"unreviewed")?;

    // Runtime admission is graph-scoped, while candidate attestation must
    // reject bytes outside the reviewed release graph.
    assembled.check(&root)?;
    let version = ArtifactVersion::try_from_token("0.1.0")?;
    assert_eq!(
        SealedRelease::load_candidate_and_check(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn persisted_release_rejects_tampering_and_unexpected_entries() -> Result<(), ArtifactPackageError>
{
    let fixture = release_fixture()?;
    let assembled = assemble(&fixture)?;
    let root = temporary_root()?;
    assembled.write_new(&root)?;
    let layout = assembled.layout(&root)?;

    let vector_path = layout.verification_vector(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
    );
    fs::write(&vector_path, b"tampered")?;
    assert_eq!(
        assembled.check(&root).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    fs::write(&vector_path, &fixture.vector_bytes[0])?;
    fs::write(layout.directory().join("unexpected.pb"), b"unexpected")?;
    assert_eq!(
        assembled.check(&root).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn persisted_release_rejects_a_symlinked_release_directory() -> Result<(), ArtifactPackageError> {
    use std::os::unix::fs::symlink;

    let fixture = release_fixture()?;
    let assembled = assemble(&fixture)?;
    let root = temporary_root()?;
    assembled.write_new(&root)?;
    let layout = assembled.layout(&root)?;
    let moved_directory = root.join("moved-release");
    fs::rename(layout.directory(), &moved_directory)?;
    symlink(&moved_directory, layout.directory())?;

    assert_eq!(
        assembled.check(&root).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn release_version_cannot_be_a_traversal_component() -> Result<(), ArtifactPackageError> {
    let fixture = release_fixture()?;
    let manifests = fixture
        .manifest_bytes
        .iter()
        .map(|bytes| ReleaseArtifactManifestFile::try_new(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let vectors = fixture
        .vector_bytes
        .iter()
        .map(|bytes| ReleaseVerificationVectorFile::try_new(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let reason = assemble_release_index("..", manifests, vectors)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::ArtifactMismatch
        ))
    );
    Ok(())
}

#[test]
fn release_version_cannot_collide_with_hash_lane() -> Result<(), ArtifactPackageError> {
    let fixture = release_fixture()?;
    let manifests = fixture
        .manifest_bytes
        .iter()
        .map(|bytes| ReleaseArtifactManifestFile::try_new(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let vectors = fixture
        .vector_bytes
        .iter()
        .map(|bytes| ReleaseVerificationVectorFile::try_new(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let reason = assemble_release_index("sha256", manifests, vectors)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::Domain(
            ZkErrorReason::ArtifactMismatch
        ))
    );
    Ok(())
}
