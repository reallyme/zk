// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use buffa::{Message, MessageField};
use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifact_package::{
    validate_mobile_public_runtime, ArtifactPackageError, ArtifactPackageErrorReason,
    ArtifactPackageLayout, ReleasePackageLayout, SealedRelease,
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactToolchain, ArtifactVersion, Digest32, ProductionArtifactManifestDraft,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    artifact::seal_artifact_manifest,
    capability_registry::build_capability_registry,
    release::{
        encode_release_index, ReleaseArtifactPin, ReleaseIndex, ReleaseVerificationVectorPin,
    },
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const PROGRAM: &[u8] = b"public test program";
const KEY: &[u8] = b"public test verification key";

fn fixture() -> Result<(PathBuf, ArtifactVersion, PathBuf), ArtifactPackageError> {
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-mobile-runtime-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let root = fs::canonicalize(root)?;
    let version = ArtifactVersion::try_from_token("v1")?;
    let registry = build_capability_registry()?;
    let toolchain = ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?;
    let mut manifests = Vec::new();
    let mut vectors = Vec::new();
    let mut first_package = None;
    for algorithm in ZkCredentialHashAlgorithm::ALL {
        for kind in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                let circuit = kind.source_ref(*algorithm, *stage);
                let draft = ProductionArtifactManifestDraft::try_new(
                    *kind,
                    *stage,
                    circuit,
                    ZkProofSuite::PRODUCTION,
                    toolchain,
                    circuit_ref_capabilities(circuit)?,
                    ArtifactDigests {
                        noir_source_sha256: Digest32::from_bytes([1; 32]),
                        bytecode_sha256: Digest32::sha256(PROGRAM),
                        verification_key_sha256: Digest32::sha256(KEY),
                        capability_registry_sha256: registry.sha256(),
                        vector_set_sha256: vec![Digest32::from_bytes([2; 32])],
                    },
                )?;
                let (manifest, wire) = seal_artifact_manifest(draft)?.into_parts();
                let layout = ArtifactPackageLayout::try_new(
                    &root,
                    *algorithm,
                    *kind,
                    *stage,
                    manifest.manifest_sha256(),
                )?;
                fs::create_dir_all(layout.directory())?;
                fs::write(layout.manifest(), wire.encode_to_vec())?;
                fs::write(layout.program(), PROGRAM)?;
                fs::write(layout.verification_key(), KEY)?;
                if first_package.is_none() {
                    first_package = Some(layout.directory().to_path_buf());
                }
                manifests.push(ReleaseArtifactPin::try_new(
                    *kind,
                    *stage,
                    circuit,
                    manifest.manifest_sha256(),
                )?);
            }
            // A runtime retains vector integrity pins, not their private bytes.
            vectors.push(ReleaseVerificationVectorPin::try_new(
                *kind,
                *algorithm,
                ZkProofSuite::PRODUCTION,
                Digest32::sha256(format!("{}:{}", algorithm.as_str(), kind.as_str()).as_bytes()),
                1,
            )?);
        }
    }
    let index = ReleaseIndex::try_new(
        version,
        toolchain,
        ZkProofSuite::PRODUCTION,
        registry.sha256(),
        manifests,
        vectors,
    )?;
    let release = ReleasePackageLayout::try_new(&root, version)?;
    fs::create_dir_all(release.directory())?;
    fs::write(release.index(), encode_release_index(&index)?)?;
    let first_package = first_package.ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    Ok((root, version, first_package))
}

#[test]
fn public_runtime_accepts_pinned_artifacts_without_private_vectors(
) -> Result<(), ArtifactPackageError> {
    let (root, version, _) = fixture()?;
    validate_mobile_public_runtime(&root, version)?;
    // Full release validation still requires its proof-bearing vectors.
    assert_eq!(
        SealedRelease::load_and_check(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMissing)
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_runtime_rejects_tampered_program_key_and_manifest() -> Result<(), ArtifactPackageError> {
    let (root, version, package) = fixture()?;
    for name in ["program.json", "verification-key.bin", "manifest.pb"] {
        let path = package.join(name);
        let original = fs::read(&path)?;
        let tampered = if name == "manifest.pb" {
            let mut manifest = pb::ZkArtifactManifest::decode_from_slice(&original)
                .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
            manifest.bytecode_sha256 = MessageField::some(pb::Digest {
                value: vec![7; 32],
                __buffa_unknown_fields: Default::default(),
            });
            manifest.encode_to_vec()
        } else {
            let mut bytes = original.clone();
            let byte = bytes
                .first_mut()
                .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
            *byte ^= 1;
            bytes
        };
        fs::write(&path, tampered)?;
        assert_eq!(
            validate_mobile_public_runtime(&root, version)
                .err()
                .map(|error| error.reason()),
            Some(ArtifactPackageErrorReason::PackageMismatch)
        );
        fs::write(path, original)?;
        validate_mobile_public_runtime(&root, version)?;
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_runtime_rejects_private_vectors_extra_files_and_empty_directories(
) -> Result<(), ArtifactPackageError> {
    let (root, version, package) = fixture()?;
    for path in [
        root.join("unexpected.bin"),
        package.join("private-proof.bin"),
    ] {
        fs::write(&path, b"private vector must not ship")?;
        assert_eq!(
            validate_mobile_public_runtime(&root, version)
                .err()
                .map(|error| error.reason()),
            Some(ArtifactPackageErrorReason::PackageMismatch)
        );
        fs::remove_file(path)?;
    }
    let vectors = package.join("vectors");
    fs::create_dir(&vectors)?;
    assert_eq!(
        validate_mobile_public_runtime(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::remove_dir(vectors)?;
    validate_mobile_public_runtime(&root, version)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_runtime_requires_absolute_complete_root() -> Result<(), ArtifactPackageError> {
    let version = ArtifactVersion::try_from_token("v1")?;
    assert_eq!(
        validate_mobile_public_runtime(Path::new("artifacts"), version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::InvalidRelativePath)
    );
    let (root, version, package) = fixture()?;
    fs::remove_file(package.join("verification-key.bin"))?;
    assert_eq!(
        validate_mobile_public_runtime(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMissing)
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn public_runtime_rejects_symlinked_key() -> Result<(), ArtifactPackageError> {
    use std::os::unix::fs::symlink;

    let (root, version, package) = fixture()?;
    let path = package.join("verification-key.bin");
    fs::remove_file(&path)?;
    symlink(package.join("program.json"), path)?;
    assert_eq!(
        validate_mobile_public_runtime(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_runtime_rejects_a_stale_capability_registry() -> Result<(), ArtifactPackageError> {
    let (root, version, _) = fixture()?;
    let layout = ReleasePackageLayout::try_new(&root, version)?;
    let mut index = pb::ZkReleaseIndex::decode_from_slice(&fs::read(layout.index())?)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    index.capability_registry_sha256 = MessageField::some(pb::Digest {
        value: vec![7; 32],
        __buffa_unknown_fields: Default::default(),
    });
    fs::write(layout.index(), index.encode_to_vec())?;
    assert_eq!(
        validate_mobile_public_runtime(&root, version)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::remove_dir_all(root)?;
    Ok(())
}
