// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::common_credential_root_pins;
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    common_root::ZkCommonCredentialRootSourceStage,
};
use reallyme_zk_artifacts::{CommonCredentialRootArtifactLayout, Digest32};
use reallyme_zk_proto_codec::release::RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT;

use crate::{ArtifactPackageError, ArtifactPackageErrorReason};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixture() -> Result<(PathBuf, Digest32), ArtifactPackageError> {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-common-credential-root-pins-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let mut lock = String::from("circuit\tpackage\tsource_closure_sha256\n");
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for source_stage in ZkCommonCredentialRootSourceStage::ALL {
            let stage = source_stage.circuit_stage();
            let circuit_ref = ZkCircuitRef::new(
                *credential_hash_algorithm,
                ZkCircuitFamily::CommonCredentialRootV1,
                stage,
            );
            let layout = CommonCredentialRootArtifactLayout::try_new(&root, circuit_ref)?;
            fs::create_dir_all(layout.directory())?;
            fs::write(layout.program(), b"synthetic compiled program")?;
            fs::write(layout.verification_key(), b"synthetic verification key")?;
            lock.push_str(&format!(
                "{}/families/{}/{}\tsynthetic_package\t{}\n",
                credential_hash_algorithm.source_dir(),
                circuit_ref.family.source_dir(),
                stage.source_dir(),
                "11".repeat(32),
            ));
        }
    }
    let lock_digest = Digest32::sha256(lock.as_bytes());
    let first = CommonCredentialRootArtifactLayout::try_new(
        &root,
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::RootAttestation,
        ),
    )?;
    fs::write(first.source_lock(), lock)?;
    Ok((root, lock_digest))
}

#[test]
fn complete_common_credential_root_artifacts_pin_and_reject_wrong_lock(
) -> Result<(), ArtifactPackageError> {
    let (root, lock_digest) = fixture()?;
    let pins = common_credential_root_pins(&root, lock_digest)?;
    assert_eq!(pins.len(), RELEASE_COMMON_CREDENTIAL_ROOT_ARTIFACT_COUNT);
    let wrong_lock = common_credential_root_pins(&root, Digest32::from_bytes([7; 32]))
        .err()
        .map(|error| error.reason());
    assert_eq!(
        wrong_lock,
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn incomplete_common_credential_root_artifacts_fail_closed() -> Result<(), ArtifactPackageError> {
    let (root, lock_digest) = fixture()?;
    let layout = CommonCredentialRootArtifactLayout::try_new(
        &root,
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::Lineage,
        ),
    )?;
    fs::remove_file(layout.verification_key())?;
    assert!(common_credential_root_pins(&root, lock_digest).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}
