// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use reallyme_zk_api::circuits::{
    ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
};
use reallyme_zk_artifacts::{Digest32, PersonaCredentialEvidenceArtifactLayout};
use reallyme_zk_proto_codec::release::RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT;

use super::{
    persona_credential_evidence_pins, validate_mobile_runtime_persona_credential_evidence_artifact,
    PERSONA_CREDENTIAL_EVIDENCE_STAGES,
};
use crate::{ArtifactPackageError, ArtifactPackageErrorReason};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixture() -> Result<(PathBuf, Digest32), ArtifactPackageError> {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "reallyme-zk-persona-credential-evidence-pins-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let mut lock = String::from("circuit\tpackage\tsource_closure_sha256\n");
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for stage in PERSONA_CREDENTIAL_EVIDENCE_STAGES {
            let circuit_ref = ZkCircuitRef::new(
                *credential_hash_algorithm,
                ZkCircuitFamily::PersonaCredentialEvidenceV1,
                stage,
            );
            let layout = PersonaCredentialEvidenceArtifactLayout::try_new(&root, circuit_ref)?;
            fs::create_dir_all(layout.directory())?;
            fs::write(
                layout.program(),
                b"synthetic compiled persona credential evidence program",
            )?;
            fs::write(
                layout.verification_key(),
                b"synthetic persona credential evidence verification key",
            )?;
            lock.push_str(&format!(
                "{}/families/{}/{}\tsynthetic_package\t{}\n",
                credential_hash_algorithm.source_dir(),
                circuit_ref.family.source_dir(),
                stage.source_dir(),
                "11".repeat(32),
            ));
        }
    }
    let digest = Digest32::sha256(lock.as_bytes());
    let first = PersonaCredentialEvidenceArtifactLayout::try_new(
        &root,
        ZkCircuitRef::new(
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidencePublicClaim,
        ),
    )?;
    fs::write(first.source_lock(), lock)?;
    Ok((root, digest))
}

#[test]
fn persona_credential_evidence_artifacts_require_full_matrix_and_authenticated_lock(
) -> Result<(), ArtifactPackageError> {
    let (root, digest) = fixture()?;
    let pins = persona_credential_evidence_pins(&root, digest)?;
    assert_eq!(
        pins.len(),
        RELEASE_PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_COUNT
    );
    assert_ne!(
        pins[0].artifact_identity_sha256(),
        pins[2].artifact_identity_sha256()
    );
    for pin in &pins {
        validate_mobile_runtime_persona_credential_evidence_artifact(&root, *pin)?;
    }
    let tampered = PersonaCredentialEvidenceArtifactLayout::try_new(&root, pins[2].circuit_ref())?;
    let original_program = fs::read(tampered.program())?;
    fs::write(
        tampered.program(),
        b"substituted persona credential evidence program",
    )?;
    assert_eq!(
        validate_mobile_runtime_persona_credential_evidence_artifact(&root, pins[2])
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::write(tampered.program(), original_program)?;
    let original_key = fs::read(tampered.verification_key())?;
    fs::write(
        tampered.verification_key(),
        b"substituted persona credential evidence key",
    )?;
    assert_eq!(
        validate_mobile_runtime_persona_credential_evidence_artifact(&root, pins[2])
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    fs::write(tampered.verification_key(), original_key)?;
    assert_eq!(
        persona_credential_evidence_pins(&root, Digest32::from_bytes([7; 32]))
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    let missing = PersonaCredentialEvidenceArtifactLayout::try_new(&root, pins[2].circuit_ref())?;
    fs::remove_file(missing.verification_key())?;
    assert!(persona_credential_evidence_pins(&root, digest).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}
