// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
};
use reallyme_zk_artifact_package::noir_source_tree_sha256;

use crate::assembly::circuit_directory;
use crate::source_tree::{parse_path_dependencies, SourceTree};
use crate::{ReleaseAssemblyError, ReleaseAssemblyErrorReason};

#[test]
fn exact_circuit_paths_are_derived_only_from_closed_coordinates() {
    let root = Path::new("/workspace");
    let path = circuit_directory(
        root,
        ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkClaimProofBundleStage::CredentialRoot,
    );
    assert_eq!(
        path,
        Path::new(
            "/workspace/circuits/poseidon2/families/private_persona_claim_v1/credential_root"
        )
    );
}

#[test]
fn package_name_registry_matches_compiled_target() {
    assert_eq!(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1
            .nargo_package_name(ZkClaimProofBundleStage::CredentialEnvelope),
        "credential_private_persona_claim_v1_credential_envelope"
    );
}

#[test]
fn real_circuit_source_tree_is_complete_and_bounded() -> Result<(), ReleaseAssemblyError> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ))?;
    let circuit = circuit_directory(
        workspace_root,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Session,
    );
    let source_tree = SourceTree::load(workspace_root, &circuit)?;
    assert_eq!(source_tree.borrowed_files()?.len(), 3);
    Ok(())
}

#[test]
fn poseidon2_source_tree_includes_the_vendored_dependency_closure(
) -> Result<(), ReleaseAssemblyError> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ))?;
    let circuit = circuit_directory(
        workspace_root,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkClaimProofBundleStage::Session,
    );
    let source_tree = SourceTree::load(workspace_root, &circuit)?;
    assert!(source_tree.contains_path(Path::new(
        "circuits/vendor/poseidon-v0.2.0/src/poseidon2.nr"
    )));
    assert_eq!(source_tree.borrowed_files()?.len(), 6);
    Ok(())
}

#[test]
fn vendored_dependency_mutation_changes_the_canonical_source_digest(
) -> Result<(), ReleaseAssemblyError> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ))?;
    let circuit = circuit_directory(
        workspace_root,
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkClaimProofBundleStage::Session,
    );
    let vendored_path = Path::new("circuits/vendor/poseidon-v0.2.0/src/poseidon2.nr");
    let mut source_tree = SourceTree::load(workspace_root, &circuit)?;
    let original = noir_source_tree_sha256(&source_tree.borrowed_files()?)?;

    source_tree.mutate_first_byte(vendored_path)?;
    let mutated = noir_source_tree_sha256(&source_tree.borrowed_files()?)?;

    assert_ne!(original, mutated);
    Ok(())
}

#[test]
fn source_closure_parser_accepts_both_path_dependency_forms() -> Result<(), ReleaseAssemblyError> {
    let inline = b"[package]\nname = 'sample'\n[dependencies] # local source closure\nposeidon2 = { path = '../../../vendor/poseidon-v0.2.0' }\n";
    let table = b"[package]\nname = 'sample'\n[dependencies.poseidon2]\npath = '../../../vendor/poseidon-v0.2.0'\n";
    let expected = vec![Path::new("../../../vendor/poseidon-v0.2.0").to_path_buf()];
    assert_eq!(parse_path_dependencies(inline)?, expected);
    assert_eq!(parse_path_dependencies(table)?, expected);
    Ok(())
}

#[test]
fn source_closure_parser_rejects_unhashed_dependency_sources() {
    for manifest in [
        "[dependencies]\nposeidon2 = { git = 'https://example.invalid/poseidon2' }\n",
        "[dependencies.poseidon2]\npath = '../vendor'\ngit = 'https://example.invalid/poseidon2'\n",
        "[dependencies]\nposeidon2 = { path = '../vendor' }\nposeidon2 = { path = '../other' }\n",
        "[dependencies]\nposeidon2 = { path = '' }\n",
    ] {
        assert_eq!(
            parse_path_dependencies(manifest.as_bytes()).err(),
            Some(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath
            ))
        );
    }
}
