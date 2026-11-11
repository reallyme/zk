// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    ZkDisclosureMode, ZkSemanticGuarantee, ZkSubjectBinding,
};

use super::{admit_artifact_manifest, capabilities, manifest};

#[test]
fn artifact_manifest_rejects_overclaimed_stage_guarantee() -> Result<(), ZkError> {
    let mut manifest = manifest();
    let mut capabilities = capabilities();
    capabilities.semantic_guarantees.push(EnumValue::from(
        ZkSemanticGuarantee::ZK_SEMANTIC_GUARANTEE_CREDENTIAL_AUTHENTICITY,
    ));
    manifest.capabilities = MessageField::some(capabilities);

    let err = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_unsupported_disclosure_mode() -> Result<(), ZkError> {
    let mut manifest = manifest();
    let mut capabilities = capabilities();
    capabilities.disclosure_modes =
        vec![EnumValue::from(ZkDisclosureMode::ZK_DISCLOSURE_MODE_HIDDEN)];
    manifest.capabilities = MessageField::some(capabilities);

    let err = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_subject_binding_mismatch() -> Result<(), ZkError> {
    let mut manifest = manifest();
    let mut capabilities = capabilities();
    capabilities.subject_binding = EnumValue::from(ZkSubjectBinding::ZK_SUBJECT_BINDING_FORBIDDEN);
    manifest.capabilities = MessageField::some(capabilities);

    let err = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn artifact_manifest_rejects_unsupported_and_unknown_predicates() -> Result<(), ZkError> {
    // Known vocabulary does not grant a circuit permission to claim support.
    for predicate_code in [0, 1, 2, 3, 99] {
        let mut manifest = manifest();
        let mut capabilities = capabilities();
        capabilities.predicate_types = vec![EnumValue::from(predicate_code)];
        manifest.capabilities = MessageField::some(capabilities);
        let error = admit_artifact_manifest(manifest)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    }
    Ok(())
}

#[test]
fn artifact_manifest_rejects_unknown_capability_codes() -> Result<(), ZkError> {
    for unknown_disclosure in [3, 4, 5] {
        let mut manifest = manifest();
        let mut capabilities = capabilities();
        capabilities.disclosure_modes = vec![EnumValue::from(unknown_disclosure)];
        manifest.capabilities = MessageField::some(capabilities);
        let error = admit_artifact_manifest(manifest)
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    }
    let mut manifest = manifest();
    let mut capabilities = capabilities();
    capabilities.semantic_guarantees.push(EnumValue::from(99));
    manifest.capabilities = MessageField::some(capabilities);
    let error = admit_artifact_manifest(manifest)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}
