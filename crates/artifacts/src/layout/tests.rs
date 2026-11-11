// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use reallyme_zk_api::circuits::{
    ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
};

use super::PersonaCredentialEvidenceArtifactLayout;

#[test]
fn prepared_layout_accepts_only_closed_source_coordinates() {
    let root = Path::new("/tmp/reallyme-artifact-layout-test");
    let prepared = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::PersonaCredentialEvidenceV1,
        ZkCircuitStage::EvidenceCurrentState,
    );
    let layout = PersonaCredentialEvidenceArtifactLayout::try_new(root, prepared).ok();
    assert_eq!(
        layout.as_ref().map(|value| value.program()),
        Some(root.join("persona-credential-evidence-v1/sha256/current_state/program.json"))
    );
    let unrelated = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::RootStatus,
    );
    assert!(PersonaCredentialEvidenceArtifactLayout::try_new(root, unrelated).is_err());
}
