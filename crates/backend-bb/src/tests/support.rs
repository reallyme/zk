// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    capabilities::ZkCircuitCapabilities,
    circuits::ZkCircuitRef,
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkCompatibilitySuiteAcknowledgement,
    },
    errors::ZkError,
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactManifestPin, ArtifactToolchain, ProductionArtifactManifest,
};

use super::manifest_digest;

fn manifest_pin_for_suite(proof_suite: ZkProofSuite) -> Result<ArtifactManifestPin, ZkError> {
    if proof_suite == ZkProofSuite::PRODUCTION {
        ArtifactManifestPin::try_new(proof_suite, manifest_digest())
    } else {
        ArtifactManifestPin::try_new_compatibility(
            proof_suite,
            manifest_digest(),
            ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )
    }
}

pub(super) fn manifest_for_suite(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    toolchain: ArtifactToolchain,
    capabilities: ZkCircuitCapabilities,
    digests: ArtifactDigests,
) -> Result<ProductionArtifactManifest, ZkError> {
    let manifest_pin = manifest_pin_for_suite(proof_suite)?;
    if proof_suite == ZkProofSuite::PRODUCTION {
        ProductionArtifactManifest::try_new(
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin,
            toolchain,
            capabilities,
            digests,
        )
    } else {
        ProductionArtifactManifest::try_new_compatibility(
            bundle_kind,
            stage,
            circuit_ref,
            manifest_pin,
            toolchain,
            capabilities,
            digests,
            ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )
    }
}
