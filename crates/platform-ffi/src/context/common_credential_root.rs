// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitFamily, ZkCircuitRef},
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_backend_bb::{
    BarretenbergCommonCredentialRootArtifactResolver, BbExactCircuitArtifacts,
};
use reallyme_zk_proto_codec::release::ReleaseIndex;

use super::{exact_source, PlatformContext};

impl BarretenbergCommonCredentialRootArtifactResolver for PlatformContext {
    fn resolve_common_credential_root_artifacts(
        &self,
        persona_mode: ZkCommonCredentialRootPersonaMode,
        slot: ZkCommonCredentialRootProofSlot,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        if self.release_index.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if persona_mode.source_ref(circuit_ref.credential_hash_algorithm, slot) != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        match circuit_ref.family {
            ZkCircuitFamily::PrivatePersonaClaimV1 => {
                let _manifest_pin = common_credential_root_release_manifest_pin(
                    &self.release_index,
                    circuit_ref,
                    proof_suite,
                )?;
                self.production_exact_artifacts_for_ref(circuit_ref, proof_suite)
            }
            ZkCircuitFamily::CommonCredentialRootV1 => {
                let pin = self
                    .release_index
                    .common_credential_root_artifacts()
                    .iter()
                    .copied()
                    .find(|pin| pin.circuit_ref() == circuit_ref)
                    .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
                exact_source::common_credential_root_release_artifacts(
                    &self.artifact_root,
                    pin,
                    proof_suite,
                )
            }
            _ => Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
        }
    }
}

pub(super) fn common_credential_root_release_manifest_pin(
    release_index: &ReleaseIndex,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
) -> Result<ZkArtifactManifestDigest, ZkError> {
    if release_index.proof_suite() != proof_suite {
        return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
    }
    release_index
        .artifact_manifests()
        .iter()
        .copied()
        .find(|pin| pin.circuit_ref() == circuit_ref)
        .map(|pin| pin.manifest_sha256())
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))
}
