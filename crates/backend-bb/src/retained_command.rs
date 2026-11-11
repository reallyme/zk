// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dev-only retained BBAPI command generation for promotion evidence.

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::ZkError,
    proofs::{ZkProofSuite, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, Digest32,
    ProductionArtifactManifest, VerifiedArtifactBytes,
};

use zeroize::Zeroizing;

use crate::{
    bbapi_abi::{BbapiCircuitProveCommand, BbapiSrsInitCommand},
    BbStageArtifacts, BbStageProveRequest,
};

/// Encodes the linked-backend `CircuitProve` command used by production.
pub fn encode_retained_prove_command(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    bytecode: Vec<u8>,
    verification_key: Vec<u8>,
    witness: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let bytecode_digest = Digest32::sha256(bytecode.as_slice());
    let verification_key_digest = Digest32::sha256(verification_key.as_slice());
    let manifest = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(
            ZkProofSuite::PRODUCTION,
            ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
        )?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        reallyme_zk_api::capabilities::circuit_ref_capabilities(circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
            bytecode_sha256: bytecode_digest,
            verification_key_sha256: verification_key_digest,
            capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
        },
    )?;
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        bytecode,
        bytecode_digest,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key,
        verification_key_digest,
    )?;
    let artifacts = BbStageArtifacts::try_new(manifest, bytecode, verification_key)?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, witness)?;
    let command = BbapiCircuitProveCommand::try_new(BbStageProveRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: retained_nonzero_binding(),
    })?;
    Ok(command.into_zeroizing_bytes())
}

/// Encodes the linked-backend full-prover `SrsInitSrs` command.
pub fn encode_retained_full_prover_srs_command(
    g1_prefix: &[u8],
    g2_point: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let command = BbapiSrsInitCommand::try_new_prover(g1_prefix, g2_point)?;
    Ok(Zeroizing::new(command.as_bytes().to_vec()))
}

const fn retained_nonzero_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    }
}
