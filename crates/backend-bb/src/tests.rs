// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    BarretenbergArtifactResolver, BarretenbergArtifactStore, BarretenbergBundleProvider,
    BbCommonCredentialRootRawVerifyRequest, BbExactCircuitArtifacts, BbStageArtifacts,
    BbStageProveRequest, BbStageProveResponse, BbStageVerifyRequest, LinkedBarretenbergBackend,
    ManifestBackedArtifactResolver,
};
use crate::provider::validate_presentation_expiry;
use crate::BarretenbergCommonCredentialRootArtifactResolver;
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkClaimProofBundle, ZkClaimProofBundleKind,
        ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver, ZkClaimProofBundleStage,
        ZkClaimProofBundleStageProof, ZkClaimProofBundleWitness,
        ZkPresentationBoundClaimBundleVerifyRequest,
    },
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding, ZkWitness,
    },
};
use reallyme_zk_artifacts::{
    ArtifactBytes, ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, Digest32,
    ProductionArtifactManifest, ProductionBundleManifest, VerifiedArtifactBytes,
};
use std::sync::atomic::{AtomicUsize, Ordering};

mod common_credential_root;
mod support;
use common_credential_root::{
    common_credential_root_artifact_identity, common_credential_root_artifacts,
};

#[derive(Debug, Clone, Copy)]
struct AcceptingBackend {
    supported_suite: Option<ZkProofSuite>,
}

impl AcceptingBackend {
    const fn all_suites() -> Self {
        Self {
            supported_suite: None,
        }
    }

    const fn only(supported_suite: ZkProofSuite) -> Self {
        Self {
            supported_suite: Some(supported_suite),
        }
    }
}

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([8_u8; 32])
}

impl LinkedBarretenbergBackend for AcceptingBackend {
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        self.supported_suite
            .is_none_or(|supported_suite| supported_suite == proof_suite)
    }

    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        let proof_marker = request
            .stage
            .index()
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if request.artifacts.bytecode().as_bytes().is_empty() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        BbStageProveResponse::try_from_compact_bytes(
            request.circuit_ref,
            vec![proof_marker],
            public_inputs_for_circuit(request.circuit_ref, request.session_binding)?.into_bytes(),
        )
    }

    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        if request.proof.proof_bytes().is_empty() {
            return Err(ZkError::new(ZkErrorReason::InvalidProof));
        }

        if request.artifacts.verification_key().as_bytes().is_empty() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(())
    }

    fn verify_common_credential_root_raw(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        if request.proof_bytes.as_bytes().is_empty() {
            return Err(ZkError::new(ZkErrorReason::InvalidProof));
        }

        if request.artifacts.verification_key().as_bytes().is_empty() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(())
    }
}

#[derive(Debug)]
struct CountingCommonCredentialRootBackend {
    common_credential_root_calls: AtomicUsize,
}

impl CountingCommonCredentialRootBackend {
    const fn new() -> Self {
        Self {
            common_credential_root_calls: AtomicUsize::new(0),
        }
    }
}

impl LinkedBarretenbergBackend for CountingCommonCredentialRootBackend {
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        proof_suite == ZkProofSuite::PRODUCTION
    }

    fn prove_stage(
        &self,
        _request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
    }

    fn verify_stage(&self, _request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
    }

    fn verify_common_credential_root_raw(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        if request.proof_bytes.as_bytes().is_empty()
            || request.public_inputs.as_bytes().is_empty()
            || request.artifacts.verification_key().as_bytes().is_empty()
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProof));
        }
        self.common_credential_root_calls
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ResolverMode {
    Matching,
    WrongManifestProfile,
    BadBytecodeDigest,
    WrongCommonCredentialRootArtifactIdentity,
}

#[derive(Debug, Clone, Copy)]
struct StaticArtifactResolver {
    mode: ResolverMode,
}

impl StaticArtifactResolver {
    const fn matching() -> Self {
        Self {
            mode: ResolverMode::Matching,
        }
    }

    const fn wrong_manifest_profile() -> Self {
        Self {
            mode: ResolverMode::WrongManifestProfile,
        }
    }

    const fn bad_bytecode_digest() -> Self {
        Self {
            mode: ResolverMode::BadBytecodeDigest,
        }
    }

    const fn wrong_common_credential_root_artifact_identity() -> Self {
        Self {
            mode: ResolverMode::WrongCommonCredentialRootArtifactIdentity,
        }
    }
}

impl BarretenbergArtifactResolver for StaticArtifactResolver {
    fn resolve_stage_artifacts(
        &self,
        profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError> {
        let manifest_profile = match self.mode {
            ResolverMode::Matching
            | ResolverMode::BadBytecodeDigest
            | ResolverMode::WrongCommonCredentialRootArtifactIdentity => profile,
            ResolverMode::WrongManifestProfile => ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        };
        let manifest_ref =
            manifest_profile.source_ref(circuit_ref.credential_hash_algorithm, stage);
        let bytecode_bytes = artifact_bytes(manifest_profile, stage, 40)?;
        let verification_key_bytes = artifact_bytes(manifest_profile, stage, 80)?;
        let bytecode_digest = match self.mode {
            ResolverMode::BadBytecodeDigest => Digest32::from_bytes([9_u8; 32]),
            ResolverMode::Matching
            | ResolverMode::WrongManifestProfile
            | ResolverMode::WrongCommonCredentialRootArtifactIdentity => {
                Digest32::sha256(bytecode_bytes.as_slice())
            }
        };
        let digests = ArtifactDigests {
            noir_source_sha256: Digest32::sha256(&[1_u8]),
            bytecode_sha256: bytecode_digest,
            verification_key_sha256: Digest32::sha256(verification_key_bytes.as_slice()),
            capability_registry_sha256: Digest32::sha256(&[2_u8]),
            vector_set_sha256: vec![Digest32::sha256(&[3_u8])],
        };
        let capabilities = circuit_ref_capabilities(manifest_ref)?;
        let manifest = support::manifest_for_suite(
            manifest_profile,
            stage,
            manifest_ref,
            proof_suite,
            test_toolchain()?,
            capabilities,
            digests,
        )?;
        let bytecode = VerifiedArtifactBytes::try_from_bytes(
            ArtifactKind::AcirBytecode,
            bytecode_bytes,
            manifest.digests().bytecode_sha256,
        )?;
        let verification_key = VerifiedArtifactBytes::try_from_bytes(
            ArtifactKind::VerificationKey,
            verification_key_bytes,
            manifest.digests().verification_key_sha256,
        )?;

        BbStageArtifacts::try_new(manifest, bytecode, verification_key)
    }
}

impl BarretenbergCommonCredentialRootArtifactResolver for StaticArtifactResolver {
    fn resolve_common_credential_root_artifacts(
        &self,
        profile: ZkCommonCredentialRootPersonaMode,
        slot: ZkCommonCredentialRootProofSlot,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbExactCircuitArtifacts, ZkError> {
        if proof_suite != ZkProofSuite::PRODUCTION
            || circuit_ref != profile.source_ref(circuit_ref.credential_hash_algorithm, slot)
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let identity = match self.mode {
            ResolverMode::WrongCommonCredentialRootArtifactIdentity => {
                ZkArtifactManifestDigest::from_bytes([0x99; 32])
            }
            ResolverMode::Matching
            | ResolverMode::WrongManifestProfile
            | ResolverMode::BadBytecodeDigest => {
                common_credential_root_artifact_identity(circuit_ref)
            }
        };
        common_credential_root_artifacts(circuit_ref, slot, identity)
    }
}

#[derive(Debug, Clone, Copy)]
enum StoreMode {
    Matching,
    BadBytecodeBytes,
}

#[derive(Debug, Clone, Copy)]
struct TestArtifactStore {
    mode: StoreMode,
}

impl TestArtifactStore {
    const fn matching() -> Self {
        Self {
            mode: StoreMode::Matching,
        }
    }

    const fn bad_bytecode_bytes() -> Self {
        Self {
            mode: StoreMode::BadBytecodeBytes,
        }
    }
}

impl BarretenbergArtifactStore for TestArtifactStore {
    fn bytecode_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError> {
        let bytes = match self.mode {
            StoreMode::Matching => artifact_bytes(manifest.bundle_kind(), manifest.stage(), 40),
            StoreMode::BadBytecodeBytes => Ok(vec![250_u8]),
        }?;
        ArtifactBytes::try_from_bytes(ArtifactKind::AcirBytecode, bytes)
    }

    fn verification_key_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError> {
        ArtifactBytes::try_from_bytes(
            ArtifactKind::VerificationKey,
            artifact_bytes(manifest.bundle_kind(), manifest.stage(), 80)?,
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct VerificationOnlyStore;

impl BarretenbergArtifactStore for VerificationOnlyStore {
    fn bytecode_bytes(
        &self,
        _manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError> {
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    }

    fn verification_key_bytes(
        &self,
        manifest: &ProductionArtifactManifest,
    ) -> Result<ArtifactBytes, ZkError> {
        ArtifactBytes::try_from_bytes(
            ArtifactKind::VerificationKey,
            artifact_bytes(manifest.bundle_kind(), manifest.stage(), 80)?,
        )
    }
}

fn provider() -> BarretenbergBundleProvider<AcceptingBackend, StaticArtifactResolver> {
    BarretenbergBundleProvider::new(
        AcceptingBackend::all_suites(),
        StaticArtifactResolver::matching(),
    )
}

fn provider_with_resolver(
    resolver: StaticArtifactResolver,
) -> BarretenbergBundleProvider<AcceptingBackend, StaticArtifactResolver> {
    BarretenbergBundleProvider::new(AcceptingBackend::all_suites(), resolver)
}

fn binding(seed: u8) -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [seed; 32],
        audience_hash: [seed.saturating_add(1); 32],
        transaction_data_hash: None,
    }
}

fn transaction_binding(seed: u8) -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [seed; 32],
        audience_hash: [seed.saturating_add(1); 32],
        transaction_data_hash: Some([seed.saturating_add(2); 32]),
    }
}

fn claim_proof_bundle_witness(
    profile: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ZkClaimProofBundleWitness, ZkError> {
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    for stage in ZkClaimProofBundleStage::ALL {
        witnesses.push(ZkWitness::try_from_noir_witness_stack_v1(
            profile.source_ref(credential_hash_algorithm, *stage),
            vec![stage.index().saturating_add(1)],
        )?);
    }
    ZkClaimProofBundleWitness::try_from_stage_witnesses(
        profile,
        credential_hash_algorithm,
        witnesses,
    )
}

fn public_inputs_for_circuit(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
) -> Result<ZkPublicInputs, ZkError> {
    public_inputs_for_circuit_and_holder(circuit_ref, binding, [10_u8; 32])
}

fn public_inputs_for_circuit_and_holder(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
    holder_link_commitment: [u8; 32],
) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::Challenge,
        &binding.nonce_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::AudienceHash,
        &binding.audience_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::TransactionDataHash,
        &binding.transaction_data_public_input(),
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &42_u64.to_be_bytes(),
    )?;
    for (name, value) in [
        (ZkPublicInputName::IssuerPublicKeyX, [21_u8; 32]),
        (ZkPublicInputName::IssuerPublicKeyY, [22_u8; 32]),
        (ZkPublicInputName::PersonaPublicKeyX, [23_u8; 32]),
        (ZkPublicInputName::PersonaPublicKeyY, [24_u8; 32]),
        (ZkPublicInputName::ClaimNameHash, [25_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::ValueLength,
            &1_u32.to_be_bytes(),
        )?;
        let mut value = [0_u8; 64];
        value[0] = 26;
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::Value,
            &value,
        )?;
    }
    for (name, value) in [
        (ZkPublicInputName::SessionBinding, holder_link_commitment),
        (ZkPublicInputName::EnvelopeBinding, [11_u8; 32]),
        (ZkPublicInputName::CredentialBinding, [12_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    ZkPublicInputs::try_from_bytes(bytes)
}

const fn trusted_issuer() -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [21_u8; 32],
        y: [22_u8; 32],
    }
}

fn write_public_input(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

fn profile_marker(profile: ZkClaimProofBundleKind) -> u8 {
    match profile {
        ZkClaimProofBundleKind::CredentialSubjectClaimV1 => 1,
        ZkClaimProofBundleKind::PrivatePersonaClaimV1 => 2,
        _ => 0,
    }
}

fn artifact_bytes(
    profile: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    offset: u8,
) -> Result<Vec<u8>, ZkError> {
    let profile_byte = profile_marker(profile)
        .checked_add(offset)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let stage_byte = stage
        .index()
        .checked_add(offset)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;

    Ok(vec![profile_byte, stage_byte])
}

fn artifact_digests(
    profile: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
) -> Result<ArtifactDigests, ZkError> {
    let bytecode = artifact_bytes(profile, stage, 40)?;
    let verification_key = artifact_bytes(profile, stage, 80)?;
    Ok(ArtifactDigests {
        noir_source_sha256: Digest32::sha256(&[1_u8]),
        bytecode_sha256: Digest32::sha256(bytecode.as_slice()),
        verification_key_sha256: Digest32::sha256(verification_key.as_slice()),
        capability_registry_sha256: Digest32::sha256(&[2_u8]),
        vector_set_sha256: vec![Digest32::sha256(&[3_u8])],
    })
}

fn test_toolchain() -> Result<ArtifactToolchain, ZkError> {
    ArtifactToolchain::try_from_versions("1.0.0-beta.9", "0.82.2")
}

fn stage_manifest(
    profile: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stage: ZkClaimProofBundleStage,
) -> Result<ProductionArtifactManifest, ZkError> {
    let circuit_ref = profile.source_ref(credential_hash_algorithm, stage);
    let capabilities = circuit_ref_capabilities(circuit_ref)?;
    ProductionArtifactManifest::try_new(
        profile,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest())?,
        test_toolchain()?,
        capabilities,
        artifact_digests(profile, stage)?,
    )
}

fn production_manifest(
    profile: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ProductionBundleManifest, ZkError> {
    let mut manifests = Vec::with_capacity(ZkClaimProofBundleStage::ALL.len());
    for stage in ZkClaimProofBundleStage::ALL {
        manifests.push(stage_manifest(profile, credential_hash_algorithm, *stage)?);
    }

    ProductionBundleManifest::try_from_stage_manifests(
        profile,
        credential_hash_algorithm,
        manifests,
    )
}

fn stage_proof_with_manifest_digest(
    profile: ZkClaimProofBundleKind,
    credential_hash_algorithm: Option<ZkCredentialHashAlgorithm>,
    stage: ZkClaimProofBundleStage,
    artifact_manifest_sha256: ZkArtifactManifestDigest,
) -> Result<ZkClaimProofBundleStageProof, ZkError> {
    stage_proof_with_manifest_digest_and_binding(
        profile,
        credential_hash_algorithm,
        stage,
        artifact_manifest_sha256,
        binding(7),
        [10_u8; 32],
    )
}

fn stage_proof_with_manifest_digest_and_binding(
    profile: ZkClaimProofBundleKind,
    credential_hash_algorithm: Option<ZkCredentialHashAlgorithm>,
    stage: ZkClaimProofBundleStage,
    artifact_manifest_sha256: ZkArtifactManifestDigest,
    session_binding: ZkSessionBinding,
    holder_link_commitment: [u8; 32],
) -> Result<ZkClaimProofBundleStageProof, ZkError> {
    let circuit_ref = credential_hash_algorithm
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))
        .map(|strategy| profile.source_ref(strategy, stage))?;
    let proof = ZkProof::try_from_exact_parts(
        profile.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        artifact_manifest_sha256,
        vec![stage.index().saturating_add(1)],
        public_inputs_for_circuit_and_holder(circuit_ref, session_binding, holder_link_commitment)?,
    )?;
    ZkClaimProofBundleStageProof::try_from_parts(profile, stage, proof)
}

fn bundle_with_hashes(
    profile: ZkClaimProofBundleKind,
    hashes: &[Option<ZkCredentialHashAlgorithm>],
) -> Result<ZkClaimProofBundle, ZkError> {
    bundle_with_hashes_and_binding(profile, hashes, binding(7))
}

fn bundle_with_hashes_and_binding(
    profile: ZkClaimProofBundleKind,
    hashes: &[Option<ZkCredentialHashAlgorithm>],
    session_binding: ZkSessionBinding,
) -> Result<ZkClaimProofBundle, ZkError> {
    if hashes.len() != ZkClaimProofBundleStage::ALL.len() {
        return Err(ZkError::new(ZkErrorReason::MissingStage));
    }

    let mut proofs = Vec::with_capacity(ZkClaimProofBundleStage::ALL.len());
    for (stage, credential_hash_algorithm) in ZkClaimProofBundleStage::ALL.iter().zip(hashes.iter())
    {
        proofs.push(stage_proof_with_manifest_digest_and_binding(
            profile,
            *credential_hash_algorithm,
            *stage,
            manifest_digest(),
            session_binding,
            [session_binding.nonce_hash[0]; 32],
        )?);
    }

    ZkClaimProofBundle::try_from_stage_proofs(profile, session_binding, proofs)
}

mod bundle_cases;
mod resolver;
mod suite_selection;
mod verification_policy;
