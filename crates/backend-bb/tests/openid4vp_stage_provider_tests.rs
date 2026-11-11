// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VP-facing evidence for the Barretenberg stage provider.

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::{circuit_ref_capabilities, ZkCircuitCapabilities},
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkCompatibilitySuiteAcknowledgement,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProofSuite, ZkProveRequest, ZkProver, ZkPublicInputDescriptor, ZkPublicInputName,
        ZkPublicInputs, ZkSessionBinding, ZkWitness,
    },
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, Digest32,
    ProductionArtifactManifest, VerifiedArtifactBytes,
};
use reallyme_zk_backend_bb::{
    BarretenbergArtifactResolver, BarretenbergStageProvider,
    BbCommonCredentialRootRawVerifyRequest, BbStageArtifacts, BbStageProveRequest,
    BbStageProveResponse, BbStageVerifyRequest, LinkedBarretenbergBackend,
};

#[test]
fn diagnostic_stage_proving_uses_backend_bb_artifact_provider() -> Result<(), TestError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let provider = BarretenbergStageProvider::new(
        BindingAwareBackend,
        StaticArtifactResolver,
        bundle_kind,
        credential_hash_algorithm,
        stage,
    );
    let binding = test_session_binding(None);
    let public_inputs = public_inputs_for_binding(circuit_ref, binding)?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9, 8, 7])?;

    let request = ZkProveRequest::try_new(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )?;
    let proof = provider.prove(request)?;

    assert_eq!(proof.circuit_id(), bundle_kind.circuit_id());
    assert_eq!(proof.circuit_ref(), circuit_ref);
    Ok(())
}

#[test]
fn openid4vp_rejects_transaction_binding_mismatch_before_backend_use() -> Result<(), TestError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let binding = test_session_binding(Some([7; 32]));
    let public_inputs = public_inputs_for_binding(circuit_ref, test_session_binding(None))?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9, 8, 7])?;

    let err = ZkProveRequest::try_new(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )
    .err()
    .ok_or(TestError::Zk(ZkError::new(ZkErrorReason::BackendFailure)))?;

    assert_eq!(err.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn openid4vp_rejects_cross_circuit_witness_before_backend_use() -> Result<(), TestError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let binding = test_session_binding(None);
    let public_inputs = public_inputs_for_binding(circuit_ref, binding)?;
    let wrong_ref =
        bundle_kind.source_ref(credential_hash_algorithm, ZkClaimProofBundleStage::Session);
    let witness = ZkWitness::try_from_noir_witness_stack_v1(wrong_ref, vec![9, 8, 7])?;

    let error = ZkProveRequest::try_new(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )
    .err()
    .ok_or(TestError::Zk(ZkError::new(ZkErrorReason::BackendFailure)))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn stage_provider_rejects_resolver_coordinate_substitution_before_backend_use(
) -> Result<(), TestError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let provider = BarretenbergStageProvider::new(
        BindingAwareBackend,
        WrongCoordinateResolver,
        bundle_kind,
        credential_hash_algorithm,
        stage,
    );
    let binding = test_session_binding(None);
    let public_inputs = public_inputs_for_binding(circuit_ref, binding)?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9, 8, 7])?;

    let request = ZkProveRequest::try_new(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )?;
    let error = provider
        .prove(request)
        .err()
        .ok_or(TestError::Zk(ZkError::new(ZkErrorReason::BackendFailure)))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn stage_provider_rejects_backend_public_input_substitution_after_prove() -> Result<(), TestError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let stage = ZkClaimProofBundleStage::Claim;
    let circuit_ref = bundle_kind.source_ref(credential_hash_algorithm, stage);
    let provider = BarretenbergStageProvider::new(
        AlteredPublicInputBackend,
        StaticArtifactResolver,
        bundle_kind,
        credential_hash_algorithm,
        stage,
    );
    let binding = test_session_binding(None);
    let public_inputs = public_inputs_for_binding(circuit_ref, binding)?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9, 8, 7])?;

    let request = ZkProveRequest::try_new(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )?;
    let error = provider
        .prove(request)
        .err()
        .ok_or(TestError::Zk(ZkError::new(ZkErrorReason::BackendFailure)))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct BindingAwareBackend;

#[derive(Debug, Clone, Copy)]
struct AlteredPublicInputBackend;

impl LinkedBarretenbergBackend for BindingAwareBackend {
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        proof_suite == ZkProofSuite::PRODUCTION
    }

    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        if request.witness.expose_bytes().is_empty()
            || request.artifacts.bytecode().as_bytes().is_empty()
        {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        let public_inputs =
            public_inputs_for_binding(request.circuit_ref, request.session_binding)?;

        BbStageProveResponse::try_from_compact_bytes(
            request.circuit_ref,
            vec![request.stage.index().saturating_add(1)],
            public_inputs.into_bytes(),
        )
    }

    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        if request.artifacts.verification_key().as_bytes().is_empty() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        request
            .expected_binding
            .decode_and_validate(request.circuit_ref, request.proof.public_inputs())?;

        Ok(())
    }

    fn verify_common_credential_root_raw(
        &self,
        _request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        Err(ZkError::new(ZkErrorReason::UnsupportedCircuit))
    }
}

impl LinkedBarretenbergBackend for AlteredPublicInputBackend {
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        proof_suite == ZkProofSuite::PRODUCTION
    }

    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        if request.witness.expose_bytes().is_empty()
            || request.artifacts.bytecode().as_bytes().is_empty()
        {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        let mut public_inputs =
            public_inputs_for_binding(request.circuit_ref, request.session_binding)?.into_bytes();
        write_public_input(
            public_inputs.as_mut_slice(),
            ZkPublicInputDescriptor::for_circuit(request.circuit_ref)?,
            ZkPublicInputName::ExpiryUnix,
            &43_u64.to_be_bytes(),
        )?;

        BbStageProveResponse::try_from_compact_bytes(
            request.circuit_ref,
            vec![request.stage.index().saturating_add(1)],
            public_inputs,
        )
    }

    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        BindingAwareBackend.verify_stage(request)
    }

    fn verify_common_credential_root_raw(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        BindingAwareBackend.verify_common_credential_root_raw(request)
    }
}

#[derive(Debug, Clone, Copy)]
struct StaticArtifactResolver;

#[derive(Debug, Clone, Copy)]
struct WrongCoordinateResolver;

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([8_u8; 32])
}

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

fn manifest_for_suite(
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

impl BarretenbergArtifactResolver for StaticArtifactResolver {
    fn resolve_stage_artifacts(
        &self,
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError> {
        let bytecode_bytes = artifact_bytes(bundle_kind, stage, 40)?;
        let verification_key_bytes = artifact_bytes(bundle_kind, stage, 80)?;
        let digests = ArtifactDigests {
            noir_source_sha256: Digest32::sha256(&[1_u8]),
            bytecode_sha256: Digest32::sha256(bytecode_bytes.as_slice()),
            verification_key_sha256: Digest32::sha256(verification_key_bytes.as_slice()),
            capability_registry_sha256: Digest32::sha256(&[2_u8]),
            vector_set_sha256: vec![Digest32::sha256(&[3_u8])],
        };
        let capabilities = circuit_ref_capabilities(circuit_ref)?;
        let manifest = manifest_for_suite(
            bundle_kind,
            stage,
            circuit_ref,
            proof_suite,
            ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
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

impl BarretenbergArtifactResolver for WrongCoordinateResolver {
    fn resolve_stage_artifacts(
        &self,
        _profile: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError> {
        let wrong_profile = if circuit_ref.family
            == reallyme_zk_api::circuits::ZkCircuitFamily::CredentialSubjectClaimV1
        {
            ZkClaimProofBundleKind::PrivatePersonaClaimV1
        } else {
            ZkClaimProofBundleKind::CredentialSubjectClaimV1
        };
        let wrong_ref = wrong_profile.source_ref(circuit_ref.credential_hash_algorithm, stage);
        StaticArtifactResolver.resolve_stage_artifacts(wrong_profile, stage, wrong_ref, proof_suite)
    }
}

fn public_inputs_for_binding(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
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
        (ZkPublicInputName::SessionBinding, [10_u8; 32]),
        (ZkPublicInputName::EnvelopeBinding, [11_u8; 32]),
        (ZkPublicInputName::CredentialBinding, [12_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    ZkPublicInputs::try_from_bytes(bytes)
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

fn test_session_binding(transaction_data_hash: Option<[u8; 32]>) -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1; 32],
        audience_hash: [2; 32],
        transaction_data_hash,
    }
}

fn artifact_bytes(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    offset: u8,
) -> Result<Vec<u8>, ZkError> {
    let profile_byte = profile_marker(bundle_kind)
        .checked_add(offset)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let stage_byte = stage
        .index()
        .checked_add(offset)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;

    Ok(vec![profile_byte, stage_byte])
}

fn profile_marker(bundle_kind: ZkClaimProofBundleKind) -> u8 {
    match bundle_kind {
        ZkClaimProofBundleKind::CredentialSubjectClaimV1 => 1,
        ZkClaimProofBundleKind::PrivatePersonaClaimV1 => 2,
        _ => 0,
    }
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("zk")]
    Zk(#[from] ZkError),
}
