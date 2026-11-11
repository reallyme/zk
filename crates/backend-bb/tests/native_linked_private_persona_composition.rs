// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in linked regression for private-persona bundle composition.

#![cfg(feature = "native")]

#[path = "support/modern_all30.rs"]
mod modern_all30;

use modern_all30::{
    binding_from_prover_toml, generate_witness, load_circuit_evidence, read_g2,
    read_prover_g1_prefix, required_path, CircuitEvidence, MatrixError, G1_PATH_ENV, G2_PATH_ENV,
    ROOT_ENV,
};
use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with, ZkClaimProofBundleKind,
        ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver, ZkClaimProofBundleStage,
        ZkClaimProofBundleWitness, ZkPresentationBoundClaimBundleVerifier,
        ZkPresentationBoundClaimBundleVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    keys::ZkIssuerPublicKey,
    proofs::{
        ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkSessionBinding, ZkWitness,
    },
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactToolchain, Digest32, ProductionArtifactManifest,
    ProductionArtifactManifestDraft, ProductionBundleManifest,
};
use reallyme_zk_backend_bb::{
    BarretenbergArtifactResolver, BarretenbergBundleProvider, BarretenbergProverCrs,
    BbStageArtifacts, BbStageVerificationArtifacts, NativeBarretenbergBackend,
};

const FIXTURE_EXPIRY_UNIX: u64 = 1_750_000_000;
const VERIFICATION_TIME_UNIX: u64 = FIXTURE_EXPIRY_UNIX - 60;
const TWO_CREDENTIAL_ROOT_ENV: &str = "REALLYME_PRIVATE_PERSONA_TWO_CREDENTIAL_ROOT";

#[test]
#[ignore = "requires linked Barretenberg, all-circuit artifacts, and pinned BN254 CRS"]
fn linked_private_persona_same_fixture_compares_verified_session_links() -> Result<(), MatrixError>
{
    let root = required_path(ROOT_ENV)?;
    let g1_path = required_path(G1_PATH_ENV)?;
    let g2_path = required_path(G2_PATH_ENV)?;
    let g1 = read_prover_g1_prefix(&g1_path)?;
    let g2 = read_g2(&g2_path)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1.as_slice(), &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(crs)?;

    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stages = load_private_persona_stages(&root, credential_hash_algorithm)?;
    let binding = binding_from_prover_toml(
        &root,
        bundle_kind.source_ref(credential_hash_algorithm, ZkClaimProofBundleStage::Claim),
    )?;
    let witness_bundle = witness_bundle(
        &root,
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
    )?;
    let issuer = trusted_issuer(stages.as_slice(), binding)?;
    let resolver = StageResolver::try_new(bundle_kind, credential_hash_algorithm, stages)?;
    let provider = BarretenbergBundleProvider::new(backend, resolver);

    let left_bundle =
        provider.prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &witness_bundle,
            binding,
        )?)?;
    let right_bundle =
        provider.prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &witness_bundle,
            binding,
        )?)?;

    let left = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &left_bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            &issuer,
            VERIFICATION_TIME_UNIX,
        )?,
    )?;
    let right = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &right_bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            &issuer,
            VERIFICATION_TIME_UNIX,
        )?,
    )?;

    left.statement()
        .require_same_session_link(right.statement())?;

    let wrong_binding = flip_nonce(binding)?;
    expect_reason(
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &right_bundle,
            ZkProofSuite::PRODUCTION,
            wrong_binding,
            &issuer,
            VERIFICATION_TIME_UNIX,
        )
        .and_then(|request| provider.verify_presentation_bound_claim_bundle_evidence(request)),
        ZkErrorReason::BindingMismatch,
    )?;

    Ok(())
}

#[test]
#[ignore = "requires linked Barretenberg, all-circuit artifacts, pinned BN254 CRS, and current-format two-credential fixture TOMLs"]
fn linked_private_persona_distinct_hidden_subject_credentials_share_session_link(
) -> Result<(), MatrixError> {
    let root = required_path(ROOT_ENV)?;
    let fixture_root = required_path(TWO_CREDENTIAL_ROOT_ENV)?;
    let g1_path = required_path(G1_PATH_ENV)?;
    let g2_path = required_path(G2_PATH_ENV)?;
    let g1 = read_prover_g1_prefix(&g1_path)?;
    let g2 = read_g2(&g2_path)?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(g1.as_slice(), &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;
    backend.initialize_prover_crs(crs)?;

    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stages = load_private_persona_stages(&root, credential_hash_algorithm)?;
    let binding = binding_from_prover_toml_file(&fixture_root.join("session").join("Prover.toml"))?;
    let first_fixture = CredentialFixture::try_new(&fixture_root, "credential-a")?;
    let second_fixture = CredentialFixture::try_new(&fixture_root, "credential-b")?;
    let wrong_persona_fixture =
        CredentialFixture::try_new(&fixture_root.join("wrong-persona"), "credential-a")?;

    if first_fixture.subject_key == second_fixture.subject_key {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.issuer_key == second_fixture.issuer_key {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.subject_key != wrong_persona_fixture.subject_key {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.issuer_key != wrong_persona_fixture.issuer_key {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.credential_binding != wrong_persona_fixture.credential_binding {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.credential_binding == second_fixture.credential_binding {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.session_link != second_fixture.session_link {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    if first_fixture.session_link == wrong_persona_fixture.session_link {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }
    let wrong_persona_binding = binding_from_prover_toml_file(&wrong_persona_fixture.session_toml)?;
    if wrong_persona_binding != binding {
        return Err(MatrixError::UnexpectedErrorReason {
            expected: ZkErrorReason::BindingMismatch,
            actual: None,
        });
    }

    let first_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &first_fixture,
    )?;
    let second_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &second_fixture,
    )?;
    let wrong_persona_witness = witness_bundle_from_tomls(
        bundle_kind,
        credential_hash_algorithm,
        stages.as_slice(),
        &wrong_persona_fixture,
    )?;
    let trusted_issuers =
        trusted_issuers_from_fixtures([&first_fixture, &second_fixture, &wrong_persona_fixture])?;
    let resolver = StageResolver::try_new(bundle_kind, credential_hash_algorithm, stages)?;
    let provider = BarretenbergBundleProvider::new(backend, resolver);

    let first_bundle =
        provider.prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &first_witness,
            binding,
        )?)?;
    let second_bundle =
        provider.prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &second_witness,
            binding,
        )?)?;
    let wrong_persona_bundle =
        provider.prove_claim_proof_bundle(ZkClaimProofBundleProveRequest::try_new(
            bundle_kind,
            credential_hash_algorithm,
            ZkProofSuite::PRODUCTION,
            &wrong_persona_witness,
            binding,
        )?)?;

    let verification_time_unix =
        verification_time_for_fixtures([&first_fixture, &second_fixture, &wrong_persona_fixture])?;

    let first = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &first_bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            trusted_issuers.as_slice(),
            verification_time_unix,
        )?,
    )?;
    let second = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &second_bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            trusted_issuers.as_slice(),
            verification_time_unix,
        )?,
    )?;
    let wrong_persona = verify_presentation_bound_claim_bundle_with(
        &provider,
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &wrong_persona_bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            trusted_issuers.as_slice(),
            verification_time_unix,
        )?,
    )?;

    first
        .statement()
        .require_same_session_link(second.statement())?;
    expect_reason(
        first
            .statement()
            .require_same_session_link(wrong_persona.statement()),
        ZkErrorReason::BindingMismatch,
    )?;

    let wrong_binding = flip_nonce(binding)?;
    expect_reason(
        ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &second_bundle,
            ZkProofSuite::PRODUCTION,
            wrong_binding,
            trusted_issuers.as_slice(),
            verification_time_unix,
        )
        .and_then(|request| provider.verify_presentation_bound_claim_bundle_evidence(request)),
        ZkErrorReason::BindingMismatch,
    )?;

    Ok(())
}

fn load_private_persona_stages(
    root: &std::path::Path,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<Vec<CircuitEvidence>, MatrixError> {
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| MatrixError::UnexpectedLength)?;
    for stage in ZkClaimProofBundleStage::ALL {
        stages.push(load_circuit_evidence(
            root,
            ZkCircuitRef::new(
                credential_hash_algorithm,
                ZkCircuitFamily::PrivatePersonaClaimV1,
                stage.source_stage(),
            ),
        )?);
    }
    Ok(stages)
}

fn witness_bundle(
    root: &std::path::Path,
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stages: &[CircuitEvidence],
) -> Result<ZkClaimProofBundleWitness, MatrixError> {
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(stages.len())
        .map_err(|_| MatrixError::UnexpectedLength)?;
    for evidence in stages {
        witnesses.push(generate_witness(root, evidence)?);
    }
    Ok(ZkClaimProofBundleWitness::try_from_stage_witnesses(
        bundle_kind,
        credential_hash_algorithm,
        witnesses,
    )?)
}

fn witness_bundle_from_tomls(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    stages: &[CircuitEvidence],
    fixture: &CredentialFixture,
) -> Result<ZkClaimProofBundleWitness, MatrixError> {
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(stages.len())
        .map_err(|_| MatrixError::UnexpectedLength)?;
    for evidence in stages {
        let toml_path = fixture.prover_toml_for(evidence.circuit_ref.stage)?;
        witnesses.push(generate_witness_from_toml(evidence, toml_path.as_path())?);
    }
    Ok(ZkClaimProofBundleWitness::try_from_stage_witnesses(
        bundle_kind,
        credential_hash_algorithm,
        witnesses,
    )?)
}

fn generate_witness_from_toml(
    evidence: &CircuitEvidence,
    prover_toml_path: &std::path::Path,
) -> Result<ZkWitness, MatrixError> {
    use reallyme_zk_noir_witness_core::{
        generate_witness_from_artifact_json_and_toml, CompiledProgramArtifactJson,
    };

    let artifact_json =
        CompiledProgramArtifactJson::try_from_bytes(evidence.artifacts.bytecode().as_bytes())?;
    let prover_toml = std::fs::read_to_string(prover_toml_path)?;
    let witness = generate_witness_from_artifact_json_and_toml(artifact_json, &prover_toml)?;
    let witness = witness.into_zeroizing_bytes();
    Ok(ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
        evidence.circuit_ref,
        witness,
    )?)
}

fn trusted_issuer(
    stages: &[CircuitEvidence],
    binding: ZkSessionBinding,
) -> Result<[ZkIssuerPublicKey; 1], MatrixError> {
    let claim_stage = stages
        .iter()
        .find(|evidence| evidence.circuit_ref.stage == ZkCircuitStage::Claim)
        .ok_or(MatrixError::MissingField)?;
    binding.decode_and_validate(claim_stage.circuit_ref, &claim_stage.public_inputs)?;
    let issuer = issuer_from_public_inputs(claim_stage)?;
    Ok([ZkIssuerPublicKey {
        x: issuer.x,
        y: issuer.y,
    }])
}

fn trusted_issuers_from_fixtures<const N: usize>(
    fixtures: [&CredentialFixture; N],
) -> Result<Vec<ZkIssuerPublicKey>, MatrixError> {
    let mut issuers = Vec::new();
    issuers
        .try_reserve_exact(N)
        .map_err(|_| MatrixError::UnexpectedLength)?;
    for fixture in fixtures {
        if !issuers.contains(&fixture.issuer_key) {
            issuers.push(fixture.issuer_key);
        }
    }
    Ok(issuers)
}

struct PublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

fn issuer_from_public_inputs(evidence: &CircuitEvidence) -> Result<PublicKey, MatrixError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(evidence.circuit_ref)?;
    let x = read_bytes32(
        evidence.public_inputs.as_bytes(),
        descriptor.field_range(ZkPublicInputName::IssuerPublicKeyX)?,
    )?;
    let y = read_bytes32(
        evidence.public_inputs.as_bytes(),
        descriptor.field_range(ZkPublicInputName::IssuerPublicKeyY)?,
    )?;
    Ok(PublicKey { x, y })
}

fn read_bytes32(source: &[u8], range: core::ops::Range<usize>) -> Result<[u8; 32], MatrixError> {
    let bytes = source.get(range).ok_or(MatrixError::UnexpectedLength)?;
    bytes.try_into().map_err(|_| MatrixError::UnexpectedLength)
}

fn flip_nonce(mut binding: ZkSessionBinding) -> Result<ZkSessionBinding, MatrixError> {
    let first = binding
        .nonce_hash
        .first_mut()
        .ok_or(MatrixError::UnexpectedLength)?;
    *first ^= 1;
    Ok(binding)
}

#[derive(PartialEq, Eq)]
struct SubjectKey {
    x: [u8; 32],
    y: [u8; 32],
}

struct CredentialFixture {
    session_toml: std::path::PathBuf,
    envelope_toml: std::path::PathBuf,
    root_toml: std::path::PathBuf,
    claim_toml: std::path::PathBuf,
    issuer_key: ZkIssuerPublicKey,
    subject_key: SubjectKey,
    credential_binding: [u8; 32],
    session_link: [u8; 32],
    expiry_unix: u64,
}

impl CredentialFixture {
    fn try_new(root: &std::path::Path, name: &str) -> Result<Self, MatrixError> {
        let session_toml = root.join("session").join("Prover.toml");
        let credential_root = root.join(name);
        let envelope_toml = credential_root
            .join("credential_envelope")
            .join("Prover.toml");
        let root_toml = credential_root.join("credential_root").join("Prover.toml");
        let claim_toml = credential_root.join("claim").join("Prover.toml");
        for path in [&session_toml, &envelope_toml, &root_toml, &claim_toml] {
            if !path.is_file() {
                return Err(MatrixError::MissingField);
            }
        }
        let claim_source = std::fs::read_to_string(&claim_toml)?;
        let issuer_key = ZkIssuerPublicKey {
            x: parse_u8_array_32(&claim_source, "pk_issuer_x")?,
            y: parse_u8_array_32(&claim_source, "pk_issuer_y")?,
        };
        let subject_key = SubjectKey {
            x: parse_u8_array_32(&claim_source, "pk_subject_x")?,
            y: parse_u8_array_32(&claim_source, "pk_subject_y")?,
        };
        let credential_binding = parse_u8_array_32(&claim_source, "credential_binding")?;
        let session_link = parse_u8_array_32(&claim_source, "session_binding")?;
        let session_source = std::fs::read_to_string(&session_toml)?;
        let expiry_unix = parse_u64_field(&session_source, "expiry_unix")?;
        Ok(Self {
            session_toml,
            envelope_toml,
            root_toml,
            claim_toml,
            issuer_key,
            subject_key,
            credential_binding,
            session_link,
            expiry_unix,
        })
    }

    fn prover_toml_for(&self, stage: ZkCircuitStage) -> Result<std::path::PathBuf, MatrixError> {
        match stage {
            ZkCircuitStage::Session => Ok(self.session_toml.clone()),
            ZkCircuitStage::CredentialEnvelope => Ok(self.envelope_toml.clone()),
            ZkCircuitStage::CredentialRoot => Ok(self.root_toml.clone()),
            ZkCircuitStage::Claim => Ok(self.claim_toml.clone()),
            ZkCircuitStage::ClaimBundle4 => Err(MatrixError::UnexpectedLength),
            _ => Err(MatrixError::UnexpectedLength),
        }
    }
}

fn binding_from_prover_toml_file(path: &std::path::Path) -> Result<ZkSessionBinding, MatrixError> {
    let source = std::fs::read_to_string(path)?;
    Ok(ZkSessionBinding {
        nonce_hash: parse_u8_array_32(&source, "challenge")?,
        audience_hash: parse_u8_array_32(&source, "audience_hash")?,
        transaction_data_hash: Some(parse_u8_array_32(&source, "transaction_data_hash")?),
    })
}

fn verification_time_for_fixtures<const N: usize>(
    fixtures: [&CredentialFixture; N],
) -> Result<u64, MatrixError> {
    let earliest_expiry = fixtures
        .iter()
        .map(|fixture| fixture.expiry_unix)
        .min()
        .ok_or(MatrixError::MissingField)?;
    earliest_expiry
        .checked_sub(60)
        .ok_or(MatrixError::UnexpectedLength)
}

fn parse_u8_array_32(source: &str, name: &str) -> Result<[u8; 32], MatrixError> {
    let value = field_value(source, name)?;
    let body = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(MatrixError::UnexpectedLength)?;
    let mut bytes = [0_u8; 32];
    let mut count = 0_usize;
    for value in body.split(',') {
        let slot = bytes.get_mut(count).ok_or(MatrixError::UnexpectedLength)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(MatrixError::UnexpectedLength);
        }
        *slot = value
            .parse::<u8>()
            .map_err(|_| MatrixError::UnexpectedLength)?;
        count = count.checked_add(1).ok_or(MatrixError::UnexpectedLength)?;
    }
    if count != bytes.len() {
        return Err(MatrixError::UnexpectedLength);
    }
    Ok(bytes)
}

fn parse_u64_field(source: &str, name: &str) -> Result<u64, MatrixError> {
    field_value(source, name)?
        .parse::<u64>()
        .map_err(|_| MatrixError::UnexpectedLength)
}

fn field_value<'a>(source: &'a str, name: &str) -> Result<&'a str, MatrixError> {
    let mut found = None;
    for line in source.lines() {
        let candidate = line
            .split_once('#')
            .map_or(line, |(before_comment, _comment)| before_comment)
            .trim();
        if candidate.is_empty() {
            continue;
        }
        let Some((key, value)) = candidate.split_once('=') else {
            continue;
        };
        if key.trim() != name {
            continue;
        }
        if found.is_some() {
            return Err(MatrixError::AmbiguousField);
        }
        found = Some(value.trim());
    }
    found.ok_or(MatrixError::MissingField)
}

fn expect_reason(result: Result<(), ZkError>, expected: ZkErrorReason) -> Result<(), MatrixError> {
    match result {
        Ok(()) => Err(MatrixError::UnexpectedErrorReason {
            expected,
            actual: None,
        }),
        Err(error) if error.reason() == expected => Ok(()),
        Err(error) => Err(MatrixError::UnexpectedErrorReason {
            expected,
            actual: Some(error.reason()),
        }),
    }
}

struct StageMaterial {
    evidence: CircuitEvidence,
    manifest: ProductionArtifactManifest,
}

struct StageResolver {
    bundle: ProductionBundleManifest,
    stages: Vec<StageMaterial>,
}

impl StageResolver {
    fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        evidence: Vec<CircuitEvidence>,
    ) -> Result<Self, MatrixError> {
        let mut stages = Vec::new();
        stages
            .try_reserve_exact(evidence.len())
            .map_err(|_| MatrixError::UnexpectedLength)?;
        let mut manifests = Vec::new();
        manifests
            .try_reserve_exact(evidence.len())
            .map_err(|_| MatrixError::UnexpectedLength)?;
        for item in evidence {
            let manifest = manifest_for(bundle_kind, &item)?;
            manifests.push(manifest.clone());
            stages.push(StageMaterial {
                evidence: item,
                manifest,
            });
        }
        let bundle = ProductionBundleManifest::try_from_stage_manifests(
            bundle_kind,
            credential_hash_algorithm,
            manifests,
        )?;
        Ok(Self { bundle, stages })
    }

    fn material(
        &self,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<&StageMaterial, ZkError> {
        let material = self
            .stages
            .iter()
            .find(|candidate| candidate.manifest.stage() == stage)
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        if material.evidence.circuit_ref != circuit_ref
            || material.manifest.proof_suite() != proof_suite
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(material)
    }
}

impl BarretenbergArtifactResolver for StageResolver {
    fn resolve_stage_artifacts(
        &self,
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageArtifacts, ZkError> {
        if self.bundle.bundle_kind() != bundle_kind || self.bundle.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let material = self.material(stage, circuit_ref, proof_suite)?;
        BbStageArtifacts::try_new(
            material.manifest.clone(),
            material.evidence.artifacts.bytecode().clone(),
            material.evidence.artifacts.verification_key().clone(),
        )
    }

    fn resolve_stage_verification_artifacts(
        &self,
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
    ) -> Result<BbStageVerificationArtifacts, ZkError> {
        if self.bundle.bundle_kind() != bundle_kind || self.bundle.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let material = self.material(stage, circuit_ref, proof_suite)?;
        BbStageVerificationArtifacts::try_new(
            material.manifest.clone(),
            material.evidence.artifacts.verification_key().clone(),
        )
    }
}

fn manifest_for(
    bundle_kind: ZkClaimProofBundleKind,
    evidence: &CircuitEvidence,
) -> Result<ProductionArtifactManifest, ZkError> {
    let stage = production_stage(evidence.circuit_ref.stage)?;
    // The provider uses a canonical protobuf manifest. Seal that manifest
    // so its identity is the hash of the metadata actually being admitted.
    let draft = ProductionArtifactManifestDraft::try_new(
        bundle_kind,
        stage,
        evidence.circuit_ref,
        ZkProofSuite::PRODUCTION,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(evidence.circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: evidence.source_closure_sha256,
            bytecode_sha256: evidence.artifacts.bytecode().digest(),
            verification_key_sha256: evidence.artifacts.verification_key().digest(),
            capability_registry_sha256: capability_registry_digest(evidence.circuit_ref),
            vector_set_sha256: vec![Digest32::sha256(evidence.proof.proof_bytes())],
        },
    )?;
    Ok(
        reallyme_zk_proto_codec::artifact::seal_artifact_manifest(draft)?
            .into_parts()
            .0,
    )
}

fn production_stage(stage: ZkCircuitStage) -> Result<ZkClaimProofBundleStage, ZkError> {
    match stage {
        ZkCircuitStage::Session => Ok(ZkClaimProofBundleStage::Session),
        ZkCircuitStage::CredentialEnvelope => Ok(ZkClaimProofBundleStage::CredentialEnvelope),
        ZkCircuitStage::CredentialRoot => Ok(ZkClaimProofBundleStage::CredentialRoot),
        ZkCircuitStage::Claim => Ok(ZkClaimProofBundleStage::Claim),
        ZkCircuitStage::ClaimBundle4 => Err(ZkError::new(ZkErrorReason::StageMismatch)),
        _ => Err(ZkError::new(ZkErrorReason::StageMismatch)),
    }
}

fn capability_registry_digest(circuit_ref: ZkCircuitRef) -> Digest32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"reallyme-zk-api-capabilities-v1\n");
    bytes.extend_from_slice(circuit_ref.credential_hash_algorithm.as_str().as_bytes());
    bytes.extend_from_slice(b"\n");
    bytes.extend_from_slice(circuit_ref.family.as_str().as_bytes());
    bytes.extend_from_slice(b"\n");
    bytes.extend_from_slice(circuit_ref.stage.as_str().as_bytes());
    bytes.extend_from_slice(b"\n");
    Digest32::sha256(bytes.as_slice())
}
