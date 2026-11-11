// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in linked Barretenberg smoke tests for the public backend API.

#![cfg(feature = "native")]

use std::{
    env, fs,
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

#[path = "support/current_session_sources.rs"]
mod current_session_sources;

use current_session_sources::CurrentSessionSources;
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::ZkError,
    proofs::{ZkDecodedPublicInputs, ZkProof, ZkProofSuite, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, Digest32,
    ProductionArtifactManifest, VerifiedArtifactBytes,
};
use reallyme_zk_backend_bb::{
    BarretenbergProverCrs, BarretenbergPublicInputCodec, BarretenbergVerifierCrs, BbStageArtifacts,
    BbStageProveRequest, BbStageVerificationArtifacts, BbStageVerifyRequest,
    LinkedBarretenbergBackend, NativeBarretenbergBackend,
};
use thiserror::Error;
use zeroize::Zeroizing;

const ENABLE_ENV: &str = "REALLYME_NATIVE_RETAINED_VERIFY";
const PROVE_ENABLE_ENV: &str = "REALLYME_NATIVE_PROVE_THEN_VERIFY";
const COMMAND_PATH_ENV: &str = "REALLYME_RETAINED_VERIFY_COMMAND";
const PROVE_COMMAND_PATH_ENV: &str = "REALLYME_RETAINED_PROVE_COMMAND";
const PROVE_PUBLIC_INPUTS_PATH_ENV: &str = "REALLYME_RETAINED_PROVE_PUBLIC_INPUTS";
const PROVER_CRS_COMMAND_PATH_ENV: &str = "REALLYME_PROVER_CRS_COMMAND";
const WRONG_VERIFICATION_KEY_PATH_ENV: &str = "REALLYME_RETAINED_WRONG_VERIFICATION_KEY";
const G1_PATH_ENV: &str = "REALLYME_BN254_G1_PATH";
const G2_PATH_ENV: &str = "REALLYME_BN254_G2_PATH";
const VERIFIER_G1_PREFIX_BYTES: usize = 64;
const VERIFIER_G2_BYTES: usize = 128;
const FULL_PROVER_CRS_G1_PREFIX_BYTES: usize = 67_108_928;
const FULL_PROVER_CRS_POINTS: u64 = 1_048_577;

#[test]
fn native_backend_verifies_retained_private_persona_session_proof() -> Result<(), SmokeError> {
    if env::var_os(ENABLE_ENV).is_none() {
        return Ok(());
    }

    let command = fs::read(required_path(COMMAND_PATH_ENV)?)?;
    let retained = RetainedVerifyCommand::parse(command.as_slice())?;
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stage = ZkClaimProofBundleStage::Session;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let public_inputs =
        BarretenbergPublicInputCodec::decode(circuit_ref, retained.public_inputs.as_slice())?;
    let decoded = ZkDecodedPublicInputs::try_decode(circuit_ref, &public_inputs)?;
    let binding = ZkSessionBinding {
        nonce_hash: decoded.challenge(),
        audience_hash: decoded.audience_hash(),
        transaction_data_hash: None,
    };
    let manifest_digest = ZkArtifactManifestDigest::from_bytes([7_u8; 32]);
    let proof = ZkProof::try_from_exact_parts(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest,
        retained.proof,
        public_inputs,
    )?;
    let verification_key_digest = Digest32::sha256(retained.verification_key.as_slice());
    let manifest = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest)?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
            bytecode_sha256: Digest32::from_bytes([2_u8; 32]),
            verification_key_sha256: verification_key_digest,
            capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
        },
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        retained.verification_key,
        verification_key_digest,
    )?;
    let artifacts = BbStageVerificationArtifacts::try_new(manifest, verification_key)?;
    let g1 = read_g1_prefix(required_path(G1_PATH_ENV)?)?;
    let g2 = read_g2(required_path(G2_PATH_ENV)?)?;
    let crs = BarretenbergVerifierCrs::try_from_pinned_slices(&g1, &g2)?;
    let backend = NativeBarretenbergBackend::try_new()?;

    backend.initialize_verifier_crs(crs)?;
    backend.verify_stage(BbStageVerifyRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        proof: &proof,
        expected_binding: binding,
    })?;

    Ok(())
}

#[test]
fn native_backend_proves_and_verifies_private_persona_session() -> Result<(), SmokeError> {
    if env::var_os(PROVE_ENABLE_ENV).is_none() {
        return Ok(());
    }

    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stage = ZkClaimProofBundleStage::Session;
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let srs_command = fs::read(required_path(PROVER_CRS_COMMAND_PATH_ENV)?)?;
    let srs = RetainedSrsInitCommand::parse(srs_command.as_slice())?;
    let crs = BarretenbergProverCrs::try_from_pinned_slices(
        srs.g1_prefix.as_slice(),
        srs.g2_point.as_slice(),
    )?;
    let prove_command = Zeroizing::new(fs::read(required_path(PROVE_COMMAND_PATH_ENV)?)?);
    let retained = RetainedProveCommand::parse(prove_command.as_slice())?;
    let sources = CurrentSessionSources::load(required_path("REALLYME_ZK_ALL_CIRCUITS_V1_ROOT")?)?;
    assert_eq!(
        retained.bytecode.as_slice(),
        sources.bbapi_bytecode.as_slice()
    );
    assert_eq!(
        retained.witness.as_slice(),
        sources.bbapi_witness.as_slice()
    );
    let expected_public_inputs = BarretenbergPublicInputCodec::decode(
        circuit_ref,
        fs::read(required_path(PROVE_PUBLIC_INPUTS_PATH_ENV)?)?.as_slice(),
    )?;
    let decoded = ZkDecodedPublicInputs::try_decode(circuit_ref, &expected_public_inputs)?;
    let binding = ZkSessionBinding {
        nonce_hash: decoded.challenge(),
        audience_hash: decoded.audience_hash(),
        transaction_data_hash: None,
    };
    let manifest_digest = ZkArtifactManifestDigest::from_bytes([7_u8; 32]);
    let bytecode_digest = Digest32::sha256(sources.bytecode.as_slice());
    let verification_key_digest = Digest32::sha256(retained.verification_key.as_slice());
    let manifest = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest)?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref)?,
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
        sources.bytecode,
        bytecode_digest,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        retained.verification_key,
        verification_key_digest,
    )?;
    let artifacts = BbStageArtifacts::try_new(manifest.clone(), bytecode, verification_key)?;
    let verification_artifacts =
        BbStageVerificationArtifacts::try_new(manifest, artifacts.verification_key().clone())?;
    let witness = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
        circuit_ref,
        sources.compressed_witness,
    )?;
    let backend = NativeBarretenbergBackend::try_new()?;

    backend.initialize_prover_crs(crs)?;
    let proved = backend.prove_stage(BbStageProveRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: binding,
    })?;
    assert_eq!(
        proved.public_inputs().as_bytes(),
        expected_public_inputs.as_bytes()
    );
    let (proof_bytes, public_inputs) = proved.into_parts();
    let proof = ZkProof::try_from_exact_bounded_parts(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest,
        proof_bytes,
        public_inputs,
    )?;
    backend.verify_stage(BbStageVerifyRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &verification_artifacts,
        proof: &proof,
        expected_binding: binding,
    })?;

    let mut wrong_binding = binding;
    let Some(first_nonce_byte) = wrong_binding.nonce_hash.first_mut() else {
        return Err(SmokeError::UnexpectedLength);
    };
    *first_nonce_byte ^= 1;
    let wrong_binding_result = backend.verify_stage(BbStageVerifyRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &verification_artifacts,
        proof: &proof,
        expected_binding: wrong_binding,
    });
    assert_eq!(
        wrong_binding_result.err().map(|error| error.reason()),
        Some(reallyme_zk_api::errors::ZkErrorReason::BindingMismatch)
    );

    let wrong_circuit_ref = bundle_kind.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Claim,
    );
    let wrong_circuit_result = backend.verify_stage(BbStageVerifyRequest {
        bundle_kind,
        stage: ZkClaimProofBundleStage::Claim,
        circuit_ref: wrong_circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &verification_artifacts,
        proof: &proof,
        expected_binding: binding,
    });
    assert_eq!(
        wrong_circuit_result.err().map(|error| error.reason()),
        Some(reallyme_zk_api::errors::ZkErrorReason::StageMismatch)
    );

    let wrong_verification_key = fs::read(required_path(WRONG_VERIFICATION_KEY_PATH_ENV)?)?;
    let wrong_verification_key_digest = Digest32::sha256(wrong_verification_key.as_slice());
    let wrong_verification_key_manifest = ProductionArtifactManifest::try_new(
        bundle_kind,
        stage,
        circuit_ref,
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest)?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref)?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
            bytecode_sha256: bytecode_digest,
            verification_key_sha256: wrong_verification_key_digest,
            capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
        },
    )?;
    let wrong_verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        wrong_verification_key,
        wrong_verification_key_digest,
    )?;
    let wrong_verification_artifacts = BbStageVerificationArtifacts::try_new(
        wrong_verification_key_manifest,
        wrong_verification_key,
    )?;
    let wrong_verification_key_result = backend.verify_stage(BbStageVerifyRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &wrong_verification_artifacts,
        proof: &proof,
        expected_binding: binding,
    });
    assert_eq!(
        wrong_verification_key_result
            .err()
            .map(|error| error.reason()),
        Some(reallyme_zk_api::errors::ZkErrorReason::InvalidProof)
    );

    let mut tampered_proof_bytes = proof.proof_bytes().to_vec();
    let first_byte = tampered_proof_bytes
        .first_mut()
        .ok_or(SmokeError::UnexpectedLength)?;
    *first_byte ^= 1;
    let tampered_public_inputs = reallyme_zk_api::proofs::ZkPublicInputs::try_copy_from_slice(
        proof.public_inputs().as_bytes(),
    )?;
    let tampered = ZkProof::try_from_exact_parts(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest,
        tampered_proof_bytes,
        tampered_public_inputs,
    )?;
    let tampered_result = backend.verify_stage(BbStageVerifyRequest {
        bundle_kind,
        stage,
        circuit_ref,
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &verification_artifacts,
        proof: &tampered,
        expected_binding: binding,
    });
    assert_eq!(
        tampered_result.err().map(|error| error.reason()),
        Some(reallyme_zk_api::errors::ZkErrorReason::InvalidProof)
    );

    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, SmokeError> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or(SmokeError::MissingEnvironment)
}

fn read_g1_prefix(path: PathBuf) -> Result<[u8; VERIFIER_G1_PREFIX_BYTES], SmokeError> {
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; VERIFIER_G1_PREFIX_BYTES];
    file.read_exact(&mut prefix)?;
    Ok(prefix)
}

fn read_g2(path: PathBuf) -> Result<[u8; VERIFIER_G2_BYTES], SmokeError> {
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|_| SmokeError::UnexpectedLength)
}

struct RetainedVerifyCommand {
    verification_key: Vec<u8>,
    public_inputs: Vec<u8>,
    proof: Vec<u8>,
}

struct RetainedProveCommand {
    bytecode: Vec<u8>,
    verification_key: Vec<u8>,
    witness: Zeroizing<Vec<u8>>,
}

impl RetainedProveCommand {
    fn parse(bytes: &[u8]) -> Result<Self, SmokeError> {
        let mut decoder = Decoder::new(bytes);
        decoder.expect_array_len(1)?;
        decoder.expect_array_len(2)?;
        decoder.expect_str(b"CircuitProve")?;
        let fields = decoder.read_map_len()?;
        let mut bytecode = None;
        let mut verification_key = None;
        let mut witness = None;
        for _ in 0..fields {
            let key = decoder.read_str()?;
            if key == b"circuit" {
                let circuit = RetainedCircuitPayload::parse(&mut decoder)?;
                bytecode = Some(circuit.bytecode);
                verification_key = Some(circuit.verification_key);
            } else if key == b"witness" {
                witness = Some(Zeroizing::new(decoder.read_bin()?.to_vec()));
            } else if key == b"settings" {
                decoder.skip_value()?;
            } else {
                return Err(SmokeError::UnexpectedSchema);
            }
        }
        decoder.expect_end()?;
        Ok(Self {
            bytecode: bytecode.ok_or(SmokeError::MissingField)?,
            verification_key: verification_key.ok_or(SmokeError::MissingField)?,
            witness: witness.ok_or(SmokeError::MissingField)?,
        })
    }
}

struct RetainedCircuitPayload {
    bytecode: Vec<u8>,
    verification_key: Vec<u8>,
}

impl RetainedCircuitPayload {
    fn parse(decoder: &mut Decoder<'_>) -> Result<Self, SmokeError> {
        let fields = decoder.read_map_len()?;
        let mut bytecode = None;
        let mut verification_key = None;
        for _ in 0..fields {
            let key = decoder.read_str()?;
            if key == b"name" {
                decoder.expect_str(b"circuit")?;
            } else if key == b"bytecode" {
                bytecode = Some(decoder.read_bin()?.to_vec());
            } else if key == b"verification_key" {
                verification_key = Some(decoder.read_bin()?.to_vec());
            } else {
                return Err(SmokeError::UnexpectedSchema);
            }
        }
        Ok(Self {
            bytecode: bytecode.ok_or(SmokeError::MissingField)?,
            verification_key: verification_key.ok_or(SmokeError::MissingField)?,
        })
    }
}

struct RetainedSrsInitCommand {
    g1_prefix: Vec<u8>,
    g2_point: Vec<u8>,
}

impl RetainedSrsInitCommand {
    fn parse(bytes: &[u8]) -> Result<Self, SmokeError> {
        let mut decoder = Decoder::new(bytes);
        decoder.expect_array_len(1)?;
        decoder.expect_array_len(2)?;
        decoder.expect_str(b"SrsInitSrs")?;
        let fields = decoder.read_map_len()?;
        let mut g1_prefix = None;
        let mut g2_point = None;
        let mut num_points = None;
        for _ in 0..fields {
            let key = decoder.read_str()?;
            if key == b"points_buf" {
                let points = decoder.read_bin()?.to_vec();
                if points.len() != FULL_PROVER_CRS_G1_PREFIX_BYTES {
                    return Err(SmokeError::UnexpectedLength);
                }
                g1_prefix = Some(points);
            } else if key == b"num_points" {
                num_points = Some(decoder.read_uint()?);
            } else if key == b"g2_point" {
                let g2 = decoder.read_bin()?.to_vec();
                if g2.len() != VERIFIER_G2_BYTES {
                    return Err(SmokeError::UnexpectedLength);
                }
                g2_point = Some(g2);
            } else {
                return Err(SmokeError::UnexpectedSchema);
            }
        }
        decoder.expect_end()?;
        if num_points != Some(FULL_PROVER_CRS_POINTS) {
            return Err(SmokeError::UnexpectedSchema);
        }
        Ok(Self {
            g1_prefix: g1_prefix.ok_or(SmokeError::MissingField)?,
            g2_point: g2_point.ok_or(SmokeError::MissingField)?,
        })
    }
}

impl RetainedVerifyCommand {
    fn parse(bytes: &[u8]) -> Result<Self, SmokeError> {
        let mut decoder = Decoder::new(bytes);
        decoder.expect_array_len(1)?;
        decoder.expect_array_len(2)?;
        decoder.expect_str(b"CircuitVerify")?;
        let fields = decoder.read_map_len()?;
        let mut verification_key = None;
        let mut public_inputs = None;
        let mut proof = None;
        for _ in 0..fields {
            let key = decoder.read_str()?;
            if key == b"verification_key" {
                verification_key = Some(decoder.read_bin()?.to_vec());
            } else if key == b"public_inputs" {
                public_inputs = Some(decoder.read_bin_array()?)
            } else if key == b"proof" {
                proof = Some(decoder.read_bin_array()?)
            } else if key == b"settings" {
                decoder.skip_value()?;
            } else {
                return Err(SmokeError::UnexpectedSchema);
            }
        }
        decoder.expect_end()?;
        Ok(Self {
            verification_key: verification_key.ok_or(SmokeError::MissingField)?,
            public_inputs: public_inputs.ok_or(SmokeError::MissingField)?,
            proof: proof.ok_or(SmokeError::MissingField)?,
        })
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_array_len(&mut self, expected: u32) -> Result<(), SmokeError> {
        if self.read_array_len()? == expected {
            Ok(())
        } else {
            Err(SmokeError::UnexpectedSchema)
        }
    }

    fn expect_str(&mut self, expected: &[u8]) -> Result<(), SmokeError> {
        if self.read_str()? == expected {
            Ok(())
        } else {
            Err(SmokeError::UnexpectedSchema)
        }
    }

    fn expect_end(&self) -> Result<(), SmokeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SmokeError::UnexpectedSchema)
        }
    }

    fn read_bin_array(&mut self) -> Result<Vec<u8>, SmokeError> {
        let count = self.read_array_len()?;
        let mut bytes = Vec::new();
        for _ in 0..count {
            let field = self.read_bin()?;
            let new_len = bytes
                .len()
                .checked_add(field.len())
                .ok_or(SmokeError::LengthOverflow)?;
            bytes
                .try_reserve_exact(field.len())
                .map_err(|_| SmokeError::ResourceExhausted)?;
            bytes.extend_from_slice(field);
            if bytes.len() != new_len {
                return Err(SmokeError::UnexpectedSchema);
            }
        }
        Ok(bytes)
    }

    fn skip_value(&mut self) -> Result<(), SmokeError> {
        let tag = self.read_u8()?;
        match tag {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => Ok(()),
            0x80..=0x8f => self.skip_map(u32::from(tag & 0x0f)),
            0x90..=0x9f => self.skip_array(u32::from(tag & 0x0f)),
            0xa0..=0xbf => self.skip_exact(usize::from(tag & 0x1f)),
            0xc4 => {
                let len = usize::from(self.read_u8()?);
                self.skip_exact(len)
            }
            0xc5 => {
                let len = usize::from(self.read_u16()?);
                self.skip_exact(len)
            }
            0xc6 => {
                let len =
                    usize::try_from(self.read_u32()?).map_err(|_| SmokeError::LengthOverflow)?;
                self.skip_exact(len)
            }
            0xcc | 0xd0 => self.skip_exact(1),
            0xcd | 0xd1 => self.skip_exact(2),
            0xce | 0xd2 => self.skip_exact(4),
            0xcf | 0xd3 => self.skip_exact(8),
            0xd9 => {
                let len = usize::from(self.read_u8()?);
                self.skip_exact(len)
            }
            0xda => {
                let len = usize::from(self.read_u16()?);
                self.skip_exact(len)
            }
            0xdb => {
                let len =
                    usize::try_from(self.read_u32()?).map_err(|_| SmokeError::LengthOverflow)?;
                self.skip_exact(len)
            }
            0xdc => {
                let len = u32::from(self.read_u16()?);
                self.skip_array(len)
            }
            0xdd => {
                let len = self.read_u32()?;
                self.skip_array(len)
            }
            0xde => {
                let len = u32::from(self.read_u16()?);
                self.skip_map(len)
            }
            0xdf => {
                let len = self.read_u32()?;
                self.skip_map(len)
            }
            _ => Err(SmokeError::UnexpectedSchema),
        }
    }

    fn skip_array(&mut self, count: u32) -> Result<(), SmokeError> {
        for _ in 0..count {
            self.skip_value()?;
        }
        Ok(())
    }

    fn skip_map(&mut self, count: u32) -> Result<(), SmokeError> {
        for _ in 0..count {
            self.skip_value()?;
            self.skip_value()?;
        }
        Ok(())
    }

    fn skip_exact(&mut self, count: usize) -> Result<(), SmokeError> {
        let _bytes = self.read_exact(count)?;
        Ok(())
    }

    fn read_array_len(&mut self) -> Result<u32, SmokeError> {
        let tag = self.read_u8()?;
        match tag {
            0x90..=0x9f => Ok(u32::from(tag & 0x0f)),
            0xdc => Ok(u32::from(self.read_u16()?)),
            0xdd => self.read_u32(),
            _ => Err(SmokeError::UnexpectedSchema),
        }
    }

    fn read_map_len(&mut self) -> Result<u32, SmokeError> {
        let tag = self.read_u8()?;
        match tag {
            0x80..=0x8f => Ok(u32::from(tag & 0x0f)),
            0xde => Ok(u32::from(self.read_u16()?)),
            0xdf => self.read_u32(),
            _ => Err(SmokeError::UnexpectedSchema),
        }
    }

    fn read_str(&mut self) -> Result<&'a [u8], SmokeError> {
        let tag = self.read_u8()?;
        let len = match tag {
            0xa0..=0xbf => usize::from(tag & 0x1f),
            0xd9 => usize::from(self.read_u8()?),
            0xda => usize::from(self.read_u16()?),
            0xdb => usize::try_from(self.read_u32()?).map_err(|_| SmokeError::LengthOverflow)?,
            _ => return Err(SmokeError::UnexpectedSchema),
        };
        self.read_exact(len)
    }

    fn read_bin(&mut self) -> Result<&'a [u8], SmokeError> {
        let tag = self.read_u8()?;
        let len = match tag {
            0xc4 => usize::from(self.read_u8()?),
            0xc5 => usize::from(self.read_u16()?),
            0xc6 => usize::try_from(self.read_u32()?).map_err(|_| SmokeError::LengthOverflow)?,
            _ => return Err(SmokeError::UnexpectedSchema),
        };
        self.read_exact(len)
    }

    fn read_u8(&mut self) -> Result<u8, SmokeError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, SmokeError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, SmokeError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_uint(&mut self) -> Result<u64, SmokeError> {
        let tag = self.read_u8()?;
        match tag {
            0x00..=0x7f => Ok(u64::from(tag)),
            0xcc => Ok(u64::from(self.read_u8()?)),
            0xcd => Ok(u64::from(self.read_u16()?)),
            0xce => Ok(u64::from(self.read_u32()?)),
            0xcf => {
                let bytes = self.read_exact(8)?;
                Ok(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            _ => Err(SmokeError::UnexpectedSchema),
        }
    }

    fn read_exact(&mut self, count: usize) -> Result<&'a [u8], SmokeError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(SmokeError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(SmokeError::UnexpectedSchema)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[derive(Debug, Error)]
enum SmokeError {
    #[error("missing smoke-test environment")]
    MissingEnvironment,
    #[error("unexpected retained fixture schema")]
    UnexpectedSchema,
    #[error("missing retained fixture field")]
    MissingField,
    #[error("unexpected retained fixture length")]
    UnexpectedLength,
    #[error("length overflow")]
    LengthOverflow,
    #[error("resource exhausted")]
    ResourceExhausted,
    #[error("io failure")]
    Io(#[from] io::Error),
    #[error("zk failure")]
    Zk(#[from] ZkError),
}
