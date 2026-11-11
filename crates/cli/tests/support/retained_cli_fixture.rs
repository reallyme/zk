// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    ffi::OsString,
    fs, io,
    io::{Read, Take},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::GzDecoder;
use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    proofs::{ZkDecodedPublicInputs, ZkProofSuite, MAX_WITNESS_BYTES},
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactToolchain, Digest32, ProductionArtifactManifestDraft,
    MAX_ACIR_BYTECODE_BYTES,
};
use reallyme_zk_backend_bb::BarretenbergPublicInputCodec;
use reallyme_zk_proto_codec::artifact::{encode_artifact_manifest, seal_artifact_manifest};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::CliTestError;

const CLI_PROVE_VERIFY_ENABLE_ENV: &str = "REALLYME_CLI_PROVE_VERIFY_RETAINED";
const CLI_PROVE_COMMAND_ENV: &str = "REALLYME_CLI_RETAINED_PROVE_COMMAND";
const CLI_PUBLIC_INPUTS_ENV: &str = "REALLYME_CLI_RETAINED_PUBLIC_INPUTS";
const CLI_SRS_COMMAND_ENV: &str = "REALLYME_CLI_RETAINED_SRS_COMMAND";
const ALL_CIRCUITS_ROOT_ENV: &str = "REALLYME_ZK_ALL_CIRCUITS_V1_ROOT";
const BYTECODE_FILE: &str = "program.acir";
const VERIFICATION_KEY_FILE: &str = "verification.key";
const WITNESS_FILE: &str = "witness.gz";
const MANIFEST_FILE: &str = "manifest.pb";
const PROVER_CRS_G1_FILE: &str = "prover-g1.dat";
const VERIFIER_CRS_G1_FILE: &str = "verifier-g1.dat";
const CRS_G2_FILE: &str = "g2.dat";
pub(super) const PROOF_FILE: &str = "proof.pb";
const VERIFIER_G1_PREFIX_BYTES: usize = 64;
const VERIFIER_G2_BYTES: usize = 128;
const FULL_PROVER_CRS_G1_PREFIX_BYTES: usize = 67_108_928;
const FULL_PROVER_CRS_POINTS: u64 = 1_048_577;

pub(super) struct RetainedCliFixturePaths {
    prove_command: PathBuf,
    public_inputs: PathBuf,
    srs_command: PathBuf,
    all_circuits_root: PathBuf,
}

impl RetainedCliFixturePaths {
    pub(super) fn from_environment() -> Option<Self> {
        std::env::var_os(CLI_PROVE_VERIFY_ENABLE_ENV)?;
        Some(Self {
            prove_command: PathBuf::from(std::env::var_os(CLI_PROVE_COMMAND_ENV)?),
            public_inputs: PathBuf::from(std::env::var_os(CLI_PUBLIC_INPUTS_ENV)?),
            srs_command: PathBuf::from(std::env::var_os(CLI_SRS_COMMAND_ENV)?),
            all_circuits_root: PathBuf::from(std::env::var_os(ALL_CIRCUITS_ROOT_ENV)?),
        })
    }
}

pub(super) struct RetainedCliFixture {
    prove: RetainedProveCommand,
    srs: RetainedSrsInitCommand,
    sources: CurrentSessionSources,
    pub(super) binding: [u8; 32],
    audience: [u8; 32],
}

impl RetainedCliFixture {
    pub(super) fn load(paths: RetainedCliFixturePaths) -> Result<Self, CliTestError> {
        let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
        let stage = ZkClaimProofBundleStage::Session;
        let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
        let prove_command = Zeroizing::new(fs::read(paths.prove_command)?);
        let prove = RetainedProveCommand::parse(prove_command.as_slice())?;
        let sources = CurrentSessionSources::load(paths.all_circuits_root)?;
        if prove.bytecode.as_slice() != sources.bbapi_bytecode.as_slice()
            || prove.witness.as_slice() != sources.bbapi_witness.as_slice()
        {
            return Err(CliTestError::UnexpectedSchema);
        }
        let srs = RetainedSrsInitCommand::parse(fs::read(paths.srs_command)?.as_slice())?;
        let public_inputs = BarretenbergPublicInputCodec::decode(
            circuit_ref,
            fs::read(paths.public_inputs)?.as_slice(),
        )?;
        let decoded = ZkDecodedPublicInputs::try_decode(circuit_ref, &public_inputs)?;
        Ok(Self {
            prove,
            srs,
            sources,
            binding: decoded.challenge(),
            audience: decoded.audience_hash(),
        })
    }

    pub(super) fn write_inputs(&self, directory: &Path) -> Result<(), CliTestError> {
        fs::write(
            directory.join(BYTECODE_FILE),
            self.sources.bytecode.as_slice(),
        )?;
        fs::write(
            directory.join(VERIFICATION_KEY_FILE),
            self.prove.verification_key.as_slice(),
        )?;
        fs::write(
            directory.join(WITNESS_FILE),
            self.sources.compressed_witness.as_slice(),
        )?;
        fs::write(
            directory.join(PROVER_CRS_G1_FILE),
            self.srs.g1_prefix.as_slice(),
        )?;
        fs::write(
            directory.join(VERIFIER_CRS_G1_FILE),
            &self.srs.g1_prefix[..VERIFIER_G1_PREFIX_BYTES],
        )?;
        fs::write(directory.join(CRS_G2_FILE), self.srs.g2_point.as_slice())?;
        fs::write(
            directory.join(MANIFEST_FILE),
            self.manifest_bytes()?.as_slice(),
        )?;
        Ok(())
    }

    fn manifest_bytes(&self) -> Result<Vec<u8>, CliTestError> {
        let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
        let stage = ZkClaimProofBundleStage::Session;
        let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
        let draft = ProductionArtifactManifestDraft::try_new(
            bundle_kind,
            stage,
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
            circuit_ref_capabilities(circuit_ref)?,
            ArtifactDigests {
                noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
                bytecode_sha256: Digest32::sha256(self.sources.bytecode.as_slice()),
                verification_key_sha256: Digest32::sha256(self.prove.verification_key.as_slice()),
                capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
                vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
            },
        )?;
        let sealed = seal_artifact_manifest(draft)?;
        encode_artifact_manifest(sealed.manifest()).map_err(CliTestError::Zk)
    }

    pub(super) fn prove_args(&self, directory: &Path) -> Vec<OsString> {
        self.prove_args_with_output(directory, &directory.join(PROOF_FILE))
    }

    fn prove_args_with_output(&self, directory: &Path, proof: &Path) -> Vec<OsString> {
        vec![
            OsString::from("reallyme-zk"),
            OsString::from("prove-stage"),
            OsString::from("--bundle-kind"),
            OsString::from("private_persona_claim_v1"),
            OsString::from("--stage"),
            OsString::from("session"),
            OsString::from("--hash-strategy"),
            OsString::from("sha256"),
            OsString::from("--manifest"),
            directory.join(MANIFEST_FILE).into_os_string(),
            OsString::from("--bytecode"),
            directory.join(BYTECODE_FILE).into_os_string(),
            OsString::from("--verification-key"),
            directory.join(VERIFICATION_KEY_FILE).into_os_string(),
            OsString::from("--witness"),
            directory.join(WITNESS_FILE).into_os_string(),
            OsString::from("--crs-g1"),
            directory.join(PROVER_CRS_G1_FILE).into_os_string(),
            OsString::from("--crs-g2"),
            directory.join(CRS_G2_FILE).into_os_string(),
            OsString::from("--nonce-hash"),
            OsString::from(hex_digest(self.binding)),
            OsString::from("--audience-hash"),
            OsString::from(hex_digest(self.audience)),
            OsString::from("--out"),
            proof.as_os_str().to_os_string(),
        ]
    }

    pub(super) fn verify_args(&self, directory: &Path) -> Vec<OsString> {
        self.verify_args_with_proof(directory, &directory.join(PROOF_FILE))
    }

    pub(super) fn verify_args_with_nonce(
        &self,
        directory: &Path,
        nonce: [u8; 32],
    ) -> Vec<OsString> {
        self.verify_args_with(directory, &directory.join(PROOF_FILE), nonce)
    }

    pub(super) fn verify_args_with_proof(&self, directory: &Path, proof: &Path) -> Vec<OsString> {
        self.verify_args_with(directory, proof, self.binding)
    }

    fn verify_args_with(&self, directory: &Path, proof: &Path, nonce: [u8; 32]) -> Vec<OsString> {
        vec![
            OsString::from("reallyme-zk"),
            OsString::from("verify-stage"),
            OsString::from("--bundle-kind"),
            OsString::from("private_persona_claim_v1"),
            OsString::from("--stage"),
            OsString::from("session"),
            OsString::from("--hash-strategy"),
            OsString::from("sha256"),
            OsString::from("--manifest"),
            directory.join(MANIFEST_FILE).into_os_string(),
            OsString::from("--verification-key"),
            directory.join(VERIFICATION_KEY_FILE).into_os_string(),
            OsString::from("--proof"),
            proof.as_os_str().to_os_string(),
            OsString::from("--crs-g1"),
            directory.join(VERIFIER_CRS_G1_FILE).into_os_string(),
            OsString::from("--crs-g2"),
            directory.join(CRS_G2_FILE).into_os_string(),
            OsString::from("--nonce-hash"),
            OsString::from(hex_digest(nonce)),
            OsString::from("--audience-hash"),
            OsString::from(hex_digest(self.audience)),
        ]
    }
}

pub(super) struct TestWorkspace {
    path: PathBuf,
}

impl TestWorkspace {
    pub(super) fn create(prefix: &str) -> Result<Self, CliTestError> {
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(CliTestError::Io(error)),
        }
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct RetainedProveCommand {
    bytecode: Vec<u8>,
    verification_key: Vec<u8>,
    witness: Zeroizing<Vec<u8>>,
}

struct CurrentSessionSources {
    bytecode: Vec<u8>,
    compressed_witness: Zeroizing<Vec<u8>>,
    bbapi_bytecode: Zeroizing<Vec<u8>>,
    bbapi_witness: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct CompiledProgramContainer {
    bytecode: String,
}

impl CurrentSessionSources {
    fn load(root: PathBuf) -> Result<Self, CliTestError> {
        let target = root
            .join("sha256")
            .join("families")
            .join("private_persona_claim_v1")
            .join("session")
            .join("target");
        let bytecode = fs::read(target.join("credential_private_persona_claim_v1_session.json"))?;
        let compressed_witness = Zeroizing::new(fs::read(
            target.join("credential_private_persona_claim_v1_session.gz"),
        )?);
        let bbapi_bytecode = decode_compiled_program_bytecode(bytecode.as_slice())?;
        let bbapi_witness =
            decode_gzip_with_limit(compressed_witness.as_slice(), MAX_WITNESS_BYTES)?;
        Ok(Self {
            bytecode,
            compressed_witness,
            bbapi_bytecode,
            bbapi_witness,
        })
    }
}

fn decode_compiled_program_bytecode(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CliTestError> {
    let container: CompiledProgramContainer =
        serde_json::from_slice(bytes).map_err(|_| CliTestError::UnexpectedSchema)?;
    if container.bytecode.is_empty() {
        return Err(CliTestError::UnexpectedSchema);
    }
    let compressed = Zeroizing::new(
        STANDARD
            .decode(container.bytecode.as_bytes())
            .map_err(|_| CliTestError::UnexpectedSchema)?,
    );
    decode_gzip_with_limit(compressed.as_slice(), MAX_ACIR_BYTECODE_BYTES)
}

fn decode_gzip_with_limit(
    compressed: &[u8],
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CliTestError> {
    if compressed.is_empty() {
        return Err(CliTestError::UnexpectedLength);
    }
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| CliTestError::LengthOverflow)?
        .checked_add(1)
        .ok_or(CliTestError::LengthOverflow)?;
    let mut decoder: Take<GzDecoder<&[u8]>> = GzDecoder::new(compressed).take(read_limit);
    let mut decoded = Zeroizing::new(Vec::new());
    decoded
        .try_reserve_exact(max_bytes.min(compressed.len()))
        .map_err(|_| CliTestError::ResourceExhausted)?;
    decoder
        .read_to_end(&mut decoded)
        .map_err(|_| CliTestError::UnexpectedSchema)?;
    if decoded.is_empty() {
        return Err(CliTestError::UnexpectedSchema);
    }
    if decoded.len() > max_bytes {
        return Err(CliTestError::UnexpectedLength);
    }
    Ok(decoded)
}

impl RetainedProveCommand {
    fn parse(bytes: &[u8]) -> Result<Self, CliTestError> {
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
                return Err(CliTestError::UnexpectedSchema);
            }
        }
        decoder.expect_end()?;
        Ok(Self {
            bytecode: bytecode.ok_or(CliTestError::MissingField)?,
            verification_key: verification_key.ok_or(CliTestError::MissingField)?,
            witness: witness.ok_or(CliTestError::MissingField)?,
        })
    }
}

struct RetainedCircuitPayload {
    bytecode: Vec<u8>,
    verification_key: Vec<u8>,
}

impl RetainedCircuitPayload {
    fn parse(decoder: &mut Decoder<'_>) -> Result<Self, CliTestError> {
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
                return Err(CliTestError::UnexpectedSchema);
            }
        }
        Ok(Self {
            bytecode: bytecode.ok_or(CliTestError::MissingField)?,
            verification_key: verification_key.ok_or(CliTestError::MissingField)?,
        })
    }
}

struct RetainedSrsInitCommand {
    g1_prefix: Vec<u8>,
    g2_point: Vec<u8>,
}

impl RetainedSrsInitCommand {
    fn parse(bytes: &[u8]) -> Result<Self, CliTestError> {
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
                    return Err(CliTestError::UnexpectedLength);
                }
                g1_prefix = Some(points);
            } else if key == b"num_points" {
                num_points = Some(decoder.read_uint()?);
            } else if key == b"g2_point" {
                let g2 = decoder.read_bin()?.to_vec();
                if g2.len() != VERIFIER_G2_BYTES {
                    return Err(CliTestError::UnexpectedLength);
                }
                g2_point = Some(g2);
            } else {
                return Err(CliTestError::UnexpectedSchema);
            }
        }
        decoder.expect_end()?;
        if num_points != Some(FULL_PROVER_CRS_POINTS) {
            return Err(CliTestError::UnexpectedSchema);
        }
        Ok(Self {
            g1_prefix: g1_prefix.ok_or(CliTestError::MissingField)?,
            g2_point: g2_point.ok_or(CliTestError::MissingField)?,
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

    fn expect_array_len(&mut self, expected: u32) -> Result<(), CliTestError> {
        if self.read_array_len()? == expected {
            Ok(())
        } else {
            Err(CliTestError::UnexpectedSchema)
        }
    }

    fn expect_str(&mut self, expected: &[u8]) -> Result<(), CliTestError> {
        if self.read_str()? == expected {
            Ok(())
        } else {
            Err(CliTestError::UnexpectedSchema)
        }
    }

    fn expect_end(&self) -> Result<(), CliTestError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CliTestError::UnexpectedSchema)
        }
    }

    fn skip_value(&mut self) -> Result<(), CliTestError> {
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
                    usize::try_from(self.read_u32()?).map_err(|_| CliTestError::LengthOverflow)?;
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
                    usize::try_from(self.read_u32()?).map_err(|_| CliTestError::LengthOverflow)?;
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
            _ => Err(CliTestError::UnexpectedSchema),
        }
    }

    fn skip_array(&mut self, count: u32) -> Result<(), CliTestError> {
        for _ in 0..count {
            self.skip_value()?;
        }
        Ok(())
    }

    fn skip_map(&mut self, count: u32) -> Result<(), CliTestError> {
        for _ in 0..count {
            self.skip_value()?;
            self.skip_value()?;
        }
        Ok(())
    }

    fn skip_exact(&mut self, count: usize) -> Result<(), CliTestError> {
        let _bytes = self.read_exact(count)?;
        Ok(())
    }

    fn read_array_len(&mut self) -> Result<u32, CliTestError> {
        let tag = self.read_u8()?;
        match tag {
            0x90..=0x9f => Ok(u32::from(tag & 0x0f)),
            0xdc => Ok(u32::from(self.read_u16()?)),
            0xdd => self.read_u32(),
            _ => Err(CliTestError::UnexpectedSchema),
        }
    }

    fn read_map_len(&mut self) -> Result<u32, CliTestError> {
        let tag = self.read_u8()?;
        match tag {
            0x80..=0x8f => Ok(u32::from(tag & 0x0f)),
            0xde => Ok(u32::from(self.read_u16()?)),
            0xdf => self.read_u32(),
            _ => Err(CliTestError::UnexpectedSchema),
        }
    }

    fn read_str(&mut self) -> Result<&'a [u8], CliTestError> {
        let tag = self.read_u8()?;
        let len = match tag {
            0xa0..=0xbf => usize::from(tag & 0x1f),
            0xd9 => usize::from(self.read_u8()?),
            0xda => usize::from(self.read_u16()?),
            0xdb => usize::try_from(self.read_u32()?).map_err(|_| CliTestError::LengthOverflow)?,
            _ => return Err(CliTestError::UnexpectedSchema),
        };
        self.read_exact(len)
    }

    fn read_bin(&mut self) -> Result<&'a [u8], CliTestError> {
        let tag = self.read_u8()?;
        let len = match tag {
            0xc4 => usize::from(self.read_u8()?),
            0xc5 => usize::from(self.read_u16()?),
            0xc6 => usize::try_from(self.read_u32()?).map_err(|_| CliTestError::LengthOverflow)?,
            _ => return Err(CliTestError::UnexpectedSchema),
        };
        self.read_exact(len)
    }

    fn read_u8(&mut self) -> Result<u8, CliTestError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, CliTestError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, CliTestError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_uint(&mut self) -> Result<u64, CliTestError> {
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
            _ => Err(CliTestError::UnexpectedSchema),
        }
    }

    fn read_exact(&mut self, count: usize) -> Result<&'a [u8], CliTestError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(CliTestError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CliTestError::UnexpectedSchema)?;
        self.offset = end;
        Ok(bytes)
    }
}

fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
