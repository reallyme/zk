// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{env, fs, path::PathBuf};

use buffa::DecodeOptions;
use reallyme_zk_api::{
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::ZkErrorReason,
};
use reallyme_zk_platform_ffi::{
    reallyme_zk_platform_context_create, reallyme_zk_platform_context_destroy,
    ReallyMeZkPlatformContext, REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::platform_abi::REALLYME_ZK_PLATFORM_STATUS_OK;

const DEMO_FIXTURES_REQUIRED_ENV: &str = "REALLYME_ZK_PLATFORM_DEMO_FIXTURES_REQUIRED";
const DEMO_ASSET_ROOT_ENV: &str = "REALLYME_ZK_DEMO_ASSET_ROOT";
const RELEASE_INDEX_SHA256_HEX: &str =
    "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7";
const VERIFIER_CRS_G2_BYTES: usize = 128;
const DEFAULT_ZK_DEMO_RELATIVE_ROOT: &str = "build/native/ios-demo-resources/zk_demo";

#[derive(Clone, Copy)]
pub(crate) struct DemoProfile {
    pub(crate) fixture_name: &'static str,
    pub(crate) family: pb::ZkCircuitFamily,
    pub(crate) bundle_kind: pb::ZkClaimProofBundleKind,
    pub(crate) domain_profile: ZkClaimProofBundleKind,
}

impl DemoProfile {
    pub(crate) const ALL: [Self; 2] = [
        Self {
            fixture_name: "credential_subject_claim_v1",
            family: pb::ZkCircuitFamily::CredentialSubjectClaimV1,
            bundle_kind: pb::ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            domain_profile: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        },
        Self {
            fixture_name: "private_persona_claim_v1",
            family: pb::ZkCircuitFamily::PrivatePersonaClaimV1,
            bundle_kind: pb::ZkClaimProofBundleKind::PrivatePersonaClaimV1,
            domain_profile: ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        },
    ];

    pub(crate) const fn domain_profile(self) -> ZkClaimProofBundleKind {
        self.domain_profile
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DemoStage {
    pub(crate) fixture_name: &'static str,
    pub(crate) circuit_stage: pb::ZkCircuitStage,
    pub(crate) production_stage: ZkClaimProofBundleStage,
}

impl DemoStage {
    pub(crate) const ALL: [Self; 4] = [
        Self {
            fixture_name: "session",
            circuit_stage: pb::ZkCircuitStage::Session,
            production_stage: ZkClaimProofBundleStage::Session,
        },
        Self {
            fixture_name: "credential_envelope",
            circuit_stage: pb::ZkCircuitStage::CredentialEnvelope,
            production_stage: ZkClaimProofBundleStage::CredentialEnvelope,
        },
        Self {
            fixture_name: "credential_root",
            circuit_stage: pb::ZkCircuitStage::CredentialRoot,
            production_stage: ZkClaimProofBundleStage::CredentialRoot,
        },
        Self {
            fixture_name: "claim",
            circuit_stage: pb::ZkCircuitStage::Claim,
            production_stage: ZkClaimProofBundleStage::Claim,
        },
    ];
}

pub(crate) enum TestError {
    BufferDestroy,
    ContextCreate {
        status_code: u32,
        error_reason_code: u32,
    },
    Decode,
    DemoAssetsMissing,
    DispatchStatus,
    Domain(ZkErrorReason),
    EmptyResponse,
    EncodeProof,
    Hex,
    Io,
    Provider(ZkErrorReason),
    UnexpectedResponse,
    Fixture {
        bundle_kind: &'static str,
        stage: &'static str,
        operation: &'static str,
        cause: Box<TestError>,
    },
    CommonCredentialRootStageFixture {
        lane: &'static str,
        mode: &'static str,
        slot: u8,
        operation: &'static str,
        cause: Box<TestError>,
    },
}

impl core::fmt::Debug for TestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Provider(reason) => formatter.debug_tuple("Provider").field(reason).finish(),
            Self::BufferDestroy => formatter.write_str("BufferDestroy"),
            Self::ContextCreate {
                status_code,
                error_reason_code,
            } => formatter
                .debug_struct("ContextCreate")
                .field("status_code", status_code)
                .field("error_reason_code", error_reason_code)
                .finish(),
            Self::Decode => formatter.write_str("Decode"),
            Self::DemoAssetsMissing => formatter.write_str("DemoAssetsMissing"),
            Self::DispatchStatus => formatter.write_str("DispatchStatus"),
            Self::Domain(reason) => formatter.debug_tuple("Domain").field(reason).finish(),
            Self::EmptyResponse => formatter.write_str("EmptyResponse"),
            Self::EncodeProof => formatter.write_str("EncodeProof"),
            Self::Hex => formatter.write_str("Hex"),
            Self::Io => formatter.write_str("Io"),
            Self::UnexpectedResponse => formatter.write_str("UnexpectedResponse"),
            Self::Fixture {
                bundle_kind,
                stage,
                operation,
                cause,
            } => formatter
                .debug_struct("Fixture")
                .field("bundle_kind", bundle_kind)
                .field("stage", stage)
                .field("operation", operation)
                .field("cause", cause)
                .finish(),
            Self::CommonCredentialRootStageFixture {
                lane,
                mode,
                slot,
                operation,
                cause,
            } => formatter
                .debug_struct("CommonCredentialRootStageFixture")
                .field("lane", lane)
                .field("mode", mode)
                .field("slot", slot)
                .field("operation", operation)
                .field("cause", cause)
                .finish(),
        }
    }
}

pub(crate) struct DemoPaths {
    artifact_root: PathBuf,
    fixture_root: PathBuf,
    release_index: PathBuf,
    crs_g1: PathBuf,
    crs_g2: PathBuf,
}

impl DemoPaths {
    pub(crate) fn discover() -> Result<Option<Self>, TestError> {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .ok_or(TestError::Io)?
            .to_path_buf();
        let demo_root = demo_asset_root(&repo);
        let required = demo_assets_required();
        if !demo_root.exists() {
            return if required {
                Err(TestError::DemoAssetsMissing)
            } else {
                Ok(None)
            };
        }
        Ok(Some(Self {
            artifact_root: demo_root.join("artifacts"),
            fixture_root: repo.join("vectors/demo-flow-inputs/v1"),
            release_index: demo_root.join("release-index.pb"),
            crs_g1: demo_root.join("crs/bn254_g1.prover"),
            crs_g2: demo_root.join("crs/bn254_g2"),
        }))
    }

    pub(crate) fn read_fixture(
        &self,
        bundle_kind: DemoProfile,
        stage: DemoStage,
    ) -> Result<pb::ZkStageWitnessInput, TestError> {
        let path = self.fixture_root.join(format!(
            "sha256_flow_{}_{}_inputs.pb",
            bundle_kind.fixture_name, stage.fixture_name
        ));
        let fixture = fs::read(path).map_err(|_| TestError::Io)?;
        DecodeOptions::new()
            .decode_from_slice::<pb::ZkStageWitnessInput>(&fixture)
            .map_err(|_| TestError::Decode)
    }
}

fn demo_asset_root(repo: &std::path::Path) -> PathBuf {
    match env::var_os(DEMO_ASSET_ROOT_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => repo.join(DEFAULT_ZK_DEMO_RELATIVE_ROOT),
    }
}

fn demo_assets_required() -> bool {
    matches!(
        env::var(DEMO_FIXTURES_REQUIRED_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

pub(crate) enum CrsMode {
    FullProver,
}

impl CrsMode {
    const fn ffi_value(&self) -> u32 {
        match self {
            Self::FullProver => REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER,
        }
    }
}

pub(crate) struct PlatformContextGuard {
    context: *mut ReallyMeZkPlatformContext,
}

impl PlatformContextGuard {
    pub(crate) fn create(paths: &DemoPaths, crs_mode: CrsMode) -> Result<Self, TestError> {
        let artifact_root = paths.artifact_root.as_os_str().as_encoded_bytes();
        let release_index = fs::read(&paths.release_index).map_err(|_| TestError::Io)?;
        let release_index_sha256 = hex_to_digest(RELEASE_INDEX_SHA256_HEX)?;
        let crs_g1 = match crs_mode {
            CrsMode::FullProver => fs::read(&paths.crs_g1).map_err(|_| TestError::Io)?,
        };
        let crs_g2 = fs::read(&paths.crs_g2).map_err(|_| TestError::Io)?;
        if crs_g2.len() != VERIFIER_CRS_G2_BYTES {
            return Err(TestError::Io);
        }
        let result = unsafe {
            reallyme_zk_platform_context_create(
                artifact_root.as_ptr(),
                artifact_root.len(),
                release_index.as_ptr(),
                release_index.len(),
                release_index_sha256.as_ptr(),
                release_index_sha256.len(),
                crs_g1.as_ptr(),
                crs_g1.len(),
                crs_g2.as_ptr(),
                crs_g2.len(),
                crs_mode.ffi_value(),
            )
        };
        if result.status_code != REALLYME_ZK_PLATFORM_STATUS_OK || result.context.is_null() {
            return Err(TestError::ContextCreate {
                status_code: result.status_code,
                error_reason_code: result.error_reason_code,
            });
        }
        Ok(Self {
            context: result.context,
        })
    }

    pub(crate) const fn as_ptr(&self) -> *mut ReallyMeZkPlatformContext {
        self.context
    }
}

impl Drop for PlatformContextGuard {
    fn drop(&mut self) {
        let _status = unsafe { reallyme_zk_platform_context_destroy(self.context) };
    }
}

pub(super) fn hex_to_digest(value: &str) -> Result<[u8; 32], TestError> {
    if value.len() != 64 {
        return Err(TestError::Hex);
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex(chunk[0])?;
        let low = decode_hex(chunk[1])?;
        output[index] = high
            .checked_mul(16)
            .and_then(|prefix| prefix.checked_add(low))
            .ok_or(TestError::Hex)?;
    }
    Ok(output)
}

fn decode_hex(byte: u8) -> Result<u8, TestError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TestError::Hex),
    }
}
