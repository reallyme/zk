// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    parse_arguments, parse_sha256, validate_attested_release_index, ArtifactPackageError,
    ArtifactPackageErrorReason, Digest32, OsString, SHA256_BYTES, SHA256_HEX_BYTES,
};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{ArtifactToolchain, ArtifactVersion};
use reallyme_zk_proto_codec::{
    capability_registry::build_capability_registry,
    release::{ReleaseArtifactPin, ReleaseIndex, ReleaseVerificationVectorPin},
};

#[test]
fn parser_requires_exact_argument_count() {
    let missing = [OsString::from("binary")];
    let digest = "0".repeat(SHA256_HEX_BYTES);
    let extra = vec![
        OsString::from("binary"),
        OsString::from("artifacts"),
        OsString::from("0.1.0"),
        OsString::from(digest),
        OsString::from("extra"),
    ];

    assert_eq!(
        parse_arguments(missing).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::InvalidArguments)
    );
    assert_eq!(
        parse_arguments(extra).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::InvalidArguments)
    );
}

#[test]
fn digest_parser_accepts_exact_lowercase_sha256() -> Result<(), ArtifactPackageError> {
    let expected = [0xab_u8; SHA256_BYTES];
    assert_eq!(
        parse_sha256(&"ab".repeat(SHA256_BYTES))?,
        Digest32::from_bytes(expected)
    );
    Ok(())
}

#[test]
fn digest_parser_rejects_wrong_length_uppercase_and_non_hex() {
    let uppercase = "AB".repeat(SHA256_BYTES);
    let non_hex = "gg".repeat(SHA256_BYTES);
    for value in ["00", uppercase.as_str(), non_hex.as_str()] {
        assert_eq!(
            parse_sha256(value).err().map(|error| error.reason()),
            Some(ArtifactPackageErrorReason::InvalidArguments)
        );
    }
}

#[test]
fn attested_index_requires_modern_toolchain_and_current_registry(
) -> Result<(), ArtifactPackageError> {
    let current_registry = build_capability_registry()?.sha256();
    let valid = release_index("1.0.0", "6.0.0", current_registry)?;
    validate_attested_release_index(&valid)?;

    let legacy_toolchain = release_index("1.0.0-beta.9", "0.87.0", current_registry)?;
    assert_eq!(
        validate_attested_release_index(&legacy_toolchain)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );

    let stale_registry = release_index("1.0.0", "6.0.0", digest(240))?;
    assert_eq!(
        validate_attested_release_index(&stale_registry)
            .err()
            .map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::PackageMismatch)
    );
    Ok(())
}

fn release_index(
    nargo_version: &str,
    barretenberg_version: &str,
    capability_registry_sha256: Digest32,
) -> Result<ReleaseIndex, ArtifactPackageError> {
    Ok(ReleaseIndex::try_new(
        ArtifactVersion::try_from_token("0.1.0")?,
        ArtifactToolchain::try_from_versions(nargo_version, barretenberg_version)?,
        ZkProofSuite::PRODUCTION,
        capability_registry_sha256,
        artifact_pins()?,
        vector_pins()?,
    )?)
}

fn artifact_pins() -> Result<Vec<ReleaseArtifactPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(
        ZkCredentialHashAlgorithm::ALL.len()
            * ZkClaimProofBundleKind::ALL.len()
            * ZkClaimProofBundleStage::ALL.len(),
    )
    .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut marker = 1_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            for stage in ZkClaimProofBundleStage::ALL {
                pins.push(ReleaseArtifactPin::try_new(
                    *bundle_kind,
                    *stage,
                    bundle_kind.source_ref(*credential_hash_algorithm, *stage),
                    ZkArtifactManifestDigest::from_bytes(*digest(marker).as_bytes()),
                )?);
                marker = marker
                    .checked_add(1)
                    .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            }
        }
    }
    Ok(pins)
}

fn vector_pins() -> Result<Vec<ReleaseVerificationVectorPin>, ZkError> {
    let mut pins = Vec::new();
    pins.try_reserve_exact(
        ZkCredentialHashAlgorithm::ALL.len() * ZkClaimProofBundleKind::ALL.len(),
    )
    .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut marker = 64_u8;
    for credential_hash_algorithm in ZkCredentialHashAlgorithm::ALL {
        for bundle_kind in ZkClaimProofBundleKind::ALL {
            pins.push(ReleaseVerificationVectorPin::try_new(
                *bundle_kind,
                *credential_hash_algorithm,
                ZkProofSuite::PRODUCTION,
                digest(marker),
                1,
            )?);
            marker = marker
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    Ok(pins)
}

fn digest(marker: u8) -> Digest32 {
    Digest32::from_bytes([marker; SHA256_BYTES])
}
