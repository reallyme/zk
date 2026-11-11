// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn ensure_directory_not_symlink(path: &Path) -> Result<(), ZkError> {
    let metadata = fs::symlink_metadata(path).map_err(map_filesystem_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(())
}

#[cfg(feature = "diagnostic-exact-source")]
fn single_program_json_path(target_dir: &Path) -> Result<PathBuf, ZkError> {
    ensure_directory_not_symlink(target_dir)?;
    let mut found = None;
    for entry in fs::read_dir(target_dir).map_err(map_filesystem_error)? {
        let entry = entry.map_err(map_filesystem_error)?;
        let file_type = entry.file_type().map_err(map_filesystem_error)?;
        if file_type.is_symlink() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if found.is_some() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        found = Some(path);
    }
    found.ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))
}

#[cfg(feature = "diagnostic-exact-source")]
pub(crate) fn trusted_claim_bundle4_artifact_identity(
    circuit_ref: ZkCircuitRef,
) -> Result<ZkArtifactSetIdentity, ZkError> {
    let digest = match (
        circuit_ref.credential_hash_algorithm,
        circuit_ref.family,
        circuit_ref.stage,
    ) {
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => "9467e576da1a34d93bf2e0fa7fe03bc4b00e3301e24d3406d344d1850ebd9df0",
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => "812bc53518d948993aa9f60b2e39fbbbfb7bcd0f5c164ee7874d8a952def7bf3",
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => "e4f0849a019a5b5806607445a3cf7a2f45702d5d8ec27da4e0909efa7213815b",
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => "5bd0553e915735e122d845c22af86bfa2e57600b1ee3336cd70830b8c65ceca9",
        _ => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    };
    let digest = parse_digest32(digest)?;
    Ok(ZkArtifactSetIdentity::from_bytes(*digest.as_bytes()))
}

#[cfg(feature = "diagnostic-exact-source")]
fn exact_source_artifact_identity(
    circuit_ref: ZkCircuitRef,
    source_closure_sha256: Digest32,
    bytecode_sha256: Digest32,
    verification_key_sha256: Digest32,
) -> Result<ZkArtifactSetIdentity, ZkError> {
    let circuit_name = exact_source_circuit_name(circuit_ref);
    let capacity = EXACT_SOURCE_ARTIFACT_IDENTITY_DOMAIN
        .len()
        .checked_add(circuit_name.len())
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(ZkProofSuite::PRODUCTION.as_str().len()))
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(96))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut material = Vec::new();
    material
        .try_reserve_exact(capacity)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    material.extend_from_slice(EXACT_SOURCE_ARTIFACT_IDENTITY_DOMAIN);
    material.extend_from_slice(circuit_name.as_bytes());
    material.extend_from_slice(b"\n");
    material.extend_from_slice(ZkProofSuite::PRODUCTION.as_str().as_bytes());
    material.extend_from_slice(b"\n");
    material.extend_from_slice(source_closure_sha256.as_bytes());
    material.extend_from_slice(bytecode_sha256.as_bytes());
    material.extend_from_slice(verification_key_sha256.as_bytes());
    Ok(ZkArtifactSetIdentity::from_bytes(
        *Digest32::sha256(material.as_slice()).as_bytes(),
    ))
}

#[cfg(feature = "diagnostic-exact-source")]
fn exact_source_circuit_dir(root: &Path, circuit_ref: ZkCircuitRef) -> PathBuf {
    root.join(circuit_ref.credential_hash_algorithm.source_dir())
        .join("families")
        .join(circuit_ref.family.source_dir())
        .join(circuit_ref.stage.source_dir())
}

#[cfg(feature = "diagnostic-exact-source")]
fn exact_source_circuit_name(circuit_ref: ZkCircuitRef) -> String {
    [
        circuit_ref.credential_hash_algorithm.source_dir(),
        "families",
        circuit_ref.family.source_dir(),
        circuit_ref.stage.source_dir(),
    ]
    .join("/")
}

#[cfg(feature = "diagnostic-exact-source")]
fn parse_digest32(value: &str) -> Result<Digest32, ZkError> {
    if value.len() != 64 {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    let mut bytes = [0_u8; 32];
    let (chunks, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Digest32::from_bytes(bytes))
}

#[cfg(feature = "diagnostic-exact-source")]
fn hex_nibble(value: u8) -> Result<u8, ZkError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ZkError::new(ZkErrorReason::ArtifactMismatch)),
    }
}

#[cfg(feature = "diagnostic-exact-source")]
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
