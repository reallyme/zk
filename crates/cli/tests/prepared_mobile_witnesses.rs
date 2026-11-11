// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks the staged demo's synthetic requests against fresh pinned Noir output.

use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceSourceStage},
    proofs::{ZkProofSuite, MAX_WITNESS_BYTES},
};
use reallyme_zk_proto_codec::operation::{decode_operation_request, ZkProviderOperation};
use zeroize::Zeroizing;

const REQUEST_OVERHEAD_BYTES: usize = 1024;
const EXPECTED_WITNESS_COUNT: usize = 20;
const COMPARE_CHUNK_BYTES: usize = 8192;

#[test]
#[ignore = "requires a fresh Nargo prepared witness for each demo stage"]
fn demo_prepared_requests_match_current_noir_witnesses() -> Result<(), ZkError> {
    let table = env::var_os("REALLYME_PREPARED_LINKED_EVIDENCE")
        .ok_or(ZkError::new(ZkErrorReason::BackendUnavailable))?;
    let table = fs::read_to_string(table).map_err(|_| invalid_encoding())?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/persona-credential-evidence-mobile-requests-v1");
    let mut checked = BTreeSet::new();
    for row in table.lines() {
        let fields: Vec<_> = row.split('\t').collect();
        let [lane, mode_name, stage_name, _, _, _, _, witness_path] = fields.as_slice() else {
            return Err(invalid_encoding());
        };
        let lane_id = match *lane {
            "sha256" => ZkCredentialHashAlgorithm::Sha256,
            "poseidon2" => ZkCredentialHashAlgorithm::Poseidon2,
            _ => return Err(invalid_encoding()),
        };
        let mode = match *mode_name {
            "public" => ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            "private" => ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            _ => return Err(invalid_encoding()),
        };
        let (stage, part) = match (*stage_name, mode) {
            ("issuer_envelope", _) => (
                ZkPersonaCredentialEvidenceSourceStage::IssuerEnvelope,
                "issuer",
            ),
            ("claim_root", _) => (ZkPersonaCredentialEvidenceSourceStage::ClaimRoot, "root"),
            ("signed_validity", _) => (
                ZkPersonaCredentialEvidenceSourceStage::SignedValidity,
                "validity",
            ),
            ("public_claim", ZkPersonaCredentialEvidenceMode::PublicPersonaV1) => {
                (ZkPersonaCredentialEvidenceSourceStage::PublicClaim, "claim")
            }
            ("private_claim", ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1) => (
                ZkPersonaCredentialEvidenceSourceStage::PrivateClaim,
                "claim",
            ),
            ("current_state", _) => (
                ZkPersonaCredentialEvidenceSourceStage::CurrentState,
                "status",
            ),
            _ => return Err(invalid_encoding()),
        };
        if !checked.insert((*lane, *mode_name, part)) {
            return Err(invalid_encoding());
        }
        let request = root.join(format!("{lane}-{mode_name}-{part}.pb"));
        let max_request_bytes = MAX_WITNESS_BYTES
            .checked_add(REQUEST_OVERHEAD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let request_bytes = read_bounded(&request, max_request_bytes)?;
        let ZkProviderOperation::ProvePersonaCredentialEvidenceStage {
            mode: actual_mode,
            circuit_ref,
            proof_suite,
            witness,
        } = decode_operation_request(&request_bytes)?
        else {
            return Err(invalid_encoding());
        };
        if actual_mode != mode
            || circuit_ref != stage.source_ref(lane_id)
            || witness.circuit_ref() != circuit_ref
            || proof_suite != ZkProofSuite::PRODUCTION
        {
            return Err(invalid_encoding());
        }
        let fresh = read_bounded(&PathBuf::from(witness_path), MAX_WITNESS_BYTES)?;
        if !same_witness(witness.expose_bytes(), &fresh)? {
            return Err(invalid_encoding());
        }
    }
    if checked.len() != EXPECTED_WITNESS_COUNT {
        return Err(invalid_encoding());
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let mut file = File::open(path).map_err(|_| invalid_encoding())?;
    let len = usize::try_from(file.metadata().map_err(|_| invalid_encoding())?.len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    if len == 0 || len > maximum {
        return Err(invalid_encoding());
    }
    let mut bytes = Zeroizing::new(vec![0_u8; len]);
    file.read_exact(&mut bytes)
        .map_err(|_| invalid_encoding())?;
    if file.read(&mut [0_u8; 1]).map_err(|_| invalid_encoding())? != 0 {
        return Err(invalid_encoding());
    }
    Ok(bytes)
}

fn same_witness(left: &[u8], right: &[u8]) -> Result<bool, ZkError> {
    // Compression framing can vary between hosts. Compare bounded uncompressed
    // chunks so errors never display witness contents and no full copy is needed.
    let mut left = GzDecoder::new(left);
    let mut right = GzDecoder::new(right);
    let mut a = Zeroizing::new([0_u8; COMPARE_CHUNK_BYTES]);
    let mut b = Zeroizing::new([0_u8; COMPARE_CHUNK_BYTES]);
    let mut total = 0_usize;
    loop {
        let left_len = read_chunk(&mut left, a.as_mut())?;
        let right_len = read_chunk(&mut right, b.as_mut())?;
        if left_len != right_len || a.get(..left_len) != b.get(..right_len) {
            return Ok(false);
        }
        if left_len == 0 {
            return Ok(total != 0);
        }
        total = total
            .checked_add(left_len)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if total > MAX_WITNESS_BYTES {
            return Err(ZkError::new(ZkErrorReason::WitnessTooLarge));
        }
    }
}

fn read_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, ZkError> {
    let mut filled = 0_usize;
    while let Some(remaining) = buffer.get_mut(filled..) {
        if remaining.is_empty() {
            break;
        }
        let count = reader.read(remaining).map_err(|_| invalid_encoding())?;
        if count == 0 {
            break;
        }
        filled = filled
            .checked_add(count)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    Ok(filled)
}

fn invalid_encoding() -> ZkError {
    ZkError::new(ZkErrorReason::InvalidProofEncoding)
}
