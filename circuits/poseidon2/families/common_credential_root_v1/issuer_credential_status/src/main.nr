// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;
mod poseidon2_bounded;

use std::ecdsa_secp256r1;

global MAX_PATH_DEPTH: u32 = 12;
global MAX_STATUS_LENGTH: u64 = 1000000;

pub struct PublicCredentialStatus {
    issuer_x: [u8; 32],
    issuer_y: [u8; 32],
    presentation_expiry: u64,
    credential_binding: [u8; 32],
    status_root: [u8; 32],
    status_length: u64,
    status_list_id: [u8; 32],
    status_url_hash: [u8; 32],
    status_purpose: u8,
    verifier_now: u64,
}

pub struct PrivateCredentialStatus {
    envelope_hash: [u8; 32],
    claims_root: [u8; 32],
    issuer_validity_status_signature: [u8; 64],
    valid_from: u64,
    valid_until: u64,
    status_index: u64,
    status_chunk: [u8; 32],
    path_len: u32,
    path: [[u8; 32]; MAX_PATH_DEPTH],
}

fn is_zero32(value: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 {
        acc = acc | value[i];
    }
    acc == 0u8
}

fn u64_to_be_bytes(value: u64) -> [u8; 8] {
    [
        ((value >> 56) & 0xff) as u8,
        ((value >> 48) & 0xff) as u8,
        ((value >> 40) & 0xff) as u8,
        ((value >> 32) & 0xff) as u8,
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]
}

fn bit_at(index: u32, level: u32) -> u8 {
    ((index >> level) & 1u32) as u8
}

fn verify_signed_credential_status(slot: PublicCredentialStatus, witness: PrivateCredentialStatus) {
    assert((slot.status_purpose == 1u8) | (slot.status_purpose == 2u8), "invalid status purpose");
    assert(witness.valid_from < witness.valid_until, "invalid credential interval");
    assert(slot.verifier_now <= slot.presentation_expiry, "invalid session interval");
    assert(witness.valid_from <= slot.verifier_now, "credential not yet valid");
    // The verifier may check the proof after the request timestamp. Require
    // validity through the entire bound session, not only at request creation.
    assert(slot.presentation_expiry < witness.valid_until, "credential expires in session");

    // The issuer signs the exact hidden status index, public list identity,
    // validity interval, envelope digest, and claim root as one transcript.
    let mut transcript: [u8; 161] = [0u8; 161];
    transcript[0] = 0x42;
    transcript[1] = 0x49;
    transcript[2] = 0x4e;
    transcript[3] = 0x44;
    transcript[4] = 0x56;
    transcript[5] = 0x4c;
    transcript[6] = 0x44;
    transcript[7] = 0x31; // "BINDVLD1"
    for i in 0..32 {
        transcript[8 + i] = witness.envelope_hash[i];
        transcript[40 + i] = witness.claims_root[i];
        transcript[88 + i] = slot.status_url_hash[i];
        transcript[120 + i] = slot.status_list_id[i];
    }
    let from_bytes = u64_to_be_bytes(witness.valid_from);
    let until_bytes = u64_to_be_bytes(witness.valid_until);
    let index_bytes = u64_to_be_bytes(witness.status_index);
    for i in 0..8 {
        transcript[72 + i] = from_bytes[i];
        transcript[80 + i] = until_bytes[i];
        transcript[152 + i] = index_bytes[i];
    }
    transcript[160] = slot.status_purpose;
    let digest = sha256_bounded::sha256_bounded::<161, 3>(transcript, 161u32);
    assert(
        ecdsa_secp256r1::verify_signature(
            slot.issuer_x,
            slot.issuer_y,
            witness.issuer_validity_status_signature,
            digest,
        ),
        "issuer validity or status signature invalid",
    );
}

fn verify_current_status(slot: PublicCredentialStatus, witness: PrivateCredentialStatus) {
    assert(slot.status_length > 0u64, "empty status list");
    assert(slot.status_length <= MAX_STATUS_LENGTH, "status list too large");
    assert(witness.status_index < slot.status_length, "status index out of range");

    let leaf_count = (slot.status_length + 255u64) / 256u64;
    let mut width = 1u64;
    let mut expected_depth = 0u32;
    for _ in 0..MAX_PATH_DEPTH {
        if width < leaf_count {
            width = width * 2u64;
            expected_depth = expected_depth + 1u32;
        }
    }
    assert(width >= leaf_count, "status tree too deep");
    assert(witness.path_len == expected_depth, "noncanonical status path length");

    let offset = (witness.status_index % 256u64) as u32;
    let byte_index = offset / 8u32;
    let shift = (offset % 8u32) as u8;
    let selected_byte = witness.status_chunk[byte_index];
    assert(((selected_byte >> shift) & 1u8) == 0u8, "credential inactive");

    let mut leaf_pre: [u8; 38] = [0u8; 38];
    leaf_pre[0] = 0x52;
    leaf_pre[1] = 0x4d;
    leaf_pre[2] = 0x43;
    leaf_pre[3] = 0x53;
    leaf_pre[4] = 0x4c;
    leaf_pre[5] = 0x31; // "RMCSL1"
    for i in 0..32 {
        leaf_pre[6 + i] = witness.status_chunk[i];
    }
    let mut current = sha256_bounded::sha256_bounded::<38, 1>(leaf_pre, 38u32);
    let chunk_index = (witness.status_index / 256u64) as u32;
    for level in 0..MAX_PATH_DEPTH {
        if level < witness.path_len {
            let mut node_pre: [u8; 70] = [0u8; 70];
            node_pre[0] = 0x52;
            node_pre[1] = 0x4d;
            node_pre[2] = 0x43;
            node_pre[3] = 0x53;
            node_pre[4] = 0x4e;
            node_pre[5] = 0x31; // "RMCSN1"
            if bit_at(chunk_index, level) == 0u8 {
                for i in 0..32 {
                    node_pre[6 + i] = current[i];
                    node_pre[38 + i] = witness.path[level][i];
                }
            } else {
                for i in 0..32 {
                    node_pre[6 + i] = witness.path[level][i];
                    node_pre[38 + i] = current[i];
                }
            }
            current = sha256_bounded::sha256_bounded::<70, 2>(node_pre, 70u32);
        } else {
            assert(bit_at(chunk_index, level) == 0u8, "unused status index bit");
            for i in 0..32 {
                assert(witness.path[level][i] == 0u8, "unused status path entry");
            }
        }
    }
    let mut root_pre: [u8; 46] = [0u8; 46];
    root_pre[0] = 0x52;
    root_pre[1] = 0x4d;
    root_pre[2] = 0x43;
    root_pre[3] = 0x53;
    root_pre[4] = 0x52;
    root_pre[5] = 0x31; // "RMCSR1"
    let length_bytes = u64_to_be_bytes(slot.status_length);
    for i in 0..8 {
        root_pre[6 + i] = length_bytes[i];
    }
    for i in 0..32 {
        root_pre[14 + i] = current[i];
    }
    let root = sha256_bounded::sha256_bounded::<46, 1>(root_pre, 46u32);
    assert(root == slot.status_root, "issuer status root mismatch");
}

fn verify_credential_join(
    slot: PublicCredentialStatus,
    witness: PrivateCredentialStatus,
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
) {
    // Same CREDB1 transcript as the lineage stage. This forces the signed
    // validity/status statement to refer to that exact hidden credential.
    let mut pre: [u8; 238] = [0u8; 238];
    pre[0] = 0x43;
    pre[1] = 0x52;
    pre[2] = 0x45;
    pre[3] = 0x44;
    pre[4] = 0x42;
    pre[5] = 0x31;
    for i in 0..32 {
        pre[6 + i] = slot.issuer_x[i];
        pre[38 + i] = slot.issuer_y[i];
        pre[70 + i] = witness.envelope_hash[i];
        pre[102 + i] = witness.claims_root[i];
        pre[134 + i] = challenge[i];
        pre[166 + i] = audience_hash[i];
        pre[198 + i] = transaction_data_hash[i];
    }
    let expiry_bytes = u64_to_be_bytes(slot.presentation_expiry);
    for i in 0..8 {
        pre[230 + i] = expiry_bytes[i];
    }
    let binding = poseidon2_bounded::poseidon2_bounded::<238>(pre, 238u32);
    assert(binding == slot.credential_binding, "credential binding mismatch");
}

pub fn main(
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    slot: pub PublicCredentialStatus,
    witness: PrivateCredentialStatus,
) {
    assert(!is_zero32(challenge), "challenge must be non-zero");
    assert(!is_zero32(audience_hash), "audience hash must be non-zero");
    assert(!is_zero32(transaction_data_hash), "transaction data hash must be non-zero");
    assert(!is_zero32(slot.issuer_x) | !is_zero32(slot.issuer_y), "issuer key is zero");
    assert(!is_zero32(witness.envelope_hash), "envelope hash is zero");
    assert(!is_zero32(witness.claims_root), "claims root is zero");
    verify_signed_credential_status(slot, witness);
    verify_current_status(slot, witness);
    verify_credential_join(
        slot,
        witness,
        challenge,
        audience_hash,
        transaction_data_hash,
    );
}
