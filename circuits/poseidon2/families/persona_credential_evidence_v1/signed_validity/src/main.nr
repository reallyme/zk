// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;
mod poseidon2_bounded;
use std::ecdsa_secp256r1;

global VALIDITY_BINDING_LEN: u32 = 161; // BINDVLD1 and its fixed-width issuer statement.
global PREPARED_BINDING_LEN: u32 = 310; // PRECB2 includes the hidden subject key.
global MAX_STATUS_LENGTH: u64 = 1000000;

pub struct PublicPreparedValidity {
    issuer_x: [u8; 32],
    issuer_y: [u8; 32],
    holder_x: [u8; 32],
    holder_y: [u8; 32],
    token_nonce: [u8; 32],
    prepared_from: u64,
    prepared_until: u64,
    credential_binding: [u8; 32],
    status_list_id: [u8; 32],
    status_url_hash: [u8; 32],
    status_purpose: u8,
}

pub struct PrivatePreparedValidity {
    envelope_hash: [u8; 32],
    claims_root: [u8; 32],
    subject_x: [u8; 32],
    subject_y: [u8; 32],
    issuer_validity_status_signature: [u8; 64],
    valid_from: u64,
    valid_until: u64,
    status_index: u64,
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

pub fn main(slot: pub PublicPreparedValidity, witness: PrivatePreparedValidity) {
    assert((slot.issuer_x != [0u8; 32]) | (slot.issuer_y != [0u8; 32]), "empty issuer key");
    assert((slot.holder_x != [0u8; 32]) | (slot.holder_y != [0u8; 32]), "empty holder key");
    assert((witness.subject_x != [0u8; 32]) | (witness.subject_y != [0u8; 32]), "empty subject key");
    assert(slot.token_nonce != [0u8; 32], "empty token nonce");
    assert(witness.envelope_hash != [0u8; 32], "empty envelope hash");
    assert(witness.claims_root != [0u8; 32], "empty claims root");
    assert((slot.status_purpose == 1u8) | (slot.status_purpose == 2u8), "invalid status purpose");
    assert(witness.status_index < MAX_STATUS_LENGTH, "status index outside supported range");
    assert(witness.valid_from < witness.valid_until, "invalid credential interval");
    assert(slot.prepared_from < slot.prepared_until, "invalid prepared interval");
    assert(witness.valid_from <= slot.prepared_from, "prepared before credential validity");
    assert(slot.prepared_until <= witness.valid_until, "prepared after credential validity");

    // This proof is prepared once for its public window. It authenticates the
    // issuer's immutable validity and status pointer, without committing to a
    // snapshot root that must change as the status list is refreshed.
    let mut signed: [u8; VALIDITY_BINDING_LEN] = [0u8; VALIDITY_BINDING_LEN];
    signed[0] = 0x42; signed[1] = 0x49; signed[2] = 0x4e; signed[3] = 0x44;
    signed[4] = 0x56; signed[5] = 0x4c; signed[6] = 0x44; signed[7] = 0x31;
    for index in 0..32 {
        signed[8 + index] = witness.envelope_hash[index];
        signed[40 + index] = witness.claims_root[index];
        signed[88 + index] = slot.status_url_hash[index];
        signed[120 + index] = slot.status_list_id[index];
    }
    let valid_from = u64_to_be_bytes(witness.valid_from);
    let valid_until = u64_to_be_bytes(witness.valid_until);
    let status_index = u64_to_be_bytes(witness.status_index);
    for index in 0..8 {
        signed[72 + index] = valid_from[index];
        signed[80 + index] = valid_until[index];
        signed[152 + index] = status_index[index];
    }
    signed[160] = slot.status_purpose;
    let signed_digest = sha256_bounded::sha256_bounded::<VALIDITY_BINDING_LEN, 3>(
        signed,
        VALIDITY_BINDING_LEN,
    );
    assert(
        ecdsa_secp256r1::verify_signature(
            slot.issuer_x,
            slot.issuer_y,
            witness.issuer_validity_status_signature,
            signed_digest,
        ),
        "issuer validity signature invalid",
    );

    // PRECB2 carries the hidden subject across all independently proven
    // stages. The verifier compares this public, token-specific value only
    // after validating each proof under its exact pinned verification key.
    let mut prepared: [u8; PREPARED_BINDING_LEN] = [0u8; PREPARED_BINDING_LEN];
    prepared[0] = 0x50; prepared[1] = 0x52; prepared[2] = 0x45;
    prepared[3] = 0x43; prepared[4] = 0x42; prepared[5] = 0x32;
    for index in 0..32 {
        prepared[6 + index] = slot.issuer_x[index];
        prepared[38 + index] = slot.issuer_y[index];
        prepared[70 + index] = witness.envelope_hash[index];
        prepared[102 + index] = witness.claims_root[index];
        prepared[134 + index] = witness.subject_x[index];
        prepared[166 + index] = witness.subject_y[index];
        prepared[198 + index] = slot.holder_x[index];
        prepared[230 + index] = slot.holder_y[index];
        prepared[262 + index] = slot.token_nonce[index];
    }
    let prepared_from = u64_to_be_bytes(slot.prepared_from);
    let prepared_until = u64_to_be_bytes(slot.prepared_until);
    for index in 0..8 {
        prepared[294 + index] = prepared_from[index];
        prepared[302 + index] = prepared_until[index];
    }
    let actual_binding = poseidon2_bounded::poseidon2_bounded::<PREPARED_BINDING_LEN>(
        prepared,
        PREPARED_BINDING_LEN,
    );
    assert(actual_binding == slot.credential_binding, "credential binding mismatch");
}
