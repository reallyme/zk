// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;
mod poseidon2_bounded;
use std::ecdsa_secp256r1;

global SUBJECT_BINDING_LEN: u32 = 104; // "BINDSUB1" || envelope || subject key
global PREPARED_BINDING_LEN: u32 = 310; // "PRECB2" || exact credential and token context

fn nonzero32(value: [u8; 32]) -> bool {
    let mut combined = 0u8;
    for index in 0..32 {
        combined = combined | value[index];
    }
    combined != 0u8
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

pub fn main(
    pk_issuer_x: pub [u8; 32],
    pk_issuer_y: pub [u8; 32],
    holder_x: pub [u8; 32],
    holder_y: pub [u8; 32],
    token_nonce: pub [u8; 32],
    prepared_from: pub u64,
    prepared_until: pub u64,
    credential_binding: pub [u8; 32],
    envelope_hash: [u8; 32],
    claims_root: [u8; 32],
    pk_subject_x: [u8; 32],
    pk_subject_y: [u8; 32],
    issuer_envelope_sig: [u8; 64],
    issuer_subject_bind_sig: [u8; 64],
) {
    assert(nonzero32(pk_issuer_x) | nonzero32(pk_issuer_y), "empty issuer key");
    assert(nonzero32(holder_x) | nonzero32(holder_y), "empty holder key");
    assert(nonzero32(pk_subject_x) | nonzero32(pk_subject_y), "empty subject key");
    assert(nonzero32(envelope_hash), "empty envelope hash");
    assert(nonzero32(claims_root), "empty claims root");
    assert(nonzero32(token_nonce), "empty token nonce");
    assert(prepared_from < prepared_until, "invalid prepared interval");

    // The subject binding alone authenticates only a digest chosen by the
    // issuer. Verify the issuer's signature on that exact canonical envelope
    // digest as a separate condition of prepared credential acceptance.
    assert(
        ecdsa_secp256r1::verify_signature(
            pk_issuer_x,
            pk_issuer_y,
            issuer_envelope_sig,
            envelope_hash,
        ),
        "issuer envelope signature invalid",
    );

    // This stage authenticates the issuer's exact envelope-to-subject edge.
    // Later stages authenticate the claim root and validity; the PRECB2 output
    // prevents either edge from being substituted across credentials or tokens.
    let mut subject_binding: [u8; SUBJECT_BINDING_LEN] = [0u8; SUBJECT_BINDING_LEN];
    subject_binding[0] = 0x42;
    subject_binding[1] = 0x49;
    subject_binding[2] = 0x4e;
    subject_binding[3] = 0x44;
    subject_binding[4] = 0x53;
    subject_binding[5] = 0x55;
    subject_binding[6] = 0x42;
    subject_binding[7] = 0x31;
    for index in 0..32 {
        subject_binding[8 + index] = envelope_hash[index];
        subject_binding[40 + index] = pk_subject_x[index];
        subject_binding[72 + index] = pk_subject_y[index];
    }
    let subject_digest = sha256_bounded::sha256_bounded::<SUBJECT_BINDING_LEN, 2>(
        subject_binding,
        SUBJECT_BINDING_LEN,
    );
    assert(
        ecdsa_secp256r1::verify_signature(
            pk_issuer_x,
            pk_issuer_y,
            issuer_subject_bind_sig,
            subject_digest,
        ),
        "issuer subject signature invalid",
    );

    let mut token_binding: [u8; PREPARED_BINDING_LEN] = [0u8; PREPARED_BINDING_LEN];
    token_binding[0] = 0x50;
    token_binding[1] = 0x52;
    token_binding[2] = 0x45;
    token_binding[3] = 0x43;
    token_binding[4] = 0x42;
    token_binding[5] = 0x32;
    for index in 0..32 {
        token_binding[6 + index] = pk_issuer_x[index];
        token_binding[38 + index] = pk_issuer_y[index];
        token_binding[70 + index] = envelope_hash[index];
        token_binding[102 + index] = claims_root[index];
        token_binding[134 + index] = pk_subject_x[index];
        token_binding[166 + index] = pk_subject_y[index];
        token_binding[198 + index] = holder_x[index];
        token_binding[230 + index] = holder_y[index];
        token_binding[262 + index] = token_nonce[index];
    }
    let from_bytes = u64_to_be_bytes(prepared_from);
    let until_bytes = u64_to_be_bytes(prepared_until);
    for index in 0..8 {
        token_binding[294 + index] = from_bytes[index];
        token_binding[302 + index] = until_bytes[index];
    }
    let actual_binding = poseidon2_bounded::poseidon2_bounded::<PREPARED_BINDING_LEN>(
        token_binding,
        PREPARED_BINDING_LEN,
    );
    assert(actual_binding == credential_binding, "token binding mismatch");
}
