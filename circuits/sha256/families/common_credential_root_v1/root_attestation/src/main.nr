// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sha256_bounded;

use std::ecdsa_secp256r1;

fn is_zero32(bytes: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 {
        acc = acc | bytes[i];
    }
    acc == 0u8
}

fn u32_to_be_bytes(x: u32) -> [u8; 4] {
    [((x >> 24) & 0xff) as u8, ((x >> 16) & 0xff) as u8, ((x >> 8) & 0xff) as u8, (x & 0xff) as u8]
}

fn u64_to_be_bytes(x: u64) -> [u8; 8] {
    [
        ((x >> 56) & 0xff) as u8,
        ((x >> 48) & 0xff) as u8,
        ((x >> 40) & 0xff) as u8,
        ((x >> 32) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ]
}

fn verify_attestation(
    reallyme_x: [u8; 32],
    reallyme_y: [u8; 32],
    root: [u8; 32],
    policy_id: [u8; 32],
    request_unix: u64,
    presentation_expiry_unix: u64,
    issued_unix: u64,
    expires_unix: u64,
    epoch: u32,
    signature: [u8; 64],
) -> [u8; 32] {
    assert(!is_zero32(reallyme_x) | !is_zero32(reallyme_y), "ReallyMe key is zero");
    assert(!is_zero32(root), "root is zero");
    assert(!is_zero32(policy_id), "policy is zero");
    assert(issued_unix <= request_unix, "attestation not yet valid");
    assert(request_unix < expires_unix, "attestation expired");
    assert(request_unix < presentation_expiry_unix, "presentation expired");
    assert(presentation_expiry_unix < expires_unix, "attestation expires before presentation");

    let mut commitment_pre: [u8; 39] = [0u8; 39];
    commitment_pre[0] = 0x52;
    commitment_pre[1] = 0x4d;
    commitment_pre[2] = 0x52;
    commitment_pre[3] = 0x4f;
    commitment_pre[4] = 0x4f;
    commitment_pre[5] = 0x54;
    commitment_pre[6] = 0x31; // "RMROOT1"
    for i in 0..32 {
        commitment_pre[7 + i] = root[i];
    }
    let commitment = sha256_bounded::sha256_bounded::<39, 1>(commitment_pre, 39u32);

    let mut transcript: [u8; 89] = [0u8; 89];
    transcript[0] = 0x52;
    transcript[1] = 0x4d;
    transcript[2] = 0x52;
    transcript[3] = 0x41;
    transcript[4] = 0x31; // "RMRA1"
    for i in 0..32 {
        transcript[5 + i] = commitment[i];
    }
    for i in 0..32 {
        transcript[37 + i] = policy_id[i];
    }
    let issued_bytes = u64_to_be_bytes(issued_unix);
    let expires_bytes = u64_to_be_bytes(expires_unix);
    let epoch_bytes = u32_to_be_bytes(epoch);
    for i in 0..8 {
        transcript[69 + i] = issued_bytes[i];
    }
    for i in 0..8 {
        transcript[77 + i] = expires_bytes[i];
    }
    for i in 0..4 {
        transcript[85 + i] = epoch_bytes[i];
    }
    let digest = sha256_bounded::sha256_bounded::<89, 2>(transcript, 89u32);
    assert(
        ecdsa_secp256r1::verify_signature(reallyme_x, reallyme_y, signature, digest),
        "root assurance signature invalid",
    );
    // Status is scoped to this exact signed attestation, including its
    // signer and signature. A shared root can have independently revoked
    // attestations with different policies or epochs.
    let mut id_pre: [u8; 167] = [0u8; 167];
    id_pre[0] = 0x52;
    id_pre[1] = 0x4d;
    id_pre[2] = 0x52;
    id_pre[3] = 0x41;
    id_pre[4] = 0x49;
    id_pre[5] = 0x44;
    id_pre[6] = 0x31; // "RMRAID1"
    for i in 0..32 {
        id_pre[7 + i] = reallyme_x[i];
    }
    for i in 0..32 {
        id_pre[39 + i] = reallyme_y[i];
    }
    for i in 0..32 {
        id_pre[71 + i] = digest[i];
    }
    for i in 0..64 {
        id_pre[103 + i] = signature[i];
    }
    sha256_bounded::sha256_bounded::<167, 3>(id_pre, 167u32)
}

fn verify_attestation_join(
    attestation_id: [u8; 32],
    join_salt: [u8; 32],
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
    expected_join: [u8; 32],
) {
    let mut pre: [u8; 169] = [0u8; 169];
    pre[0] = 0x52;
    pre[1] = 0x4d;
    pre[2] = 0x41;
    pre[3] = 0x54;
    pre[4] = 0x4a;
    pre[5] = 0x4f;
    pre[6] = 0x49;
    pre[7] = 0x4e;
    pre[8] = 0x31; // "RMATJOIN1"
    for i in 0..32 {
        pre[9 + i] = attestation_id[i];
    }
    for i in 0..32 {
        pre[41 + i] = join_salt[i];
    }
    for i in 0..32 {
        pre[73 + i] = challenge[i];
    }
    for i in 0..32 {
        pre[105 + i] = audience_hash[i];
    }
    for i in 0..32 {
        pre[137 + i] = transaction_data_hash[i];
    }
    let join = sha256_bounded::sha256_bounded::<169, 3>(pre, 169u32);
    assert(join == expected_join, "attestation join mismatch");
}

fn verify_root_join(
    root: [u8; 32],
    join_salt: [u8; 32],
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
    expected_join: [u8; 32],
) {
    assert(!is_zero32(join_salt), "join salt is zero");
    let mut pre: [u8; 168] = [0u8; 168];
    pre[0] = 0x52;
    pre[1] = 0x4d;
    pre[2] = 0x52;
    pre[3] = 0x4a;
    pre[4] = 0x4f;
    pre[5] = 0x49;
    pre[6] = 0x4e;
    pre[7] = 0x31; // "RMRJOIN1"
    for i in 0..32 {
        pre[8 + i] = root[i];
    }
    for i in 0..32 {
        pre[40 + i] = join_salt[i];
    }
    for i in 0..32 {
        pre[72 + i] = challenge[i];
    }
    for i in 0..32 {
        pre[104 + i] = audience_hash[i];
    }
    for i in 0..32 {
        pre[136 + i] = transaction_data_hash[i];
    }
    let join = sha256_bounded::sha256_bounded::<168, 3>(pre, 168u32);
    assert(join == expected_join, "root join mismatch");
}

pub fn main(
    reallyme_x: pub [u8; 32],
    reallyme_y: pub [u8; 32],
    assurance_policy_id: pub [u8; 32],
    request_unix: pub u64,
    presentation_expiry_unix: pub u64,
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    root_join: pub [u8; 32],
    attestation_join: pub [u8; 32],
    root: [u8; 32],
    attestation_issued_unix: u64,
    attestation_expires_unix: u64,
    attestation_epoch: u32,
    attestation_signature: [u8; 64],
    join_salt: [u8; 32],
) {
    assert(!is_zero32(challenge), "challenge is zero");
    assert(!is_zero32(audience_hash), "audience is zero");
    assert(!is_zero32(transaction_data_hash), "transaction hash is zero");
    let attestation_id = verify_attestation(
        reallyme_x,
        reallyme_y,
        root,
        assurance_policy_id,
        request_unix,
        presentation_expiry_unix,
        attestation_issued_unix,
        attestation_expires_unix,
        attestation_epoch,
        attestation_signature,
    );
    verify_root_join(
        root,
        join_salt,
        challenge,
        audience_hash,
        transaction_data_hash,
        root_join,
    );
    verify_attestation_join(
        attestation_id,
        join_salt,
        challenge,
        audience_hash,
        transaction_data_hash,
        attestation_join,
    );
}
