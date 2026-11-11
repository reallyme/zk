// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod hkdf;
mod sha256_bounded;

use std::ecdsa_secp256r1;

global MAX_DEPTH: u32 = 6;
global MAX_LEAF_COUNT: u32 = 64;
global SALT_LEN: u32 = 16;

// SHA-256("reallyme.lineage.v1"). A fixed claim name prevents a different
// credential attribute from being interpreted as lineage.
global LINEAGE_NAME_HASH: [u8; 32] = [
    0xa0, 0x0e, 0x5f, 0x5f, 0x55, 0xfa, 0x10, 0x52, 0x66, 0x8a, 0x6f, 0x10, 0x71, 0x98, 0xe8, 0x48,
    0x58, 0x90, 0x42, 0x51, 0x19, 0xb4, 0xca, 0x1a, 0xe1, 0xe8, 0x28, 0x7a, 0x77, 0x08, 0x46, 0xdd,
];

pub struct PublicSlot {
    issuer_x: [u8; 32],
    issuer_y: [u8; 32],
    expiry_unix: u64,
    credential_binding: [u8; 32],
    subject_join: [u8; 32],
}

pub struct CredentialWitness {
    envelope_hash: [u8; 32],
    merkle_root: [u8; 32],
    issuer_root_bind_sig: [u8; 64],
    subject_x: [u8; 32],
    subject_y: [u8; 32],
    relationship_did_hash: [u8; 32],
    relationship_nonce: [u8; 32],
    claim_salt: [u8; SALT_LEN],
    leaf_index: u32,
    path_len: u32,
    path: [[u8; 32]; MAX_DEPTH],
}

fn is_zero32(bytes: [u8; 32]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..32 {
        acc = acc | bytes[i];
    }
    acc == 0u8
}

fn is_zero16(bytes: [u8; 16]) -> bool {
    let mut acc: u8 = 0u8;
    for i in 0..16 {
        acc = acc | bytes[i];
    }
    acc == 0u8
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

fn bit_at(index: u32, level: u32) -> u8 {
    ((index >> level) & 1u32) as u8
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

fn verify_slot(
    slot: PublicSlot,
    witness: CredentialWitness,
    prk: [u8; 32],
    join_salt: [u8; 32],
    challenge: [u8; 32],
    audience_hash: [u8; 32],
    transaction_data_hash: [u8; 32],
) {
    assert(!is_zero32(slot.issuer_x) | !is_zero32(slot.issuer_y), "issuer key is zero");
    assert(!is_zero32(witness.subject_x) | !is_zero32(witness.subject_y), "subject key is zero");
    assert(!is_zero32(witness.envelope_hash), "envelope hash is zero");
    assert(!is_zero32(witness.merkle_root), "merkle root is zero");
    assert(!is_zero32(witness.relationship_did_hash), "relationship DID hash is zero");
    assert(!is_zero32(witness.relationship_nonce), "relationship nonce is zero");
    assert(!is_zero16(witness.claim_salt), "claim salt is zero");
    // The claim tree has one fixed depth. A shorter path would let a digest
    // that the issuer signed in a leaf position stand for a hidden subtree.
    assert(witness.path_len == MAX_DEPTH, "claim tree path must have fixed depth");
    assert(witness.leaf_index < MAX_LEAF_COUNT, "leaf index too large");
    // The issuer's canonical lineage field occupies slot zero. A holder
    // cannot choose another same-named leaf from this signed claim tree.
    assert(witness.leaf_index == 0u32, "lineage leaf must occupy slot zero");

    for level in 0..MAX_DEPTH {
        if level >= witness.path_len {
            assert(bit_at(witness.leaf_index, level) == 0u8, "unused index bit");
            for j in 0..32 {
                assert(witness.path[level][j] == 0u8, "unused path entry");
            }
        }
    }

    let mut root_bind_pre: [u8; 72] = [0u8; 72];
    root_bind_pre[0] = 0x42;
    root_bind_pre[1] = 0x49;
    root_bind_pre[2] = 0x4e;
    root_bind_pre[3] = 0x44;
    root_bind_pre[4] = 0x4d;
    root_bind_pre[5] = 0x52;
    root_bind_pre[6] = 0x4b;
    root_bind_pre[7] = 0x31; // "BINDMRK1"
    for i in 0..32 {
        root_bind_pre[8 + i] = witness.envelope_hash[i];
    }
    for i in 0..32 {
        root_bind_pre[40 + i] = witness.merkle_root[i];
    }
    let root_bind_digest = sha256_bounded::sha256_bounded::<72, 2>(root_bind_pre, 72u32);
    assert(
        ecdsa_secp256r1::verify_signature(
            slot.issuer_x,
            slot.issuer_y,
            witness.issuer_root_bind_sig,
            root_bind_digest,
        ),
        "issuer root binding signature invalid",
    );

    // The paired selected-claim proof verifies BINDSUB1 and LINK1 for this
    // same subject. The private salt makes this join untestable by an issuer
    // that knows the subject key but did not participate in the presentation.
    let mut join_pre: [u8; 200] = [0u8; 200];
    join_pre[0] = 0x52;
    join_pre[1] = 0x4d;
    join_pre[2] = 0x53;
    join_pre[3] = 0x4a;
    join_pre[4] = 0x4f;
    join_pre[5] = 0x49;
    join_pre[6] = 0x4e;
    join_pre[7] = 0x31; // "RMSJOIN1"
    for i in 0..32 {
        join_pre[8 + i] = witness.subject_x[i];
    }
    for i in 0..32 {
        join_pre[40 + i] = witness.subject_y[i];
    }
    for i in 0..32 {
        join_pre[72 + i] = join_salt[i];
    }
    for i in 0..32 {
        join_pre[104 + i] = challenge[i];
    }
    for i in 0..32 {
        join_pre[136 + i] = audience_hash[i];
    }
    for i in 0..32 {
        join_pre[168 + i] = transaction_data_hash[i];
    }
    let subject_join = sha256_bounded::sha256_bounded::<200, 4>(join_pre, 200u32);
    assert(subject_join == slot.subject_join, "subject join mismatch");

    // Every variable context field is opened from the authenticated lineage
    // leaf below. The issuer key and subject key are reused from the signature
    // and subject join above, preventing independent wallet-supplied identities.
    let mut context_pre: [u8; 198] = [0u8; 198];
    context_pre[0] = 0x52;
    context_pre[1] = 0x4d;
    context_pre[2] = 0x43;
    context_pre[3] = 0x54;
    context_pre[4] = 0x58;
    context_pre[5] = 0x31; // "RMCTX1"
    for i in 0..32 {
        context_pre[6 + i] = slot.issuer_x[i];
    }
    for i in 0..32 {
        context_pre[38 + i] = slot.issuer_y[i];
    }
    for i in 0..32 {
        context_pre[70 + i] = witness.relationship_did_hash[i];
    }
    for i in 0..32 {
        context_pre[102 + i] = witness.subject_x[i];
    }
    for i in 0..32 {
        context_pre[134 + i] = witness.subject_y[i];
    }
    for i in 0..32 {
        context_pre[166 + i] = witness.relationship_nonce[i];
    }
    let context_hash = sha256_bounded::sha256_bounded::<198, 4>(context_pre, 198u32);
    let lineage_tag = hkdf::expand_lineage(prk, context_hash);

    // The v1 Merkle claim has a 64-byte value:
    // SHA-256(canonical relationship context) || HKDF lineage value.
    let mut claim_inner_pre: [u8; 88] = [0u8; 88];
    claim_inner_pre[0] = 0x43;
    claim_inner_pre[1] = 0x4c;
    claim_inner_pre[2] = 0x4d;
    claim_inner_pre[3] = 0x31; // "CLM1"
    claim_inner_pre[7] = 0x40; // big-endian u32 length 64
    for i in 0..32 {
        claim_inner_pre[8 + i] = context_hash[i];
    }
    for i in 0..32 {
        claim_inner_pre[40 + i] = lineage_tag[i];
    }
    for i in 0..16 {
        claim_inner_pre[72 + i] = witness.claim_salt[i];
    }
    let claim_inner = sha256_bounded::sha256_bounded::<88, 2>(claim_inner_pre, 88u32);

    let mut leaf_pre: [u8; 69] = [0u8; 69];
    leaf_pre[0] = 0x4c;
    leaf_pre[1] = 0x45;
    leaf_pre[2] = 0x41;
    leaf_pre[3] = 0x46;
    leaf_pre[4] = 0x31; // "LEAF1"
    for i in 0..32 {
        leaf_pre[5 + i] = LINEAGE_NAME_HASH[i];
    }
    for i in 0..32 {
        leaf_pre[37 + i] = claim_inner[i];
    }
    let mut current = sha256_bounded::sha256_bounded::<69, 2>(leaf_pre, 69u32);

    for level in 0..MAX_DEPTH {
        if level < witness.path_len {
            let mut node_pre: [u8; 69] = [0u8; 69];
            node_pre[0] = 0x4e;
            node_pre[1] = 0x4f;
            node_pre[2] = 0x44;
            node_pre[3] = 0x45;
            node_pre[4] = 0x31; // "NODE1"
            let sibling = witness.path[level];
            if bit_at(witness.leaf_index, level) == 0u8 {
                for i in 0..32 {
                    node_pre[5 + i] = current[i];
                }
                for i in 0..32 {
                    node_pre[37 + i] = sibling[i];
                }
            } else {
                for i in 0..32 {
                    node_pre[5 + i] = sibling[i];
                }
                for i in 0..32 {
                    node_pre[37 + i] = current[i];
                }
            }
            current = sha256_bounded::sha256_bounded::<69, 2>(node_pre, 69u32);
        }
    }
    assert(current == witness.merkle_root, "lineage leaf not in signed root");

    // Recompute the session-scoped binding shared with the selected-claim
    // proof. BINDMRK1 authenticates the claim root against the envelope digest;
    // the envelope's validity dates and credential status require separate
    // issuer-credential evidence at the verifier.
    let mut cred_pre: [u8; 238] = [0u8; 238];
    cred_pre[0] = 0x43;
    cred_pre[1] = 0x52;
    cred_pre[2] = 0x45;
    cred_pre[3] = 0x44;
    cred_pre[4] = 0x42;
    cred_pre[5] = 0x31; // "CREDB1"
    for i in 0..32 {
        cred_pre[6 + i] = slot.issuer_x[i];
    }
    for i in 0..32 {
        cred_pre[38 + i] = slot.issuer_y[i];
    }
    for i in 0..32 {
        cred_pre[70 + i] = witness.envelope_hash[i];
    }
    for i in 0..32 {
        cred_pre[102 + i] = witness.merkle_root[i];
    }
    for i in 0..32 {
        cred_pre[134 + i] = challenge[i];
    }
    for i in 0..32 {
        cred_pre[166 + i] = audience_hash[i];
    }
    for i in 0..32 {
        cred_pre[198 + i] = transaction_data_hash[i];
    }
    let expiry_bytes = u64_to_be_bytes(slot.expiry_unix);
    for i in 0..8 {
        cred_pre[230 + i] = expiry_bytes[i];
    }
    let binding = sha256_bounded::sha256_bounded::<238, 4>(cred_pre, 238u32);
    assert(binding == slot.credential_binding, "credential binding mismatch");
}

pub fn main(
    challenge: pub [u8; 32],
    audience_hash: pub [u8; 32],
    transaction_data_hash: pub [u8; 32],
    root_join: pub [u8; 32],
    slot: pub PublicSlot,
    root: [u8; 32],
    join_salt: [u8; 32],
    witness: CredentialWitness,
) {
    assert(!is_zero32(root), "root is zero");
    assert(!is_zero32(challenge), "challenge is zero");
    assert(!is_zero32(audience_hash), "audience is zero");
    assert(!is_zero32(transaction_data_hash), "transaction hash is zero");
    verify_root_join(
        root,
        join_salt,
        challenge,
        audience_hash,
        transaction_data_hash,
        root_join,
    );
    let prk = hkdf::extract(root);
    verify_slot(
        slot,
        witness,
        prk,
        join_salt,
        challenge,
        audience_hash,
        transaction_data_hash,
    );
}
