// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz common-credential-root status, attestation, and wallet-record admission.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm, common_root::ZkCommonCredentialRootSubjectPublicKey,
    keys::ZkIssuerPublicKey,
};
use reallyme_zk_proto_codec::{
    common_credential_root_active_set_path_assignment::{
        decode_root_active_set_path_assignment, encode_root_active_set_path_assignment,
        ZkRootActiveSetPathAssignmentRef,
    },
    common_credential_root_active_set_publication::{
        admit_root_active_set_publication, MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES,
    },
    common_credential_root_attestation::{
        decode_root_assurance_attestation, encode_root_assurance_attestation,
    },
    common_credential_root_private_claims::decode_prepared_claims_for_lane,
    common_credential_root_status_snapshot::{
        decode_root_status_snapshot, encode_root_status_snapshot,
    },
    wallet_stored_credential::decode_wallet_stored_credential_for_lane,
};

const DECODER_COUNT: u8 = 8;
const ACTIVE_SET_IDENTIFIER_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
// Fixed synthetic context. These values are not key material and only select
// which authenticated bindings the wallet-record decoder compares against.
const SYNTHETIC_CREDENTIAL_ENVELOPE: &[u8] = b"synthetic-credential-envelope";
const SYNTHETIC_ISSUER_KEY: ZkIssuerPublicKey = ZkIssuerPublicKey {
    x: [0x11; DIGEST_BYTES],
    y: [0x22; DIGEST_BYTES],
};
const SYNTHETIC_SUBJECT_KEY_X: [u8; DIGEST_BYTES] = [0x33; DIGEST_BYTES];
const SYNTHETIC_SUBJECT_KEY_Y: [u8; DIGEST_BYTES] = [0x44; DIGEST_BYTES];

/// Splits the caller-authenticated root and issuance binding from the front
/// of the input so the fuzzer can reach the binding-dependent decode paths.
fn split_bindings(payload: &[u8]) -> Option<([u8; DIGEST_BYTES], [u8; DIGEST_BYTES], &[u8])> {
    let (issuer_root, rest) = payload.split_first_chunk::<DIGEST_BYTES>()?;
    let (issuance_binding, rest) = rest.split_first_chunk::<DIGEST_BYTES>()?;
    Some((*issuer_root, *issuance_binding, rest))
}

fn fuzz_prepared_claims(payload: &[u8], lane: ZkCredentialHashAlgorithm) {
    let Some((issuer_root, issuance_binding, encoded)) = split_bindings(payload) else {
        return;
    };
    let _claims = decode_prepared_claims_for_lane(encoded, lane, issuer_root, issuance_binding);
}

fn fuzz_wallet_stored_credential(payload: &[u8], lane: ZkCredentialHashAlgorithm) {
    let Some((issuer_root, issuance_binding, encoded)) = split_bindings(payload) else {
        return;
    };
    let _stored = decode_wallet_stored_credential_for_lane(
        encoded,
        SYNTHETIC_CREDENTIAL_ENVELOPE,
        SYNTHETIC_ISSUER_KEY,
        ZkCommonCredentialRootSubjectPublicKey {
            x: SYNTHETIC_SUBJECT_KEY_X,
            y: SYNTHETIC_SUBJECT_KEY_Y,
        },
        lane,
        issuer_root,
        issuance_binding,
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };

    match *selector % DECODER_COUNT {
        0 => {
            if let Ok(snapshot) = decode_root_status_snapshot(payload) {
                let encoded = encode_root_status_snapshot(&snapshot);
                if encoded.as_deref() != Ok(payload) {
                    // An accepted canonical snapshot must re-encode byte-for-byte.
                    // Abort without placing record bytes in a panic.
                    std::process::abort();
                }
            }
        }
        1 => {
            if let Ok(attestation) = decode_root_assurance_attestation(payload) {
                let encoded = encode_root_assurance_attestation(&attestation);
                if encoded.as_ref().map(|bytes| bytes.as_slice()).ok() != Some(payload) {
                    // An accepted canonical attestation must re-encode byte-for-byte.
                    std::process::abort();
                }
            }
        }
        2 => {
            // Admission is the only stage reachable without a pinned
            // authority key, so it is the stage hostile bytes exercise.
            if let Ok(admitted) = admit_root_active_set_publication(payload) {
                let identifier_bytes = admitted
                    .identifier_count()
                    .checked_mul(ACTIVE_SET_IDENTIFIER_BYTES);
                let snapshot = admitted.unauthenticated_snapshot();
                let snapshot_reencodes = encode_root_status_snapshot(&snapshot)
                    .ok()
                    .and_then(|encoded| decode_root_status_snapshot(&encoded).ok())
                    .is_some_and(|decoded| decoded == snapshot);
                if payload.len() > MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES
                    || identifier_bytes.is_none_or(|length| length >= payload.len())
                    || !snapshot_reencodes
                {
                    // An admitted publication is bounded, carries its whole
                    // identifier list inside the payload, and embeds a
                    // canonical snapshot. Abort without echoing its bytes.
                    std::process::abort();
                }
            }
        }
        3 => {
            if let Ok(assignment) = decode_root_active_set_path_assignment(payload) {
                let encoded =
                    encode_root_active_set_path_assignment(ZkRootActiveSetPathAssignmentRef {
                        feed_id: assignment.feed_id(),
                        active_status_root: assignment.active_status_root(),
                        sequence: assignment.sequence(),
                        attestation_id: assignment.attestation_id(),
                        status_index: assignment.status_index(),
                        status_path: assignment.status_path(),
                    });
                if encoded.as_ref().map(|bytes| bytes.as_slice()).ok() != Some(payload) {
                    // An accepted canonical assignment must re-encode byte-for-byte.
                    std::process::abort();
                }
            }
        }
        4 => fuzz_prepared_claims(payload, ZkCredentialHashAlgorithm::Sha256),
        5 => fuzz_prepared_claims(payload, ZkCredentialHashAlgorithm::Poseidon2),
        6 => fuzz_wallet_stored_credential(payload, ZkCredentialHashAlgorithm::Sha256),
        _ => fuzz_wallet_stored_credential(payload, ZkCredentialHashAlgorithm::Poseidon2),
    }
});
