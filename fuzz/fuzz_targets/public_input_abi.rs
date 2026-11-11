// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz compiler-pinned Barretenberg field decoding and proof normalization.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_api::circuits::ZkCircuitRef;
use reallyme_zk_backend_bb::BarretenbergPublicInputCodec;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let index = usize::from(*selector) % ZkCircuitRef::ALL.len();
    let Some(circuit_ref) = ZkCircuitRef::ALL.get(index).copied() else {
        return;
    };

    if let Ok(compact) = BarretenbergPublicInputCodec::decode(circuit_ref, payload) {
        let encoded = BarretenbergPublicInputCodec::encode(circuit_ref, &compact);
        if encoded.as_deref() != Ok(payload) {
            // A decoded canonical ABI value must re-encode byte-for-byte.
            // Abort without placing potentially sensitive bytes in a panic.
            std::process::abort();
        }
    }
    let _complete = BarretenbergPublicInputCodec::normalize_complete_proof(circuit_ref, payload);
});
