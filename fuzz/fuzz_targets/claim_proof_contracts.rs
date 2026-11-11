// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz canonical exact-proof, status-qualified bundle, and raw public-input admission.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_proto_codec::{
    common_credential_root::{
        decode_common_credential_root_raw_public_inputs,
        encode_common_credential_root_raw_public_inputs,
    },
    proof::{decode_exact_proof, encode_exact_proof},
    status_qualified::{
        decode_status_qualified_claim_proof_bundle, encode_status_qualified_claim_proof_bundle,
    },
};

const DECODER_COUNT: u8 = 3;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };

    // Accepted values are re-encoded to exercise the encoders on decoder
    // output. Byte equality is not asserted for these multi-layer domain
    // conversions; the decoders enforce canonical wire bytes themselves.
    match *selector % DECODER_COUNT {
        0 => {
            if let Ok(proof) = decode_exact_proof(payload) {
                let _encoded = encode_exact_proof(&proof);
            }
        }
        1 => {
            if let Ok(bundle) = decode_status_qualified_claim_proof_bundle(payload) {
                let _encoded = encode_status_qualified_claim_proof_bundle(&bundle);
            }
        }
        _ => {
            if let Ok(package) = decode_common_credential_root_raw_public_inputs(payload) {
                let _encoded = encode_common_credential_root_raw_public_inputs(
                    package.persona_mode(),
                    package.slot(),
                    package.public_inputs(),
                );
            }
        }
    }
});
