// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz persona-credential-evidence proof, request, and holder-auth admission.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_proto_codec::{
    persona_credential_evidence_auth::{
        decode_persona_credential_evidence_presentation_auth,
        decode_persona_credential_evidence_verifier_request,
    },
    persona_credential_evidence_proof_set::decode_persona_credential_evidence_proof_set,
    persona_credential_evidence_stage_proof::decode_persona_credential_evidence_stage_proof,
};

const DECODER_COUNT: u8 = 4;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };

    match *selector % DECODER_COUNT {
        0 => {
            if let Ok(proof_set) = decode_persona_credential_evidence_proof_set(payload) {
                let _encoded = proof_set.encode();
            }
        }
        1 => {
            let _stage_proof = decode_persona_credential_evidence_stage_proof(payload);
        }
        2 => {
            if let Ok(request) = decode_persona_credential_evidence_verifier_request(payload) {
                let encoded = request.encode();
                if encoded.as_ref().map(|bytes| bytes.as_slice()).ok() != Some(payload) {
                    // An accepted canonical request must re-encode byte-for-byte.
                    // Abort without placing request bytes in a panic.
                    std::process::abort();
                }
            }
        }
        _ => {
            if let Ok(auth) = decode_persona_credential_evidence_presentation_auth(payload) {
                let encoded = auth.encode();
                if encoded.as_ref().map(|bytes| bytes.as_slice()).ok() != Some(payload) {
                    // An accepted canonical holder-auth transcript must
                    // re-encode byte-for-byte.
                    std::process::abort();
                }
            }
        }
    }
});
