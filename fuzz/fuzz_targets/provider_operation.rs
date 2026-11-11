// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz canonical binary request/response and strict request ProtoJSON ingress.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_proto_codec::{
    operation::{decode_operation_request, decode_operation_request_json},
    result::decode_operation_response,
};

const CANONICAL_ARTIFACT_REQUEST: [u8; 2] = [0x2a, 0x00];
const CANONICAL_BACKEND_UNAVAILABLE_RESPONSE: [u8; 6] = [0x12, 0x04, 0x08, 0x0b, 0x40, 0x01];

fuzz_target!(|data: &[u8]| {
    let _binary_request = decode_operation_request(data);
    let _json_request = decode_operation_request_json(data);
    let _binary_response = decode_operation_response(data);

    // Keep valid structured parser states permanently reachable even when a
    // corpus minimizer reduces attacker-controlled input to unrelated bytes.
    let _valid_request = decode_operation_request(&CANONICAL_ARTIFACT_REQUEST);
    let _valid_response = decode_operation_response(&CANONICAL_BACKEND_UNAVAILABLE_RESPONSE);
});
