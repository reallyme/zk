// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz proof-bearing operation responses and both canonical vector layers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_proto_codec::{
    result::decode_operation_response, vector::decode_proving_vector_set,
    verification_vector::decode_verification_vector_set,
};

fuzz_target!(|data: &[u8]| {
    let _response = decode_operation_response(data);
    let _proving_vectors = decode_proving_vector_set(data);
    let _verification_vectors = decode_verification_vector_set(data);
});
