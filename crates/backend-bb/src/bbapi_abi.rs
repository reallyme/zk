// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Narrow validation boundary for upstream Barretenberg `bbapi` envelopes.
//!
//! Upstream exposes a raw C ABI that accepts and returns MessagePack bytes. This
//! module deliberately models only the byte envelope admitted by ReallyMe
//! platform bindings after wrapper-owned construction: bounded MessagePack
//! arrays with string-keyed maps, no trailing bytes, and no duplicate keys.
//! Native adapters must construct exact typed commands here, validate exact
//! upstream response schemas, and never accept caller-supplied raw envelopes.

mod command;
mod compiled_program_json;
mod message;
mod pack;
mod response;

pub(crate) use command::{
    BbapiCircuitProveCommand, BbapiCircuitVerifyCommand, BbapiSrsInitCommand,
};
pub(crate) use message::{
    validate_message_length, FULL_PROVER_CRS_G1_PREFIX_BYTES, VERIFIER_CRS_G1_PREFIX_BYTES,
    VERIFIER_CRS_G2_BYTES,
};
pub(crate) use response::{
    decode_circuit_prove_raw_common_credential_root_response,
    decode_circuit_prove_raw_prepared_response, decode_circuit_prove_response,
    decode_circuit_verify_response, decode_srs_init_response,
};

#[cfg(test)]
mod tests;
