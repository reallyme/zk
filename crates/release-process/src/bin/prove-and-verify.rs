// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal executable adapter for the typed release proof cycle.

use std::{ffi::OsString, path::PathBuf};

use reallyme_zk_api::{circuits::ZkCircuitRef, proofs::ZkProofSuite};
use reallyme_zk_release_process::{
    PinnedReleaseProcess, ReleaseProcessError, ReleaseProcessErrorReason, ReleaseProofCyclePaths,
    ReleaseToolDigests, ReleaseToolPaths, SystemReleaseProcessRunner,
};

const REQUIRED_ARGUMENT_COUNT: usize = 9;

fn main() -> Result<(), ReleaseProcessError> {
    let arguments = parse_arguments(std::env::args_os())?;
    let tools = ReleaseToolPaths::try_new(
        &arguments.nargo,
        &arguments.barretenberg,
        arguments.tool_digests,
    )?;
    let process = PinnedReleaseProcess::try_new(SystemReleaseProcessRunner, tools)?;
    let cycle = ReleaseProofCyclePaths::try_new(
        arguments.circuit_ref,
        &arguments.crs,
        &arguments.bytecode,
        &arguments.witness,
        &arguments.output,
    )?;
    let _completed = process.prove_and_verify_for_suite(cycle, arguments.proof_suite)?;
    Ok(())
}

struct Arguments {
    nargo: PathBuf,
    barretenberg: PathBuf,
    crs: PathBuf,
    bytecode: PathBuf,
    witness: PathBuf,
    output: PathBuf,
    circuit_ref: ZkCircuitRef,
    tool_digests: ReleaseToolDigests,
    proof_suite: ZkProofSuite,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, ReleaseProcessError> {
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    let mut values = Vec::new();
    values
        .try_reserve_exact(REQUIRED_ARGUMENT_COUNT)
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidArguments))?;
    for _ in 0..REQUIRED_ARGUMENT_COUNT {
        values.push(arguments.next().ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        ))?);
    }
    let proof_suite = arguments
        .next()
        .map(parse_proof_suite)
        .transpose()?
        .unwrap_or(ZkProofSuite::PRODUCTION);
    if arguments.next().is_some() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        ));
    }
    let mut values = values.into_iter();
    let nargo = next_path(&mut values)?;
    let nargo_sha256 = parse_sha256(next_value(&mut values)?)?;
    let barretenberg = next_path(&mut values)?;
    let barretenberg_sha256 = parse_sha256(next_value(&mut values)?)?;
    Ok(Arguments {
        nargo,
        barretenberg,
        crs: next_path(&mut values)?,
        bytecode: next_path(&mut values)?,
        witness: next_path(&mut values)?,
        output: next_path(&mut values)?,
        circuit_ref: parse_circuit_ref(next_value(&mut values)?)?,
        tool_digests: ReleaseToolDigests::new(nargo_sha256, barretenberg_sha256),
        proof_suite,
    })
}

fn parse_sha256(value: OsString) -> Result<[u8; 32], ReleaseProcessError> {
    let value = value.to_str().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::InvalidArguments,
    ))?;
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        ));
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        ));
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        digest[index] = high
            .checked_mul(16)
            .and_then(|value| value.checked_add(low))
            .ok_or(ReleaseProcessError::new(
                ReleaseProcessErrorReason::InvalidArguments,
            ))?;
    }
    Ok(digest)
}

fn decode_hex_nibble(value: u8) -> Result<u8, ReleaseProcessError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        )),
    }
}

fn parse_proof_suite(value: OsString) -> Result<ZkProofSuite, ReleaseProcessError> {
    let value = value.to_str().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::InvalidArguments,
    ))?;
    ZkProofSuite::try_from_stable_name(value)
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidArguments))
}

fn parse_circuit_ref(value: OsString) -> Result<ZkCircuitRef, ReleaseProcessError> {
    let value = value.to_str().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::InvalidArguments,
    ))?;
    ZkCircuitRef::try_from_stable_name(value)
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidArguments))
}

fn next_path(values: &mut impl Iterator<Item = OsString>) -> Result<PathBuf, ReleaseProcessError> {
    values
        .next()
        .map(PathBuf::from)
        .ok_or(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidArguments,
        ))
}

fn next_value(
    values: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, ReleaseProcessError> {
    values.next().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::InvalidArguments,
    ))
}

#[cfg(test)]
#[path = "prove-and-verify/tests.rs"]
mod tests;
