// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::OsStr;
use std::io::Write;

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_proto_codec::operation::MAX_ZK_PROTO_OPERATION_BYTES;

use crate::{
    stage_commands::{run_prove_stage, run_validate_artifacts, run_verify_stage, run_witness},
    CliError, CliErrorReason, CliExit,
};

const TOOLCHAIN_LOCK_JSON: &str = include_str!("../../../circuits/toolchain-lock.json");

/// Runs the CLI against already-split process arguments.
pub fn run<I, S>(
    args: I,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CliExit, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        write_usage(stdout)?;
        return Ok(CliExit::Success);
    };

    match command.as_ref().to_str() {
        Some("help") | Some("--help") | Some("-h") => {
            ensure_no_more_args(args)?;
            write_usage(stdout)?;
            Ok(CliExit::Success)
        }
        Some("toolchain") => {
            ensure_no_more_args(args)?;
            write_toolchain(stdout)?;
            Ok(CliExit::Success)
        }
        Some("circuits") => {
            match args.next() {
                None => write_circuits(stdout)?,
                Some(option) if option.as_ref() == OsStr::new("--paths") => {
                    ensure_no_more_args(args)?;
                    write_circuit_paths(stdout)?;
                }
                Some(_) => return Err(CliError::new(CliErrorReason::UnexpectedArgument)),
            }
            Ok(CliExit::Success)
        }
        Some("witness") => run_witness(args, stdout),
        Some("prove-stage") => run_prove_stage(args, stdout),
        Some("verify-stage") => run_verify_stage(args, stdout),
        Some("validate-artifacts") => run_validate_artifacts(args, stdout),
        Some("doctor") => {
            ensure_no_more_args(args)?;
            inspect_repository_readiness(stdout)?;
            Ok(CliExit::Failure)
        }
        _ => {
            ensure_no_more_args(args)?;
            write_error(stderr, CliErrorReason::UnknownCommand)?;
            Ok(CliExit::Usage)
        }
    }
}

fn ensure_no_more_args<I, S>(mut args: I) -> Result<(), CliError>
where
    I: Iterator<Item = S>,
    S: AsRef<OsStr>,
{
    if args.next().is_some() {
        return Err(CliError::new(CliErrorReason::UnexpectedArgument));
    }
    Ok(())
}

fn write_usage(output: &mut dyn Write) -> Result<(), CliError> {
    output.write_all(
        concat!(
            "reallyme-zk commands:\n",
            "  help\n",
            "  toolchain\n",
            "  circuits\n",
            "  circuits --paths\n",
            "  witness\n",
            "  prove-stage\n",
            "  verify-stage (diagnostic only; never presentation admission)\n",
            "  validate-artifacts\n",
            "  doctor\n",
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn write_toolchain(output: &mut dyn Write) -> Result<(), CliError> {
    output.write_all(TOOLCHAIN_LOCK_JSON.as_bytes())?;
    output.write_all(b"\n")?;
    Ok(())
}

fn write_circuits(output: &mut dyn Write) -> Result<(), CliError> {
    output.write_all(b"circuit_ref\n")?;
    for circuit_ref in ZkCircuitRef::ALL {
        write_circuit_ref(output, *circuit_ref)?;
        output.write_all(b"\n")?;
    }
    Ok(())
}

fn write_circuit_paths(output: &mut dyn Write) -> Result<(), CliError> {
    output.write_all(b"circuit_path\n")?;
    for circuit_ref in ZkCircuitRef::ALL {
        write_circuit_path(output, *circuit_ref)?;
        output.write_all(b"\n")?;
    }
    Ok(())
}

fn inspect_repository_readiness(output: &mut dyn Write) -> Result<(), CliError> {
    validate_repository_policy()?;
    output.write_all(b"doctor: not-ready\n")?;
    output.write_all(b"circuit_count: ")?;
    write_usize(output, ZkCircuitRef::ALL.len())?;
    output.write_all(b"\n")?;
    output.write_all(b"production_suite: barretenberg_ultra_honk_keccak_zk_no_ipa\n")?;
    output.write_all(b"provider_backend: linked-barretenberg-required\n")?;
    output.write_all(b"modern_gate: pending\n")?;
    Ok(())
}

fn validate_repository_policy() -> Result<(), CliError> {
    if ZkCircuitRef::ALL.is_empty() {
        return Err(CliError::new(CliErrorReason::RepositoryPolicyMismatch));
    }
    map_zk_policy_result(ZkProofSuite::PRODUCTION.require_production())?;
    if MAX_ZK_PROTO_OPERATION_BYTES == 0 {
        return Err(CliError::new(CliErrorReason::RepositoryPolicyMismatch));
    }
    Ok(())
}

fn map_zk_policy_result(result: Result<(), ZkError>) -> Result<(), CliError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => match error.reason() {
            ZkErrorReason::UnsupportedProofSuite => {
                Err(CliError::new(CliErrorReason::RepositoryPolicyMismatch))
            }
            _ => Err(CliError::new(CliErrorReason::RepositoryPolicyMismatch)),
        },
    }
}

fn write_circuit_ref(output: &mut dyn Write, circuit_ref: ZkCircuitRef) -> Result<(), CliError> {
    output.write_all(circuit_ref.credential_hash_algorithm.as_str().as_bytes())?;
    output.write_all(b":")?;
    output.write_all(circuit_ref.family.as_str().as_bytes())?;
    output.write_all(b":")?;
    output.write_all(circuit_ref.stage.as_str().as_bytes())?;
    output.write_all(b":v")?;
    write_u32(output, circuit_ref.revision)?;
    Ok(())
}

fn write_circuit_path(output: &mut dyn Write, circuit_ref: ZkCircuitRef) -> Result<(), CliError> {
    output.write_all(
        circuit_ref
            .credential_hash_algorithm
            .source_dir()
            .as_bytes(),
    )?;
    output.write_all(b"/families/")?;
    output.write_all(circuit_ref.family.source_dir().as_bytes())?;
    output.write_all(b"/")?;
    output.write_all(circuit_ref.stage.source_dir().as_bytes())?;
    Ok(())
}

fn write_u32(output: &mut dyn Write, value: u32) -> Result<(), CliError> {
    write_decimal(output, u64::from(value))
}

fn write_usize(output: &mut dyn Write, value: usize) -> Result<(), CliError> {
    let value = u64::try_from(value)
        .map_err(|_| CliError::new(CliErrorReason::RepositoryPolicyMismatch))?;
    write_decimal(output, value)
}

fn write_decimal(output: &mut dyn Write, value: u64) -> Result<(), CliError> {
    let mut buffer = [0_u8; 20];
    let mut index = buffer.len();
    let mut remaining = value;
    if remaining == 0 {
        output.write_all(b"0")?;
        return Ok(());
    }
    while remaining > 0 {
        index = index
            .checked_sub(1)
            .ok_or(CliError::new(CliErrorReason::RepositoryPolicyMismatch))?;
        let digit = u8::try_from(remaining % 10)
            .map_err(|_| CliError::new(CliErrorReason::RepositoryPolicyMismatch))?;
        buffer[index] = b'0'
            .checked_add(digit)
            .ok_or(CliError::new(CliErrorReason::RepositoryPolicyMismatch))?;
        remaining /= 10;
    }
    let bytes = buffer
        .get(index..)
        .ok_or(CliError::new(CliErrorReason::RepositoryPolicyMismatch))?;
    output.write_all(bytes)?;
    Ok(())
}

fn write_error(output: &mut dyn Write, reason: CliErrorReason) -> Result<(), CliError> {
    output.write_all(b"error: ")?;
    output.write_all(reason.as_str().as_bytes())?;
    output.write_all(b"\n")?;
    Ok(())
}
