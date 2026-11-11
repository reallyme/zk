// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binary entrypoint for the ReallyMe ZK runtime CLI.

use std::{io, process::ExitCode};

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = match reallyme_zk_cli::run(std::env::args_os(), &mut stdout, &mut stderr) {
        Ok(exit) => exit.code(),
        Err(error) => {
            match write_startup_error(&mut stderr, error.reason()) {
                Ok(()) | Err(_) => {}
            }
            1
        }
    };
    match u8::try_from(code) {
        Ok(value) => ExitCode::from(value),
        Err(_) => ExitCode::FAILURE,
    }
}

fn write_startup_error(
    stderr: &mut dyn io::Write,
    reason: reallyme_zk_cli::CliErrorReason,
) -> io::Result<()> {
    stderr.write_all(b"error: ")?;
    stderr.write_all(reason.as_str().as_bytes())?;
    stderr.write_all(b"\n")?;
    Ok(())
}
