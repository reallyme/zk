// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generates deterministic private-persona distinct-subject linked fixtures.

use std::{
    env,
    io::{self, Write as _},
    process::ExitCode,
};

mod generate_private_persona_distinct_fixtures;

fn main() -> ExitCode {
    match generate_private_persona_distinct_fixtures::run(env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = io::stderr().write_all(error.audit_message());
            ExitCode::FAILURE
        }
    }
}
