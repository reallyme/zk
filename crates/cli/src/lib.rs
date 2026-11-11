// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Production-oriented ReallyMe ZK command-line orchestration.

mod error;
mod io;
mod runner;
mod stage_args;
mod stage_commands;

pub use error::{CliError, CliErrorReason, CliExit};
pub use runner::run;
