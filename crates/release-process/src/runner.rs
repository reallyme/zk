// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Bounded operating-system process execution.
//!
//! This module is the single audited production boundary allowed to construct
//! operating-system commands. Workspace Clippy policy denies process execution
//! everywhere else, including aliased `std::process` paths.

use std::{
    ffi::OsStr,
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::process::crs_identity::require_modern_crs_identity;
use crate::{ReleaseCommand, ReleaseProcessError, ReleaseProcessErrorReason, ReleaseTool};

/// Maximum bytes accepted from a tool version query.
pub const MAX_RELEASE_TOOL_VERSION_OUTPUT_BYTES: usize = 4 * 1024;
const RELEASE_PROCESS_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const RELEASE_PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(50);
const ALLOWED_ENVIRONMENT: &[&str] = &["PATH", "TMPDIR"];

/// Non-debuggable bounded output returned by a process runner.
pub struct ReleaseProcessOutput {
    pub(crate) stdout: Vec<u8>,
}

/// Injectable process boundary used by release orchestration and tests.
pub trait ReleaseProcessRunner {
    /// Executes one typed command or returns a stable path-free error.
    fn run(&self, command: &ReleaseCommand) -> Result<ReleaseProcessOutput, ReleaseProcessError>;
}

/// Operating-system runner for the approved release commands.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemReleaseProcessRunner;

impl ReleaseProcessRunner for SystemReleaseProcessRunner {
    fn run(&self, command: &ReleaseCommand) -> Result<ReleaseProcessOutput, ReleaseProcessError> {
        require_modern_crs_identity(command)?;
        let mut process = Command::new(&command.executable);
        process.env_clear();
        for name in ALLOWED_ENVIRONMENT {
            if let Some(value) = std::env::var_os(name) {
                process.env(OsStr::new(name), value);
            }
        }
        // Nargo may use its isolated caller-provided home for source caching.
        // Barretenberg must see only the explicit -c CRS directory, never an
        // ambient ~/.bb-crs fallback when a required CRS file is absent.
        if command.tool == ReleaseTool::Nargo {
            if let Some(home) = std::env::var_os("HOME") {
                process.env("HOME", home);
            }
        }
        process.env("GIT_CONFIG_NOSYSTEM", "1");
        process.args(&command.arguments);
        if let Some(directory) = &command.current_directory {
            process.current_dir(directory);
        }
        process.stdin(Stdio::null()).stderr(Stdio::null());
        process.stdout(if command.capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        let mut child = process
            .spawn()
            .map_err(|error| process_io(command, error))?;
        let stdout_reader = if command.capture_stdout {
            let limit = u64::try_from(MAX_RELEASE_TOOL_VERSION_OUTPUT_BYTES)
                .map_err(|_| {
                    ReleaseProcessError::new(ReleaseProcessErrorReason::VersionOutputTooLarge(
                        command.tool,
                    ))
                })?
                .checked_add(1)
                .ok_or(ReleaseProcessError::new(
                    ReleaseProcessErrorReason::VersionOutputTooLarge(command.tool),
                ))?;
            let pipe = child.stdout.take().ok_or(ReleaseProcessError::new(
                ReleaseProcessErrorReason::ProcessIo {
                    tool: command.tool,
                    operation: command.operation,
                    kind: std::io::ErrorKind::BrokenPipe,
                },
            ))?;
            Some(thread::spawn(move || {
                let mut stdout = Vec::new();
                stdout
                    .try_reserve_exact(MAX_RELEASE_TOOL_VERSION_OUTPUT_BYTES)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
                pipe.take(limit).read_to_end(&mut stdout)?;
                Ok::<Vec<u8>, std::io::Error>(stdout)
            }))
        } else {
            None
        };

        let deadline =
            Instant::now()
                .checked_add(RELEASE_PROCESS_TIMEOUT)
                .ok_or(ReleaseProcessError::new(
                    ReleaseProcessErrorReason::ProcessTimedOut {
                        tool: command.tool,
                        operation: command.operation,
                    },
                ))?;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| process_io(command, error))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().map_err(|error| process_io(command, error))?;
                let _status = child.wait().map_err(|error| process_io(command, error))?;
                return Err(ReleaseProcessError::new(
                    ReleaseProcessErrorReason::ProcessTimedOut {
                        tool: command.tool,
                        operation: command.operation,
                    },
                ));
            }
            thread::sleep(RELEASE_PROCESS_POLL_INTERVAL);
        };
        let stdout = match stdout_reader {
            Some(reader) => reader
                .join()
                .map_err(|_| {
                    ReleaseProcessError::new(ReleaseProcessErrorReason::ProcessIo {
                        tool: command.tool,
                        operation: command.operation,
                        kind: std::io::ErrorKind::Other,
                    })
                })?
                .map_err(|error| process_io(command, error))?,
            None => Vec::new(),
        };
        if stdout.len() > MAX_RELEASE_TOOL_VERSION_OUTPUT_BYTES {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::VersionOutputTooLarge(command.tool),
            ));
        }
        if !status.success() {
            return Err(ReleaseProcessError::new(
                ReleaseProcessErrorReason::ProcessFailed {
                    tool: command.tool,
                    operation: command.operation,
                },
            ));
        }
        Ok(ReleaseProcessOutput { stdout })
    }
}

fn process_io(command: &ReleaseCommand, error: std::io::Error) -> ReleaseProcessError {
    ReleaseProcessError::new(ReleaseProcessErrorReason::ProcessIo {
        tool: command.tool,
        operation: command.operation,
        kind: error.kind(),
    })
}
