// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generates reviewed mobile-demo witness fixtures from circuit-lane inputs.

#[path = "generate-demo-flow-inputs/fields.rs"]
mod fields;
#[path = "generate-demo-flow-inputs/fixture_io.rs"]
mod fixture_io;
#[path = "generate-demo-flow-inputs/proto_json.rs"]
mod proto_json;

use std::{
    env,
    ffi::OsString,
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use thiserror::Error;

const PROFILE_CREDENTIAL_SUBJECT_CLAIM: &str = "credential_subject_claim_v1";
const PROFILE_PRIVATE_PERSONA: &str = "private_persona_claim_v1";

const STAGE_SESSION: &str = "session";
const STAGE_CREDENTIAL_ENVELOPE: &str = "credential_envelope";
const STAGE_CREDENTIAL_ROOT: &str = "credential_root";
const STAGE_CLAIM: &str = "claim";

#[derive(Clone, Copy)]
enum FixtureCredentialHashAlgorithm {
    Sha256,
    Poseidon2,
}

impl FixtureCredentialHashAlgorithm {
    const ALL: [Self; 2] = [Self::Sha256, Self::Poseidon2];

    const fn directory(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Poseidon2 => "poseidon2",
        }
    }
}

const MODE_GENERATE: &str = "generate";
const MODE_CHECK: &str = "check";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = io::stderr().write_all(error.audit_message());
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), FixtureError> {
    let args = Args::parse(env::args_os())?;
    let vectors = fixture_io::build_vectors(&args.root)?;
    match args.mode {
        Mode::Generate => fixture_io::write_vectors(&args.root, &vectors),
        Mode::Check => fixture_io::check_vectors(&args.root, &vectors),
    }
}

struct Args {
    mode: Mode,
    root: PathBuf,
}

impl Args {
    fn parse<I>(mut args: I) -> Result<Self, FixtureError>
    where
        I: Iterator<Item = OsString>,
    {
        let _program = args.next();
        let mode_arg = args.next().ok_or(FixtureError::Usage)?;
        let mode = Mode::parse(&mode_arg)?;
        let root = match args.next() {
            Some(path) => PathBuf::from(path),
            None => env::current_dir().map_err(|_| FixtureError::Io)?,
        };
        if args.next().is_some() {
            return Err(FixtureError::Usage);
        }
        Ok(Self { mode, root })
    }
}

enum Mode {
    Generate,
    Check,
}

impl Mode {
    fn parse(value: &OsString) -> Result<Self, FixtureError> {
        if value == MODE_GENERATE {
            return Ok(Self::Generate);
        }
        if value == MODE_CHECK {
            return Ok(Self::Check);
        }
        Err(FixtureError::Usage)
    }
}

#[derive(Error, Debug)]
enum FixtureError {
    #[error("demo fixture generation failed")]
    Decode,
    #[error("demo fixture generation failed")]
    Encode,
    #[error("demo fixture generation failed")]
    FixtureMismatch,
    #[error("demo fixture generation failed")]
    Io,
    #[error("demo fixture generation failed")]
    Json,
    #[error("demo fixture generation failed")]
    MissingField,
    #[error("demo fixture generation failed")]
    Toml,
    #[error("usage: generate-demo-flow-inputs <generate|check> [repo-root]")]
    Usage,
}

impl FixtureError {
    fn audit_message(&self) -> &'static [u8] {
        match self {
            Self::Usage => b"usage: generate-demo-flow-inputs <generate|check> [repo-root]\n",
            Self::FixtureMismatch => b"demo fixture generation check failed\n",
            _ => b"demo fixture generation failed\n",
        }
    }
}
