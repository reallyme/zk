// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;

mod crypto;

use crypto::{
    build_credential, build_direct_credential, build_direct_session, build_session, BindingContext,
    CredentialMaterial, P256Key, ISSUER_A_SCALAR, ISSUER_B_SCALAR, PERSONA_SCALAR,
    SUBJECT_A_SCALAR, SUBJECT_B_SCALAR, WRONG_PERSONA_SCALAR,
};

const MODE_GENERATE: &str = "generate";
const MODE_CHECK: &str = "check";

const REQUIRED_CIRCUIT_MARKERS: [CircuitMarker; 7] = [
    CircuitMarker {
        path: "circuits/sha256/families/credential_subject_claim_v1/session/src/main.nr",
        markers: &["SESS1", "SESSB1", "verify_signature"],
    },
    CircuitMarker {
        path: "circuits/sha256/families/credential_subject_claim_v1/claim/src/main.nr",
        markers: &["BINDSUB1", "SESSB1", "CREDB1", "verify_signature"],
    },
    CircuitMarker {
        path: "circuits/sha256/families/private_persona_claim_v1/session/src/main.nr",
        markers: &["PERS2", "PSESB2", "verify_signature"],
    },
    CircuitMarker {
        path: "circuits/sha256/families/private_persona_claim_v1/credential_envelope/src/main.nr",
        markers: &["ENVB1", "verify_signature"],
    },
    CircuitMarker {
        path: "circuits/sha256/families/private_persona_claim_v1/credential_root/src/main.nr",
        markers: &["BINDMRK1", "CREDB1", "verify_signature"],
    },
    CircuitMarker {
        path: "circuits/sha256/families/private_persona_claim_v1/claim/src/main.nr",
        markers: &["BINDSUB1", "LINK1", "PSESB2", "CREDB1", "verify_signature"],
    },
    CircuitMarker {
        path: "circuits/sha256/families/common_credential_root_v1/issuer_credential_status/src/main.nr",
        markers: &[
            "BINDVLD1",
            "CREDB1",
            "credential inactive",
            "verify_signature",
        ],
    },
];

pub fn run<I>(args: I) -> Result<(), FixtureError>
where
    I: Iterator<Item = OsString>,
{
    let args = Args::parse(args)?;
    validate_circuit_markers(&args.repo_root)?;
    let fixture = FixtureTree::build(BindingContext::from_environment()?)?;
    match args.mode {
        Mode::Generate => fixture.write_to(&args.output_root),
        Mode::Check => fixture.check_at(&args.output_root),
    }
}

struct Args {
    mode: Mode,
    output_root: PathBuf,
    repo_root: PathBuf,
}

impl Args {
    fn parse<I>(mut args: I) -> Result<Self, FixtureError>
    where
        I: Iterator<Item = OsString>,
    {
        let _program = args.next();
        let mode_arg = args.next().ok_or(FixtureError::Usage)?;
        let output_root = args.next().map(PathBuf::from).ok_or(FixtureError::Usage)?;
        let repo_root = match args.next() {
            Some(path) => PathBuf::from(path),
            None => std::env::current_dir().map_err(|_| FixtureError::Io)?,
        };
        if args.next().is_some() {
            return Err(FixtureError::Usage);
        }
        Ok(Self {
            mode: Mode::parse(&mode_arg)?,
            output_root,
            repo_root,
        })
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

#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("private persona distinct fixture generation failed")]
    Crypto,
    #[error("private persona distinct fixture generation failed")]
    CircuitContract,
    #[error("private persona distinct fixture generation failed")]
    FixtureMismatch,
    #[error("private persona distinct fixture generation failed")]
    Io,
    #[error("private persona distinct fixture generation failed")]
    Length,
    #[error("usage: generate-private-persona-distinct-fixtures <generate|check> <fixture-root> [repo-root]")]
    Usage,
}

impl FixtureError {
    pub fn audit_message(&self) -> &'static [u8] {
        match self {
            Self::Usage => {
                b"usage: generate-private-persona-distinct-fixtures <generate|check> <fixture-root> [repo-root]\n"
            }
            Self::FixtureMismatch => b"private persona distinct fixture check failed\n",
            _ => b"private persona distinct fixture generation failed\n",
        }
    }
}

struct CircuitMarker {
    path: &'static str,
    markers: &'static [&'static str],
}

fn validate_circuit_markers(repo_root: &Path) -> Result<(), FixtureError> {
    for contract in REQUIRED_CIRCUIT_MARKERS {
        let source =
            fs::read_to_string(repo_root.join(contract.path)).map_err(|_| FixtureError::Io)?;
        for marker in contract.markers {
            if !source.contains(marker) {
                return Err(FixtureError::CircuitContract);
            }
        }
    }
    Ok(())
}

struct FixtureTree {
    files: Vec<FixtureFile>,
}

impl FixtureTree {
    fn build(binding_context: BindingContext) -> Result<Self, FixtureError> {
        let issuer_a = P256Key::from_scalar(&ISSUER_A_SCALAR)?;
        let issuer_b = P256Key::from_scalar(&ISSUER_B_SCALAR)?;
        let subject_a = P256Key::from_scalar(&SUBJECT_A_SCALAR)?;
        let subject_b = P256Key::from_scalar(&SUBJECT_B_SCALAR)?;
        let persona = P256Key::from_scalar(&PERSONA_SCALAR)?;
        let wrong_persona = P256Key::from_scalar(&WRONG_PERSONA_SCALAR)?;

        let shared_session = build_session(&persona, binding_context)?;
        let direct_session = build_direct_session(&subject_a, binding_context)?;
        let wrong_session = build_session(&wrong_persona, binding_context)?;
        let first_material = CredentialMaterial::try_new(0)?;
        let second_material = CredentialMaterial::try_new(1)?;
        let first = build_credential(
            "credential-a",
            &issuer_a,
            &subject_a,
            &persona,
            &first_material,
            binding_context,
        )?;
        let direct = build_direct_credential(
            "direct/credential-a",
            &issuer_a,
            &subject_a,
            &first_material,
            binding_context,
        )?;
        let wrong = build_credential(
            "wrong-persona/credential-a",
            &issuer_a,
            &subject_a,
            &wrong_persona,
            &first_material,
            binding_context,
        )?;
        let second = build_credential(
            "credential-b",
            &issuer_b,
            &subject_b,
            &persona,
            &second_material,
            binding_context,
        )?;

        if direct.subject_public_key != first.subject_public_key
            || direct.issuer_public_key != first.issuer_public_key
            || direct.credential_binding != first.credential_binding
            || direct.session_binding != direct_session.session_binding
            || direct.session_binding == first.session_binding
            || first.subject_public_key == second.subject_public_key
            || first.issuer_public_key == second.issuer_public_key
            || first.subject_public_key != wrong.subject_public_key
            || first.issuer_public_key != wrong.issuer_public_key
            || first.credential_binding != wrong.credential_binding
            || first.session_binding != second.session_binding
            || first.session_binding == wrong.session_binding
            || shared_session.session_binding != first.session_binding
            || wrong_session.session_binding != wrong.session_binding
        {
            return Err(FixtureError::CircuitContract);
        }

        let mut files = Vec::new();
        files
            .try_reserve_exact(19)
            .map_err(|_| FixtureError::Length)?;
        files.push(FixtureFile::new("session/Prover.toml", shared_session.toml));
        files.push(FixtureFile::new(
            "direct/session/Prover.toml",
            direct_session.toml,
        ));
        files.extend(direct.files()?);
        files.extend(first.files()?);
        files.extend(second.files()?);
        files.push(FixtureFile::new(
            "wrong-persona/session/Prover.toml",
            wrong_session.toml,
        ));
        files.extend(wrong.files()?);
        Ok(Self { files })
    }

    fn write_to(&self, output_root: &Path) -> Result<(), FixtureError> {
        self.validate_managed_output_tree(output_root)?;
        for file in &self.files {
            let path = output_root.join(file.path);
            let parent = path.parent().ok_or(FixtureError::Io)?;
            self.require_regular_path_or_absent(parent)?;
            self.require_regular_path_or_absent(path.as_path())?;
            fs::create_dir_all(parent).map_err(|_| FixtureError::Io)?;
            fs::write(path, file.contents.as_bytes()).map_err(|_| FixtureError::Io)?;
        }
        Ok(())
    }

    fn check_at(&self, output_root: &Path) -> Result<(), FixtureError> {
        self.validate_managed_output_tree(output_root)?;
        for file in &self.files {
            let actual = fs::read(output_root.join(file.path)).map_err(|_| FixtureError::Io)?;
            if actual != file.contents.as_bytes() {
                return Err(FixtureError::FixtureMismatch);
            }
        }
        Ok(())
    }

    fn validate_managed_output_tree(&self, output_root: &Path) -> Result<(), FixtureError> {
        match fs::symlink_metadata(output_root) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(FixtureError::Io);
                }
                self.validate_managed_entries(output_root, output_root)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_error) => Err(FixtureError::Io),
        }
    }

    fn validate_managed_entries(
        &self,
        output_root: &Path,
        current: &Path,
    ) -> Result<(), FixtureError> {
        for entry in fs::read_dir(current).map_err(|_| FixtureError::Io)? {
            let entry = entry.map_err(|_| FixtureError::Io)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| FixtureError::Io)?;
            if metadata.file_type().is_symlink() {
                return Err(FixtureError::Io);
            }
            if metadata.is_dir() {
                if !self.is_expected_directory(output_root, &path) {
                    return Err(FixtureError::FixtureMismatch);
                }
                self.validate_managed_entries(output_root, &path)?;
                continue;
            }
            if !metadata.is_file() || !self.is_expected_file(output_root, &path) {
                return Err(FixtureError::FixtureMismatch);
            }
        }
        Ok(())
    }

    fn is_expected_directory(&self, output_root: &Path, path: &Path) -> bool {
        if path == output_root {
            return true;
        }
        for file in &self.files {
            let mut ancestor = output_root.join(file.path);
            while let Some(parent) = ancestor.parent() {
                if parent == output_root {
                    break;
                }
                if parent == path {
                    return true;
                }
                ancestor = parent.to_path_buf();
            }
        }
        false
    }

    fn is_expected_file(&self, output_root: &Path, path: &Path) -> bool {
        self.files
            .iter()
            .any(|file| output_root.join(file.path) == path)
    }

    fn require_regular_path_or_absent(&self, path: &Path) -> Result<(), FixtureError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(FixtureError::Io);
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_error) => Err(FixtureError::Io),
        }
    }
}

pub(super) struct FixtureFile {
    path: &'static str,
    contents: String,
}

impl FixtureFile {
    pub(super) fn new(path: &'static str, contents: String) -> Self {
        Self { path, contents }
    }
}
