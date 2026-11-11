// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use zeroize::Zeroize;

use super::{FixtureError, FixtureFile};
use toml::{
    append_array, append_common_context, append_issuer_context, append_path, append_public_key,
    append_u32, append_u64,
};

mod binding_context;
mod toml;
mod transcript;

pub(super) use binding_context::BindingContext;
use transcript::{
    credential_binding, direct_session_binding, domain_hash, envelope_binding, material_label,
    merkle_path_for, merkle_root, persona_message_hash, read_fixed_32, read_fixed_64, salt_for,
    scalar_bytes, session_binding, value_for,
};

const HASH_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const VALUE_BYTES: usize = 64;
const SALT_BYTES: usize = 16;
/// Fixed height of every claim tree; the claim circuits accept no other path length.
const CLAIM_TREE_DEPTH: usize = 6;
const CLAIM_TREE_DEPTH_U32: u32 = 6;
const STATUS_PATH_DEPTH: usize = 12;
const STATUS_LENGTH: u64 = 256;
const STATUS_PURPOSE_REVOCATION: u8 = 1;
const STATUS_VALID_FROM: u64 = EXPIRY_UNIX - 3600;
const STATUS_VALID_UNTIL: u64 = EXPIRY_UNIX + 3600;
const STATUS_VERIFIER_NOW: u64 = EXPIRY_UNIX - 60;
const STATUS_URL: &[u8] = b"https://status.example/revocation-v1";
const P256_UNCOMPRESSED_BYTES: usize = 65;
const P256_UNCOMPRESSED_PREFIX: u8 = 0x04;
const SALT_OFFSETS: [u8; SALT_BYTES] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

const CHALLENGE: [u8; HASH_BYTES] = *b"12345678901234567890123456789012";
const AUDIENCE_HASH: [u8; HASH_BYTES] = [
    9, 154, 253, 179, 93, 59, 240, 212, 165, 85, 211, 128, 46, 230, 32, 231, 23, 222, 68, 74, 195,
    109, 9, 235, 217, 195, 125, 17, 110, 225, 61, 255,
];
const TRANSACTION_DATA_HASH: [u8; HASH_BYTES] = [3; HASH_BYTES];
const EXPIRY_UNIX: u64 = 1_750_000_000;

pub(super) const ISSUER_A_SCALAR: [u8; HASH_BYTES] = scalar_bytes(1);
pub(super) const SUBJECT_A_SCALAR: [u8; HASH_BYTES] = scalar_bytes(2);
pub(super) const SUBJECT_B_SCALAR: [u8; HASH_BYTES] = scalar_bytes(3);
pub(super) const PERSONA_SCALAR: [u8; HASH_BYTES] = scalar_bytes(4);
pub(super) const WRONG_PERSONA_SCALAR: [u8; HASH_BYTES] = scalar_bytes(5);
pub(super) const ISSUER_B_SCALAR: [u8; HASH_BYTES] = scalar_bytes(6);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PublicKeyBytes {
    x: [u8; HASH_BYTES],
    y: [u8; HASH_BYTES],
}

pub(super) struct P256Key {
    signing_key: SigningKey,
    public_key: PublicKeyBytes,
}

impl P256Key {
    pub(super) fn from_scalar(scalar: &[u8; HASH_BYTES]) -> Result<Self, FixtureError> {
        let signing_key = SigningKey::from_slice(scalar).map_err(|_| FixtureError::Crypto)?;
        let encoded = signing_key.verifying_key().to_sec1_point(false);
        let bytes = encoded.as_bytes();
        if bytes.len() != P256_UNCOMPRESSED_BYTES
            || bytes.first().copied() != Some(P256_UNCOMPRESSED_PREFIX)
        {
            return Err(FixtureError::Crypto);
        }
        let x = read_fixed_32(bytes.get(1..33).ok_or(FixtureError::Crypto)?)?;
        let y = read_fixed_32(bytes.get(33..65).ok_or(FixtureError::Crypto)?)?;
        Ok(Self {
            signing_key,
            public_key: PublicKeyBytes { x, y },
        })
    }

    fn sign_hash(&self, hash: &[u8; HASH_BYTES]) -> Result<[u8; SIGNATURE_BYTES], FixtureError> {
        let signature: Signature = self
            .signing_key
            .sign_prehash(hash)
            .map_err(|_| FixtureError::Crypto)?;
        let mut bytes = signature.normalize_s().to_bytes();
        let out = read_fixed_64(bytes.as_slice())?;
        bytes.zeroize();
        Ok(out)
    }

    fn compressed_public_key(&self) -> [u8; 33] {
        let mut out = [0_u8; 33];
        out[0] = if self.public_key.y[31] & 1 == 1 {
            0x03
        } else {
            0x02
        };
        out[1..].copy_from_slice(&self.public_key.x);
        out
    }
}

pub(super) struct SessionFixture {
    pub(super) session_binding: [u8; HASH_BYTES],
    pub(super) toml: String,
}

pub(super) fn build_session(
    persona: &P256Key,
    binding_context: BindingContext,
) -> Result<SessionFixture, FixtureError> {
    let session_binding = session_binding(&persona.public_key, binding_context);
    let persona_sig = persona.sign_hash(&persona_message_hash(binding_context))?;
    let mut toml = String::new();
    append_common_context(&mut toml, binding_context);
    append_array(&mut toml, "session_binding", &session_binding);
    append_public_key(&mut toml, "persona", &persona.public_key);
    append_array(&mut toml, "persona_sig", &persona_sig);
    Ok(SessionFixture {
        session_binding,
        toml,
    })
}

pub(super) fn build_direct_session(
    subject: &P256Key,
    binding_context: BindingContext,
) -> Result<SessionFixture, FixtureError> {
    let session_binding = direct_session_binding(&subject.public_key, binding_context);
    let signature = subject.sign_hash(&domain_hash(
        b"SESS1",
        &[
            &binding_context.challenge,
            &binding_context.audience_hash,
            &binding_context.transaction_data_hash,
            &EXPIRY_UNIX.to_be_bytes(),
        ],
    ))?;
    let mut toml = String::new();
    append_common_context(&mut toml, binding_context);
    append_array(&mut toml, "session_binding", &session_binding);
    append_public_key(&mut toml, "subject", &subject.public_key);
    append_array(&mut toml, "subject_sig", &signature);
    Ok(SessionFixture {
        session_binding,
        toml,
    })
}

pub(super) struct CredentialFixture {
    base_path: &'static str,
    envelope_toml: String,
    root_toml: String,
    claim_toml: String,
    status_toml: String,
    pub(super) issuer_public_key: PublicKeyBytes,
    pub(super) subject_public_key: PublicKeyBytes,
    pub(super) session_binding: [u8; HASH_BYTES],
    pub(super) credential_binding: [u8; HASH_BYTES],
}

impl CredentialFixture {
    pub(super) fn files(self) -> Result<Vec<FixtureFile>, FixtureError> {
        let mut files = Vec::new();
        files
            .try_reserve_exact(4)
            .map_err(|_| FixtureError::Length)?;
        files.push(FixtureFile::new(
            credential_path(self.base_path, "credential_envelope")?,
            self.envelope_toml,
        ));
        files.push(FixtureFile::new(
            credential_path(self.base_path, "credential_root")?,
            self.root_toml,
        ));
        files.push(FixtureFile::new(
            credential_path(self.base_path, "claim")?,
            self.claim_toml,
        ));
        files.push(FixtureFile::new(
            credential_path(self.base_path, "issuer_credential_status")?,
            self.status_toml,
        ));
        Ok(files)
    }
}

pub(super) struct CredentialMaterial {
    envelope_hash: [u8; HASH_BYTES],
    name_hash: [u8; HASH_BYTES],
    salt: [u8; SALT_BYTES],
    value: Vec<u8>,
    val_pub: [u8; VALUE_BYTES],
    val_len: u32,
    path: [[u8; HASH_BYTES]; CLAIM_TREE_DEPTH],
    merkle_root: [u8; HASH_BYTES],
}

impl CredentialMaterial {
    pub(super) fn try_new(index: u8) -> Result<Self, FixtureError> {
        let label = material_label(index)?;
        let envelope_hash = domain_hash(b"ENVH1", &[label]);
        let name_hash = domain_hash(b"NAME1", &[label]);
        let salt = salt_for(index);
        let value = value_for(index)?;
        let val_len = u32::try_from(value.len()).map_err(|_| FixtureError::Length)?;
        let mut val_pub = [0_u8; VALUE_BYTES];
        val_pub
            .get_mut(..value.len())
            .ok_or(FixtureError::Length)?
            .copy_from_slice(value.as_slice());
        let path = merkle_path_for(index)?;
        let merkle_root = merkle_root(&name_hash, &val_pub, val_len, &salt, &path, 0)?;
        Ok(Self {
            envelope_hash,
            name_hash,
            salt,
            value,
            val_pub,
            val_len,
            path,
            merkle_root,
        })
    }
}

pub(super) fn build_credential(
    base_path: &'static str,
    issuer: &P256Key,
    subject: &P256Key,
    persona: &P256Key,
    material: &CredentialMaterial,
    binding_context: BindingContext,
) -> Result<CredentialFixture, FixtureError> {
    build_credential_for_holder(
        base_path,
        issuer,
        subject,
        Some(persona),
        material,
        binding_context,
    )
}

pub(super) fn build_direct_credential(
    base_path: &'static str,
    issuer: &P256Key,
    subject: &P256Key,
    material: &CredentialMaterial,
    binding_context: BindingContext,
) -> Result<CredentialFixture, FixtureError> {
    build_credential_for_holder(base_path, issuer, subject, None, material, binding_context)
}

fn build_credential_for_holder(
    base_path: &'static str,
    issuer: &P256Key,
    subject: &P256Key,
    persona: Option<&P256Key>,
    material: &CredentialMaterial,
    binding_context: BindingContext,
) -> Result<CredentialFixture, FixtureError> {
    if usize::try_from(material.val_len).map_err(|_| FixtureError::Length)? != material.value.len()
    {
        return Err(FixtureError::Length);
    }
    let envelope_binding =
        envelope_binding(&issuer.public_key, &material.envelope_hash, binding_context);
    let credential_binding = credential_binding(
        &issuer.public_key,
        &material.envelope_hash,
        &material.merkle_root,
        binding_context,
    );
    let session_binding = match persona {
        Some(persona) => session_binding(&persona.public_key, binding_context),
        None => direct_session_binding(&subject.public_key, binding_context),
    };
    let issuer_sig = issuer.sign_hash(&material.envelope_hash)?;
    let root_bind_hash = domain_hash(
        b"BINDMRK1",
        &[&material.envelope_hash, &material.merkle_root],
    );
    let issuer_root_bind_sig = issuer.sign_hash(&root_bind_hash)?;
    let issuer_subject_bind_sig = issuer.sign_hash(&domain_hash(
        b"BINDSUB1",
        &[
            &material.envelope_hash,
            &subject.public_key.x,
            &subject.public_key.y,
        ],
    ))?;

    let mut envelope_toml = String::new();
    append_issuer_context(&mut envelope_toml, &issuer.public_key, binding_context);
    append_array(&mut envelope_toml, "envelope_binding", &envelope_binding);
    append_array(&mut envelope_toml, "envelope_hash", &material.envelope_hash);
    append_array(&mut envelope_toml, "issuer_sig", &issuer_sig);

    let mut root_toml = String::new();
    append_issuer_context(&mut root_toml, &issuer.public_key, binding_context);
    append_array(&mut root_toml, "envelope_binding", &envelope_binding);
    append_array(&mut root_toml, "credential_binding", &credential_binding);
    append_array(&mut root_toml, "envelope_hash", &material.envelope_hash);
    append_array(&mut root_toml, "merkle_root", &material.merkle_root);
    append_array(
        &mut root_toml,
        "issuer_root_bind_sig",
        &issuer_root_bind_sig,
    );

    let mut claim_toml = String::new();
    append_issuer_context(&mut claim_toml, &issuer.public_key, binding_context);
    append_array(&mut claim_toml, "session_binding", &session_binding);
    append_array(&mut claim_toml, "credential_binding", &credential_binding);
    append_u32(&mut claim_toml, "val_len", material.val_len);
    append_array(&mut claim_toml, "val_pub", &material.val_pub);
    append_array(&mut claim_toml, "name_hash", &material.name_hash);
    append_array(&mut claim_toml, "envelope_hash", &material.envelope_hash);
    append_array(&mut claim_toml, "merkle_root", &material.merkle_root);
    append_array(
        &mut claim_toml,
        "issuer_subject_bind_sig",
        &issuer_subject_bind_sig,
    );
    append_public_key(&mut claim_toml, "subject", &subject.public_key);
    if let Some(persona) = persona {
        let persona_comp = persona.compressed_public_key();
        let subject_link_sig = subject.sign_hash(&domain_hash(b"LINK1", &[&persona_comp]))?;
        append_public_key(&mut claim_toml, "persona", &persona.public_key);
        append_array(&mut claim_toml, "subject_link_sig", &subject_link_sig);
    }
    append_array(&mut claim_toml, "salt", &material.salt);
    append_u32(&mut claim_toml, "index", 0);
    append_u32(&mut claim_toml, "path_len", CLAIM_TREE_DEPTH_U32);
    append_path(&mut claim_toml, "path", &material.path);

    let status_chunk = [0_u8; HASH_BYTES];
    let status_leaf = domain_hash(b"RMCSL1", &[&status_chunk]);
    let status_root = domain_hash(b"RMCSR1", &[&STATUS_LENGTH.to_be_bytes(), &status_leaf]);
    let status_list_id = domain_hash(b"LIST1", &[&issuer.public_key.x, &issuer.public_key.y]);
    let status_url_hash = domain_hash(b"", &[STATUS_URL]);
    let status_index = 0_u64;
    let signature_hash = domain_hash(
        b"BINDVLD1",
        &[
            &material.envelope_hash,
            &material.merkle_root,
            &STATUS_VALID_FROM.to_be_bytes(),
            &STATUS_VALID_UNTIL.to_be_bytes(),
            &status_url_hash,
            &status_list_id,
            &status_index.to_be_bytes(),
            &[STATUS_PURPOSE_REVOCATION],
        ],
    );
    let status_signature = issuer.sign_hash(&signature_hash)?;
    let mut status_toml = String::new();
    append_array(&mut status_toml, "challenge", &binding_context.challenge);
    append_array(
        &mut status_toml,
        "audience_hash",
        &binding_context.audience_hash,
    );
    append_array(
        &mut status_toml,
        "transaction_data_hash",
        &binding_context.transaction_data_hash,
    );
    status_toml.push_str("\n[slot]\n");
    append_array(&mut status_toml, "issuer_x", &issuer.public_key.x);
    append_array(&mut status_toml, "issuer_y", &issuer.public_key.y);
    append_u64(&mut status_toml, "presentation_expiry", EXPIRY_UNIX);
    append_array(&mut status_toml, "credential_binding", &credential_binding);
    append_array(&mut status_toml, "status_root", &status_root);
    append_u64(&mut status_toml, "status_length", STATUS_LENGTH);
    append_array(&mut status_toml, "status_list_id", &status_list_id);
    append_array(&mut status_toml, "status_url_hash", &status_url_hash);
    append_u64(
        &mut status_toml,
        "status_purpose",
        u64::from(STATUS_PURPOSE_REVOCATION),
    );
    append_u64(&mut status_toml, "verifier_now", STATUS_VERIFIER_NOW);
    status_toml.push_str("\n[witness]\n");
    append_array(&mut status_toml, "envelope_hash", &material.envelope_hash);
    append_array(&mut status_toml, "claims_root", &material.merkle_root);
    append_array(
        &mut status_toml,
        "issuer_validity_status_signature",
        &status_signature,
    );
    append_u64(&mut status_toml, "valid_from", STATUS_VALID_FROM);
    append_u64(&mut status_toml, "valid_until", STATUS_VALID_UNTIL);
    append_u64(&mut status_toml, "status_index", status_index);
    append_array(&mut status_toml, "status_chunk", &status_chunk);
    append_u32(&mut status_toml, "path_len", 0);
    append_path(
        &mut status_toml,
        "path",
        &[[0_u8; HASH_BYTES]; STATUS_PATH_DEPTH],
    );

    Ok(CredentialFixture {
        base_path,
        envelope_toml,
        root_toml,
        claim_toml,
        status_toml,
        issuer_public_key: issuer.public_key,
        subject_public_key: subject.public_key,
        session_binding,
        credential_binding,
    })
}

fn credential_path(base_path: &str, stage: &str) -> Result<&'static str, FixtureError> {
    match (base_path, stage) {
        ("direct/credential-a", "credential_envelope") => {
            Ok("direct/credential-a/credential_envelope/Prover.toml")
        }
        ("direct/credential-a", "credential_root") => {
            Ok("direct/credential-a/credential_root/Prover.toml")
        }
        ("direct/credential-a", "claim") => Ok("direct/credential-a/claim/Prover.toml"),
        ("direct/credential-a", "issuer_credential_status") => {
            Ok("direct/credential-a/issuer_credential_status/Prover.toml")
        }
        ("credential-a", "credential_envelope") => {
            Ok("credential-a/credential_envelope/Prover.toml")
        }
        ("credential-a", "credential_root") => Ok("credential-a/credential_root/Prover.toml"),
        ("credential-a", "claim") => Ok("credential-a/claim/Prover.toml"),
        ("credential-a", "issuer_credential_status") => {
            Ok("credential-a/issuer_credential_status/Prover.toml")
        }
        ("credential-b", "credential_envelope") => {
            Ok("credential-b/credential_envelope/Prover.toml")
        }
        ("credential-b", "credential_root") => Ok("credential-b/credential_root/Prover.toml"),
        ("credential-b", "claim") => Ok("credential-b/claim/Prover.toml"),
        ("credential-b", "issuer_credential_status") => {
            Ok("credential-b/issuer_credential_status/Prover.toml")
        }
        ("wrong-persona/credential-a", "credential_envelope") => {
            Ok("wrong-persona/credential-a/credential_envelope/Prover.toml")
        }
        ("wrong-persona/credential-a", "credential_root") => {
            Ok("wrong-persona/credential-a/credential_root/Prover.toml")
        }
        ("wrong-persona/credential-a", "claim") => {
            Ok("wrong-persona/credential-a/claim/Prover.toml")
        }
        ("wrong-persona/credential-a", "issuer_credential_status") => {
            Ok("wrong-persona/credential-a/issuer_credential_status/Prover.toml")
        }
        _ => Err(FixtureError::Io),
    }
}
