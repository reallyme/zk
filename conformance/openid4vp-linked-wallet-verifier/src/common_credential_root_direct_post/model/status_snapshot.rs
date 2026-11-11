// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::p256;
use reallyme_zk_api::{common_root::ZkRootStatusSnapshot, keys::ZkStatusAuthorityPublicKey};
use reallyme_zk_proto_codec::common_credential_root_status_snapshot::{
    decode_root_status_snapshot, encode_root_status_snapshot,
};
use zeroize::Zeroizing;

use crate::error::HarnessError;

pub(super) fn signed_status_snapshot(
    verification_time_unix: u64,
    status_root: [u8; 32],
    expires_unix: u64,
) -> Result<(ZkRootStatusSnapshot, ZkStatusAuthorityPublicKey), HarnessError> {
    const STATUS_SEQUENCE: u64 = 1;
    let issued_unix = verification_time_unix
        .checked_sub(2)
        .ok_or(HarnessError::InvalidLength)?;
    // The harness signs an authority snapshot rather than injecting a raw
    // root into verifier policy. The scalar is fixture-only, never released.
    let mut authority_secret = Zeroizing::new([0_u8; 32]);
    authority_secret[31] = 37;
    let (compressed, _owned_secret) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&authority_secret)?;
    let uncompressed = reallyme_crypto::p256::decompress_public_key(&compressed)?;
    let public_key =
        <[u8; 65]>::try_from(uncompressed.as_slice()).map_err(|_| HarnessError::InvalidLength)?;
    let mut x = [0_u8; 32];
    let mut y = [0_u8; 32];
    x.copy_from_slice(&public_key[1..33]);
    y.copy_from_slice(&public_key[33..65]);
    let signer = ZkStatusAuthorityPublicKey { x, y };
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(
        status_root,
        issued_unix,
        expires_unix,
        STATUS_SEQUENCE,
    );
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let signature_der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(authority_secret.as_ref(), &digest)?;
    let signature = p256::p256_ecdsa_der_to_jose_signature(&signature_der)?;
    let snapshot = ZkRootStatusSnapshot::try_from_parts(
        status_root,
        issued_unix,
        expires_unix,
        STATUS_SEQUENCE,
        signer,
        signature,
    )?;
    let snapshot_bytes = encode_root_status_snapshot(&snapshot)?;
    let snapshot = decode_root_status_snapshot(&snapshot_bytes)?;
    Ok((snapshot, signer))
}
