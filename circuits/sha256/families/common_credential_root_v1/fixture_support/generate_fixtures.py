# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Generate deterministic, synthetic circuit witnesses for review and testing."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16
)
LINEAGE_NAME_HASH = hashlib.sha256(b"reallyme.lineage.v1").digest()
EXTRACT_SALT = hashlib.sha256(
    b"ReallyMe/common-credential-root/v1/HKDF-Extract"
).digest()
FIXTURE_REQUEST_UNIX = 1_900_000_000
FIXTURE_EXPIRY_UNIX = FIXTURE_REQUEST_UNIX + 240


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def key_pair(scalar: int) -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    return (
        private,
        numbers.x.to_bytes(32, "big"),
        numbers.y.to_bytes(32, "big"),
    )


def sign(private: ec.EllipticCurvePrivateKey, message_digest: bytes) -> bytes:
    encoded = private.sign(
        message_digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True),
    )
    r, s = utils.decode_dss_signature(encoded)
    s = min(s, P256_ORDER - s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def selected_claim(label: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    name_hash = digest(b"fixture selected claim name:" + label)
    value = b"verified:" + label
    salt = digest(b"fixture selected claim salt:" + label)[:16]
    inner = digest(b"CLM1" + len(value).to_bytes(4, "big") + value + salt)
    leaf = digest(b"LEAF1" + name_hash + inner)
    return name_hash, value, salt, leaf


CLAIM_TREE_DEPTH = 6


def empty_subtree_digests() -> list[bytes]:
    """Digests of empty claim subtrees at heights zero through five.

    An empty leaf is 32 zero bytes. Height k is the node over two empty
    subtrees of height k - 1.
    """
    digests = [bytes(32)]
    for _ in range(1, CLAIM_TREE_DEPTH):
        digests.append(digest(b"NODE1" + digests[-1] + digests[-1]))
    return digests


def fold_claim_path(leaf: bytes, index: int, path: list[bytes]) -> bytes:
    """Root reached from one leaf through a full fixed-depth path."""
    if len(path) != CLAIM_TREE_DEPTH:
        raise ValueError("claim path must have the fixed tree depth")
    node = leaf
    for level, sibling in enumerate(path):
        if (index >> level) & 1 == 0:
            node = digest(b"NODE1" + node + sibling)
        else:
            node = digest(b"NODE1" + sibling + node)
    return node


def two_leaf_claim_path(sibling: bytes) -> list[bytes]:
    """Fixed-depth path for either leaf of a two-leaf tree padded with empties."""
    return [sibling] + empty_subtree_digests()[1:]


def slot(
    issuer_scalar: int,
    subject_scalar: int,
    label: bytes,
    prk: bytes,
    challenge: bytes,
    audience_hash: bytes,
    transaction_hash: bytes,
    join_salt: bytes,
) -> tuple[dict[str, object], dict[str, object]]:
    issuer_private, issuer_x, issuer_y = key_pair(issuer_scalar)
    _, subject_x, subject_y = key_pair(subject_scalar)
    envelope_hash = digest(b"fixture envelope:" + label)
    did_hash = digest(b"did:me:fixture:" + label)
    nonce = digest(b"fixture relationship nonce:" + label)
    claim_salt = digest(b"fixture claim salt:" + label)[:16]
    context_hash = digest(
        b"RMCTX1"
        + issuer_x
        + issuer_y
        + did_hash
        + subject_x
        + subject_y
        + nonce
    )
    lineage_tag = hmac.new(prk, context_hash + b"\x01", hashlib.sha256).digest()
    value = context_hash + lineage_tag
    inner = digest(b"CLM1" + len(value).to_bytes(4, "big") + value + claim_salt)
    lineage_leaf = digest(b"LEAF1" + LINEAGE_NAME_HASH + inner)
    _, _, _, claim_leaf = selected_claim(label)
    lineage_path = two_leaf_claim_path(claim_leaf)
    merkle_root = fold_claim_path(lineage_leaf, 0, lineage_path)
    root_signature = sign(
        issuer_private, digest(b"BINDMRK1" + envelope_hash + merkle_root)
    )
    expiry_unix = FIXTURE_EXPIRY_UNIX
    subject_join = digest(
        b"RMSJOIN1"
        + subject_x
        + subject_y
        + join_salt
        + challenge
        + audience_hash
        + transaction_hash
    )
    credential_binding = digest(
        b"CREDB1"
        + issuer_x
        + issuer_y
        + envelope_hash
        + merkle_root
        + challenge
        + audience_hash
        + transaction_hash
        + expiry_unix.to_bytes(8, "big")
    )
    public = {
        "issuer_x": issuer_x,
        "issuer_y": issuer_y,
        "expiry_unix": expiry_unix,
        "credential_binding": credential_binding,
        "subject_join": subject_join,
    }
    witness = {
        "envelope_hash": envelope_hash,
        "merkle_root": merkle_root,
        "issuer_root_bind_sig": root_signature,
        "subject_x": subject_x,
        "subject_y": subject_y,
        "relationship_did_hash": did_hash,
        "relationship_nonce": nonce,
        "claim_salt": claim_salt,
        "leaf_index": 0,
        "path_len": CLAIM_TREE_DEPTH,
        "path": lineage_path,
    }
    return public, witness


def toml_value(value: object) -> str:
    if isinstance(value, bytes):
        return "[" + ", ".join(str(byte) for byte in value) + "]"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, int):
        return str(value)
    raise TypeError("unsupported synthetic fixture field")
