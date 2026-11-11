#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Generate deterministic Noir fixtures for the request-bound claim families.

Covers `credential_subject_claim_v1` and `private_persona_claim_v1` in both
credential hash lanes: the session, credential-envelope, credential-root, claim,
and diagnostic `claim_bundle_4` stages. One synthetic credential with a
fixed-depth claim tree backs every stage, so the stages of one family join.

Run with `check` to verify the checked-in fixtures instead of writing them.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import subprocess
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT = Path(__file__).resolve().parent.parent
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ZERO32 = bytes(32)

# Synthetic keys only. Never use these scalars for issuance or presentation.
ISSUER = ec.derive_private_key(11, ec.SECP256R1())
SUBJECT = ec.derive_private_key(13, ec.SECP256R1())
PERSONA = ec.derive_private_key(17, ec.SECP256R1())

CHALLENGE = b"12345678901234567890123456789012"
AUDIENCE_HASH = sha256(b"https://verifier.example").digest()
TRANSACTION_DATA_HASH = bytes([3]) * 32
EXPIRY_UNIX = 1_750_000_000
ENVELOPE_HASH = sha256(b"claim-family-fixture:credential-envelope").digest()

CLAIM_TREE_DEPTH = 6
MAX_VALUE_BYTES = 64
SALT_BYTES = 16
BUNDLE_SLOTS = 4
ISSUED_CLAIM_COUNT = 18

# The single disclosed claim occupies slot zero. The bundle discloses four
# further claims spread across the tree; values are canonical CBOR text strings.
SELECTED_CLAIM = (0, b"address.locality", b"kSpringfield")
BUNDLE_CLAIMS = (
    (17, b"tax_identifier", b"mTAX-4839-2217"),
    (9, b"legal_name", b"x(Alexandria Catherine Montgomery-Sinclair"),
    (1, b"birth_date", b"j1994-11-23"),
    (10, b"passport_number", b"iP12345678"),
)

FAMILIES = ("credential_subject_claim_v1", "private_persona_claim_v1")
LANES = ("sha256", "poseidon2")

HEADER = [
    "# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved",
    "#",
    "# SPDX-License-Identifier: MIT OR Apache-2.0",
    "#",
    "# Deterministic synthetic keys only. Never use these keys for issuance.",
    "",
]


def be32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def be64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def public_coordinates(key: ec.EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    public = key.public_key().public_numbers()
    return public.x.to_bytes(32, "big"), public.y.to_bytes(32, "big")


def compressed_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    x, y = public_coordinates(key)
    return bytes([2 | (y[-1] & 1)]) + x


def sign_digest(key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    """Deterministic low-s P-256 signature over one 32-byte digest."""
    if len(digest) != 32:
        raise ValueError("P-256 digest must be 32 bytes")
    der = key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True),
    )
    r, s = utils.decode_dss_signature(der)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


_POSEIDON2_CACHE: dict[bytes, bytes] = {}


def lane_hash(lane: str, value: bytes) -> bytes:
    """Credential hash of one byte string in the selected lane."""
    if lane == "sha256":
        return sha256(value).digest()
    cached = _POSEIDON2_CACHE.get(value)
    if cached is not None:
        return cached
    fixture_bin = os.environ.get(
        "POSEIDON2_FIXTURE_BIN", str(ROOT / "target/debug/poseidon2-bounded-fixture")
    )
    result = subprocess.run(
        [fixture_bin],
        input=",".join(str(byte) for byte in value) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    digest = bytes(int(byte) for byte in result.stdout.strip().split(","))
    if len(digest) != 32:
        raise ValueError("Poseidon2 fixture tool produced an invalid digest")
    _POSEIDON2_CACHE[value] = digest
    return digest


def claim_salt(index: int) -> bytes:
    return sha256(b"claim-family-fixture:salt:" + be32(index)).digest()[:SALT_BYTES]


def issued_claims() -> list[tuple[bytes, bytes, bytes]]:
    """Name hash, value, and salt of every issued leaf, in leaf order."""
    named = {index: (name, value) for index, name, value in (SELECTED_CLAIM, *BUNDLE_CLAIMS)}
    claims = []
    for index in range(ISSUED_CLAIM_COUNT):
        name, value = named.get(
            index,
            (b"filler.claim." + str(index).encode(), b"ffiller"),
        )
        if not 1 <= len(value) <= MAX_VALUE_BYTES:
            raise ValueError("synthetic claim value is out of range")
        claims.append((sha256(name).digest(), value, claim_salt(index)))
    return claims


def leaf_digest(lane: str, name_hash: bytes, value: bytes, salt: bytes) -> bytes:
    inner = lane_hash(lane, b"CLM1" + be32(len(value)) + value + salt)
    return lane_hash(lane, b"LEAF1" + name_hash + inner)


class ClaimTree:
    """Fixed-depth claim tree padded with canonical empty subtrees.

    An empty leaf is 32 zero bytes; the empty subtree at each higher level is
    the node over two empty subtrees below it. `depth` shorter than the fixed
    depth builds the unpadded tree used only by negative fixtures.
    """

    def __init__(self, lane: str, leaves: list[bytes], depth: int = CLAIM_TREE_DEPTH):
        if not 1 <= len(leaves) <= 1 << depth:
            raise ValueError("synthetic claim tree has an invalid leaf count")
        self.lane = lane
        self.depth = depth
        self.levels = [list(leaves)]
        self.empties = [ZERO32]
        for _ in range(depth):
            below = self.levels[-1]
            empty = self.empties[-1]
            parents = []
            for position in range(0, len(below), 2):
                right = below[position + 1] if position + 1 < len(below) else empty
                parents.append(lane_hash(lane, b"NODE1" + below[position] + right))
            self.levels.append(parents)
            self.empties.append(lane_hash(lane, b"NODE1" + empty + empty))
        if len(self.levels[-1]) != 1:
            raise ValueError("synthetic claim tree did not reduce to one root")
        self.root = self.levels[-1][0]

    def path(self, index: int) -> list[bytes]:
        """Siblings from leaf to root, zero-filled to the circuit's path width."""
        siblings = []
        for level in range(self.depth):
            row = self.levels[level]
            sibling = index ^ 1
            siblings.append(row[sibling] if sibling < len(row) else self.empties[level])
            index >>= 1
        return siblings + [ZERO32] * (CLAIM_TREE_DEPTH - self.depth)


def render(value: object) -> str:
    if isinstance(value, bytes):
        return "[" + ",".join(str(byte) for byte in value) + "]"
    if isinstance(value, list):
        return "[" + ",".join(render(item) for item in value) + "]"
    if isinstance(value, int):
        return str(value)
    raise TypeError("unsupported synthetic fixture field")


def fixture_text(fields: dict[str, object]) -> str:
    return "\n".join(HEADER + [f"{name} = {render(value)}" for name, value in fields.items()]) + "\n"


def binding_context() -> bytes:
    return CHALLENGE + AUDIENCE_HASH + TRANSACTION_DATA_HASH + be64(EXPIRY_UNIX)


def public_context() -> dict[str, object]:
    return {
        "challenge": CHALLENGE,
        "audience_hash": AUDIENCE_HASH,
        "transaction_data_hash": TRANSACTION_DATA_HASH,
        "expiry_unix": EXPIRY_UNIX,
    }


def session_stage(lane: str, family: str) -> tuple[dict[str, object], bytes]:
    """Session fixture and the session binding shared with the claim stages."""
    if family == "credential_subject_claim_v1":
        holder, message_tag, binding_tag, key_name, signature_name = (
            SUBJECT, b"SESS1", b"SESSB1", "subject", "subject_sig",
        )
    else:
        holder, message_tag, binding_tag, key_name, signature_name = (
            PERSONA, b"PERS2", b"PSESB2", "persona", "persona_sig",
        )
    holder_x, holder_y = public_coordinates(holder)
    binding = lane_hash(lane, binding_tag + holder_x + holder_y + binding_context())
    fields = {
        **public_context(),
        "session_binding": binding,
        f"pk_{key_name}_x": holder_x,
        f"pk_{key_name}_y": holder_y,
        signature_name: sign_digest(holder, lane_hash(lane, message_tag + binding_context())),
    }
    return fields, binding


def credential_binding(lane: str, root: bytes) -> bytes:
    issuer_x, issuer_y = public_coordinates(ISSUER)
    return lane_hash(
        lane, b"CREDB1" + issuer_x + issuer_y + ENVELOPE_HASH + root + binding_context()
    )


def issuer_context() -> dict[str, object]:
    issuer_x, issuer_y = public_coordinates(ISSUER)
    return {"pk_issuer_x": issuer_x, "pk_issuer_y": issuer_y, **public_context()}


def holder_witness(lane: str, family: str) -> dict[str, object]:
    """Subject binding and, for the persona family, the subject's persona link."""
    subject_x, subject_y = public_coordinates(SUBJECT)
    fields: dict[str, object] = {
        "issuer_subject_bind_sig": sign_digest(
            ISSUER, lane_hash(lane, b"BINDSUB1" + ENVELOPE_HASH + subject_x + subject_y)
        ),
        "pk_subject_x": subject_x,
        "pk_subject_y": subject_y,
    }
    if family == "private_persona_claim_v1":
        persona_x, persona_y = public_coordinates(PERSONA)
        fields["pk_persona_x"] = persona_x
        fields["pk_persona_y"] = persona_y
        fields["subject_link_sig"] = sign_digest(
            SUBJECT, lane_hash(lane, b"LINK1" + compressed_key(PERSONA))
        )
    return fields


def claim_stage(
    lane: str, family: str, tree: ClaimTree, session_binding: bytes,
) -> dict[str, object]:
    index = SELECTED_CLAIM[0]
    name_hash, value, salt = issued_claims()[index]
    return {
        **issuer_context(),
        "session_binding": session_binding,
        "credential_binding": credential_binding(lane, tree.root),
        "val_len": len(value),
        "val_pub": value + bytes(MAX_VALUE_BYTES - len(value)),
        "name_hash": name_hash,
        "envelope_hash": ENVELOPE_HASH,
        "merkle_root": tree.root,
        **holder_witness(lane, family),
        "salt": salt,
        "index": index,
        "path_len": tree.depth,
        "path": tree.path(index),
    }


def bundle_stage(
    lane: str, family: str, tree: ClaimTree, session_binding: bytes,
) -> dict[str, object]:
    claims = issued_claims()
    # The circuit requires disclosed entries in strictly ascending name-hash order.
    disclosed = sorted(
        ((claims[index][0], claims[index][1], claims[index][2], index) for index, _, _ in BUNDLE_CLAIMS),
        key=lambda entry: entry[0],
    )
    if len(disclosed) != BUNDLE_SLOTS:
        raise ValueError("synthetic bundle must fill every slot")
    bundle_preimage = b"BUNDLE1" + binding_context() + be32(len(disclosed))
    for name_hash, value, _, _ in disclosed:
        bundle_preimage += name_hash + be32(len(value)) + value
    return {
        **issuer_context(),
        "session_binding": session_binding,
        "credential_binding": credential_binding(lane, tree.root),
        "bundle_count": len(disclosed),
        "bundle_hash": lane_hash(lane, bundle_preimage),
        "val_lens": [len(value) for _, value, _, _ in disclosed],
        "val_pubs": [value + bytes(MAX_VALUE_BYTES - len(value)) for _, value, _, _ in disclosed],
        "name_hashes": [name_hash for name_hash, _, _, _ in disclosed],
        "envelope_hash": ENVELOPE_HASH,
        "merkle_root": tree.root,
        **holder_witness(lane, family),
        "salts": [salt for _, _, salt, _ in disclosed],
        "indices": [index for _, _, _, index in disclosed],
        "path_lens": [tree.depth] * len(disclosed),
        "paths": [tree.path(index) for _, _, _, index in disclosed],
    }


PUBLIC_FIELDS = {
    "session": (
        "challenge", "audience_hash", "transaction_data_hash", "expiry_unix",
        "session_binding",
    ),
    "credential_envelope": (
        "pk_issuer_x", "pk_issuer_y", "challenge", "audience_hash",
        "transaction_data_hash", "expiry_unix", "envelope_binding",
    ),
    "credential_root": (
        "pk_issuer_x", "pk_issuer_y", "challenge", "audience_hash",
        "transaction_data_hash", "expiry_unix", "envelope_binding",
        "credential_binding",
    ),
    "claim": (
        "pk_issuer_x", "pk_issuer_y", "challenge", "audience_hash",
        "transaction_data_hash", "expiry_unix", "session_binding",
        "credential_binding", "val_len", "val_pub", "name_hash",
    ),
    "claim_bundle_4": (
        "pk_issuer_x", "pk_issuer_y", "challenge", "audience_hash",
        "transaction_data_hash", "expiry_unix", "session_binding",
        "credential_binding", "bundle_count", "bundle_hash",
    ),
}


def family_fixtures(lane: str, family: str) -> dict[str, str]:
    """Every fixture file of one family and lane, keyed by relative path."""
    issuer_x, issuer_y = public_coordinates(ISSUER)
    leaves = [leaf_digest(lane, *claim) for claim in issued_claims()]
    tree = ClaimTree(lane, leaves)
    session, session_binding = session_stage(lane, family)
    envelope_binding = lane_hash(
        lane, b"ENVB1" + issuer_x + issuer_y + ENVELOPE_HASH + binding_context()
    )
    envelope = {
        **issuer_context(),
        "envelope_binding": envelope_binding,
        "envelope_hash": ENVELOPE_HASH,
        # The v1 envelope stage verifies this signature over the digest directly.
        "issuer_sig": sign_digest(ISSUER, ENVELOPE_HASH),
    }
    root = {
        **issuer_context(),
        "envelope_binding": envelope_binding,
        "credential_binding": credential_binding(lane, tree.root),
        "envelope_hash": ENVELOPE_HASH,
        "merkle_root": tree.root,
        "issuer_root_bind_sig": sign_digest(
            ISSUER, lane_hash(lane, b"BINDMRK1" + ENVELOPE_HASH + tree.root)
        ),
    }
    stages = {
        "session": session,
        "credential_envelope": envelope,
        "credential_root": root,
        "claim": claim_stage(lane, family, tree, session_binding),
        "claim_bundle_4": bundle_stage(lane, family, tree, session_binding),
    }
    files = {}
    for stage, fields in stages.items():
        files[f"{stage}/Prover.toml"] = fixture_text(fields)
        files[f"{stage}/Verifier.toml"] = fixture_text(
            {name: fields[name] for name in PUBLIC_FIELDS[stage]}
        )
    # The same claims opened in a correctly bound tree one level short of the
    # fixed depth. Only the fixed-depth rule rejects these.
    short_tree = ClaimTree(lane, leaves, CLAIM_TREE_DEPTH - 1)
    files["claim/ProverShortPath.toml"] = fixture_text(
        claim_stage(lane, family, short_tree, session_binding)
    )
    files["claim_bundle_4/ProverShortPath.toml"] = fixture_text(
        bundle_stage(lane, family, short_tree, session_binding)
    )
    return files


def all_fixtures() -> dict[Path, str]:
    fixtures = {}
    for lane in LANES:
        for family in FAMILIES:
            folder = ROOT / "circuits" / lane / "families" / family
            for relative, text in family_fixtures(lane, family).items():
                fixtures[folder / relative] = text
    return fixtures


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "generate"
    if mode not in ("generate", "check") or len(sys.argv) > 2:
        print("usage: generate-claim-family-fixtures.py [generate|check]", file=sys.stderr)
        return 2
    fixtures = all_fixtures()
    if mode == "check":
        stale = [
            str(path.relative_to(ROOT))
            for path, text in fixtures.items()
            if not path.is_file() or path.read_text() != text
        ]
        if stale:
            print("claim-family fixtures are stale:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"claim-family fixtures match the generator ({len(fixtures)} files)")
        return 0
    for path, text in fixtures.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote {len(fixtures)} claim-family fixture files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
