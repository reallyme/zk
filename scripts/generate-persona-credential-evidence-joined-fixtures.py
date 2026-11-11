# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Generate deterministic joined prepared-claim and current-status Noir fixtures."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT = Path(__file__).resolve().parent.parent
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ZERO32 = bytes(32)
ISSUER = ec.derive_private_key(11, ec.SECP256R1())
SUBJECT = ec.derive_private_key(13, ec.SECP256R1())
PERSONA = ec.derive_private_key(17, ec.SECP256R1())
PRIVATE_HOLDER = ec.derive_private_key(19, ec.SECP256R1())
ENVELOPE = sha256(b"prepared-fixture:issuer-envelope").digest()
CLAIM_NAME = sha256(b"over_18").digest()
CLAIM_VALUE = b"true"
CLAIM_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
LIST_ID = sha256(b"prepared-fixture:shared-issuer-status-list").digest()
LIST_URL_HASH = sha256(b"https://issuer.example/status/shared").digest()
VALID_FROM = 1_700_000_000
VALID_UNTIL = 1_900_000_000
PREPARED_FROM = 1_800_000_000
PREPARED_UNTIL = 1_800_086_400
STATUS_LENGTH = 8
STATUS_INDEX = 3


def be64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def array(value: bytes) -> str:
    return "[" + ", ".join(str(byte) for byte in value) + "]"


def public_coordinates(key: ec.EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    public = key.public_key().public_numbers()
    return public.x.to_bytes(32, "big"), public.y.to_bytes(32, "big")


def compressed_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    x, y = public_coordinates(key)
    return bytes([2 | (y[-1] & 1)]) + x


def sign_digest(key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
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


def lane_hash(lane: str, value: bytes) -> bytes:
    if lane == "sha256":
        return sha256(value).digest()
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
    return digest


def fields(values: dict[str, bytes | int | list[bytes]]) -> list[str]:
    output = []
    for name, value in values.items():
        if isinstance(value, bytes):
            rendered = array(value)
        elif isinstance(value, list):
            rendered = "[" + ", ".join(array(item) for item in value) + "]"
        else:
            rendered = str(value)
        output.append(f"{name} = {rendered}")
    return output


def write_fixture(folder: Path, name: str, sections: list[tuple[str | None, dict]]) -> None:
    lines = [
        "# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved",
        "#",
        "# SPDX-License-Identifier: MIT OR Apache-2.0",
        "# Synthetic, deterministic circuit witness. No production secret is used.",
    ]
    for section_name, values in sections:
        if section_name is not None:
            lines.append(f"[{section_name}]")
        lines.extend(fields(values))
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.toml").write_text("\n".join(lines) + "\n")


CLAIM_TREE_DEPTH = 6


def empty_claim_subtrees(lane: str) -> list[bytes]:
    """Digests of empty claim subtrees at heights zero through five."""
    digests = [ZERO32]
    for _ in range(1, CLAIM_TREE_DEPTH):
        digests.append(lane_hash(lane, b"NODE1" + digests[-1] + digests[-1]))
    return digests


def first_leaf_root(lane: str, leaf: bytes, path: list[bytes]) -> bytes:
    """Root of the fixed-depth claim tree whose only issued leaf is slot zero."""
    node = leaf
    for sibling in path:
        node = lane_hash(lane, b"NODE1" + node + sibling)
    return node


def generate_lane(lane: str) -> None:
    folder = ROOT / "circuits" / lane / "families" / "persona_credential_evidence_v1"
    issuer_x, issuer_y = public_coordinates(ISSUER)
    subject_x, subject_y = public_coordinates(SUBJECT)
    persona_x, persona_y = public_coordinates(PERSONA)
    claim_inner = lane_hash(
        lane, b"CLM1" + len(CLAIM_VALUE).to_bytes(4, "big") + CLAIM_VALUE + CLAIM_SALT
    )
    claim_leaf = lane_hash(lane, b"LEAF1" + CLAIM_NAME + claim_inner)
    claim_path = empty_claim_subtrees(lane)
    claims_root = first_leaf_root(lane, claim_leaf, claim_path)
    # SSI signs this issuer transcript with SHA-256 in both hash lanes.
    subject_bind = sign_digest(
        ISSUER, sha256(b"BINDSUB1" + ENVELOPE + subject_x + subject_y).digest()
    )
    root_bind = sign_digest(
        ISSUER, sha256(b"BINDMRK1" + ENVELOPE + claims_root).digest()
    )
    status_chunk = ZERO32
    status_leaf = sha256(b"RMCSL1" + status_chunk).digest()
    status_root = sha256(b"RMCSR1" + be64(STATUS_LENGTH) + status_leaf).digest()
    validity = sign_digest(
        ISSUER,
        sha256(
            b"BINDVLD1"
            + ENVELOPE
            + claims_root
            + be64(VALID_FROM)
            + be64(VALID_UNTIL)
            + LIST_URL_HASH
            + LIST_ID
            + be64(STATUS_INDEX)
            + bytes([1])
        ).digest(),
    )
    base_claim = {
        "pk_issuer_x": issuer_x,
        "pk_issuer_y": issuer_y,
        "prepared_from": PREPARED_FROM,
        "prepared_until": PREPARED_UNTIL,
        "val_len": len(CLAIM_VALUE),
        "val_pub": CLAIM_VALUE + bytes(64 - len(CLAIM_VALUE)),
        "name_hash": CLAIM_NAME,
        "envelope_hash": ENVELOPE,
        "merkle_root": claims_root,
        "issuer_subject_bind_sig": subject_bind,
        "pk_subject_x": subject_x,
        "pk_subject_y": subject_y,
        "salt": CLAIM_SALT,
        "index": 0,
        "path_len": CLAIM_TREE_DEPTH,
        "path": claim_path,
    }
    for mode, holder in (("public", PERSONA), ("private", PRIVATE_HOLDER)):
        holder_x, holder_y = public_coordinates(holder)
        token_nonce = sha256(b"prepared-fixture:" + mode.encode() + b":token").digest()
        credential_binding = lane_hash(
            lane,
            b"PRECB2"
            + issuer_x
            + issuer_y
            + ENVELOPE
            + claims_root
            + subject_x
            + subject_y
            + holder_x
            + holder_y
            + token_nonce
            + be64(PREPARED_FROM)
            + be64(PREPARED_UNTIL),
        )
        shared_evidence = {
            "pk_issuer_x": issuer_x,
            "pk_issuer_y": issuer_y,
            "holder_x": holder_x,
            "holder_y": holder_y,
            "token_nonce": token_nonce,
            "prepared_from": PREPARED_FROM,
            "prepared_until": PREPARED_UNTIL,
            "credential_binding": credential_binding,
            "envelope_hash": ENVELOPE,
            "claims_root": claims_root,
            "pk_subject_x": subject_x,
            "pk_subject_y": subject_y,
        }
        issuer_envelope = dict(shared_evidence)
        issuer_envelope.update(
            {
                "pk_subject_x": subject_x,
                "pk_subject_y": subject_y,
                "issuer_envelope_sig": sign_digest(ISSUER, ENVELOPE),
                "issuer_subject_bind_sig": subject_bind,
            }
        )
        claim_root = dict(shared_evidence)
        claim_root["issuer_root_bind_sig"] = root_bind
        for stage, values, signature_field in (
            ("issuer_envelope", issuer_envelope, "issuer_subject_bind_sig"),
            ("claim_root", claim_root, "issuer_root_bind_sig"),
        ):
            stage_folder = folder / stage
            # The public mode fixture is the source of the stable stage
            # sample. The private fixture exercises the same circuit with a
            # distinct one-time holder key and token-specific join.
            fixture_name = "PublicJoined" if mode == "public" else "PrivateJoined"
            write_fixture(stage_folder, fixture_name, [(None, values)])
            if mode == "public":
                write_fixture(stage_folder, "Prover", [(None, values)])
            invalid = dict(values)
            invalid[signature_field] = bytes(64)
            write_fixture(stage_folder, f"{fixture_name}WrongSignature", [(None, invalid)])
            if mode == "public":
                write_fixture(stage_folder, "ProverWrongSignature", [(None, invalid)])
            if stage == "issuer_envelope":
                invalid_envelope = dict(values)
                invalid_envelope["issuer_envelope_sig"] = bytes(64)
                write_fixture(
                    stage_folder,
                    f"{fixture_name}WrongEnvelopeSignature",
                    [(None, invalid_envelope)],
                )
            wrong_join = dict(values)
            wrong_join["credential_binding"] = bytes(32)
            write_fixture(stage_folder, f"{fixture_name}WrongJoin", [(None, wrong_join)])
        claim = dict(base_claim)
        claim.update(
            {
                "holder_x": holder_x,
                "holder_y": holder_y,
                "token_nonce": token_nonce,
                "credential_binding": credential_binding,
                "subject_link_sig": sign_digest(
                    SUBJECT, lane_hash(lane, b"LINK1" + compressed_key(PERSONA if mode == "private" else holder))
                ),
            }
        )
        if mode == "private":
            claim["pk_persona_x"] = persona_x
            claim["pk_persona_y"] = persona_y
            claim["persona_token_auth_sig"] = sign_digest(
                PERSONA,
                sha256(
                    b"PKAUTH1"
                    + compressed_key(holder)
                    + token_nonce
                    + be64(PREPARED_FROM)
                    + be64(PREPARED_UNTIL)
                ).digest(),
            )
        write_fixture(folder / f"{mode}_claim", "Prover", [(None, claim)])
        # The same claim as the bare root of an unpadded tree. Its join is
        # recomputed for that root, so only the fixed-depth rule rejects it.
        short_path = dict(claim)
        short_path.update(
            {
                "merkle_root": claim_leaf,
                "path_len": 0,
                "path": [ZERO32] * CLAIM_TREE_DEPTH,
                "credential_binding": lane_hash(
                    lane,
                    b"PRECB2"
                    + issuer_x
                    + issuer_y
                    + ENVELOPE
                    + claim_leaf
                    + subject_x
                    + subject_y
                    + holder_x
                    + holder_y
                    + token_nonce
                    + be64(PREPARED_FROM)
                    + be64(PREPARED_UNTIL),
                ),
            }
        )
        write_fixture(folder / f"{mode}_claim", "ProverShortPath", [(None, short_path)])
        validity_slot = {
            "issuer_x": issuer_x,
            "issuer_y": issuer_y,
            "holder_x": holder_x,
            "holder_y": holder_y,
            "token_nonce": token_nonce,
            "prepared_from": PREPARED_FROM,
            "prepared_until": PREPARED_UNTIL,
            "credential_binding": credential_binding,
            "status_list_id": LIST_ID,
            "status_url_hash": LIST_URL_HASH,
            "status_purpose": 1,
        }
        validity_witness = {
            "envelope_hash": ENVELOPE,
            "claims_root": claims_root,
            "subject_x": subject_x,
            "subject_y": subject_y,
            "issuer_validity_status_signature": validity,
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "status_index": STATUS_INDEX,
        }
        write_fixture(
            folder / "signed_validity",
            f"{mode.capitalize()}Joined",
            [("slot", validity_slot), ("witness", validity_witness)],
        )
        if mode == "public":
            write_fixture(
                folder / "signed_validity",
                "Prover",
                [("slot", validity_slot), ("witness", validity_witness)],
            )
        validity_negatives = {
            "WrongSignature": (
                validity_slot,
                {**validity_witness, "issuer_validity_status_signature": bytes(64)},
            ),
            "OutsideIssuerWindow": (
                {**validity_slot, "prepared_until": VALID_UNTIL + 1},
                validity_witness,
            ),
            "WrongStatusIndex": (
                validity_slot,
                {**validity_witness, "status_index": STATUS_INDEX + 1},
            ),
            "WrongStatusList": (
                {**validity_slot, "status_list_id": bytes(32)},
                validity_witness,
            ),
            "WrongSubject": (
                validity_slot,
                {**validity_witness, "subject_x": bytes(32)},
            ),
            "WrongJoin": (
                {**validity_slot, "credential_binding": bytes(32)},
                validity_witness,
            ),
        }
        for negative_name, (negative_slot, negative_witness) in validity_negatives.items():
            write_fixture(
                folder / "signed_validity",
                f"{mode.capitalize()}Joined{negative_name}",
                [("slot", negative_slot), ("witness", negative_witness)],
            )
        slot = {
            "issuer_x": issuer_x,
            "issuer_y": issuer_y,
            "holder_x": holder_x,
            "holder_y": holder_y,
            "token_nonce": token_nonce,
            "prepared_from": PREPARED_FROM,
            "prepared_until": PREPARED_UNTIL,
            "credential_binding": credential_binding,
            "status_root": status_root,
            "status_length": STATUS_LENGTH,
            "status_list_id": LIST_ID,
            "status_url_hash": LIST_URL_HASH,
            "status_purpose": 1,
        }
        witness = {
            "envelope_hash": ENVELOPE,
            "claims_root": claims_root,
            "subject_x": subject_x,
            "subject_y": subject_y,
            "issuer_validity_status_signature": validity,
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "status_index": STATUS_INDEX,
            "status_chunk": status_chunk,
            "path_len": 0,
            "path": [ZERO32] * 12,
        }
        write_fixture(
            folder / "current_state", f"{mode.capitalize()}Joined", [("slot", slot), ("witness", witness)]
        )


for hash_lane in ("sha256", "poseidon2"):
    generate_lane(hash_lane)
