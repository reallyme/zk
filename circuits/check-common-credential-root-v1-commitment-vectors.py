# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check fixed ZK claim-tree vectors independently of Noir fixtures."""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
from pathlib import Path
import subprocess


VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"
DERIVATION_VECTOR = VECTOR_DIR / "common-credential-root-v1-derivation.tsv"
COMMITMENT_VECTORS = {
    "sha256": VECTOR_DIR / "common-credential-root-v1-sha-commitments.tsv",
    "poseidon2": VECTOR_DIR / "common-credential-root-v1-poseidon2-commitments.tsv",
}
POSEIDON2_ORACLE = Path(
    os.environ.get(
        "POSEIDON2_FIXTURE_BIN",
        str(Path(__file__).resolve().parent.parent / "target/debug/poseidon2-bounded-fixture"),
    )
)
FIELDS = (
    "context_hash_hex", "lineage_tag_hex", "lineage_salt_hex",
    "lineage_inner_hex", "lineage_leaf_hex", "selected_name_hash_hex",
    "selected_value_hex", "selected_salt_hex", "selected_inner_hex",
    "selected_leaf_hex", "merkle_root_hex",
)
LINEAGE_NAME_HASH = hashlib.sha256(b"reallyme.lineage.v1").digest()


def read_rows(path: Path, columns: tuple[str, ...]) -> list[dict[str, str]]:
    with path.open(newline="") as source:
        reader = csv.DictReader(
            (line for line in source if not line.startswith("#")),
            delimiter="\t",
        )
        if reader.fieldnames != ["case", *columns]:
            raise ValueError("unexpected common-credential-root vector schema")
        rows = list(reader)
    if [row.get("case") for row in rows] != ["university", "employer"]:
        raise ValueError("missing or reordered common-credential-root vector cases")
    if any(None in row for row in rows):
        raise ValueError("extra common-credential-root vector column")
    return rows


def field(row: dict[str, str], name: str, length: int | None = 32) -> bytes:
    try:
        value = bytes.fromhex(row[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid synthetic vector field: {name}") from error
    if length is not None and len(value) != length:
        raise ValueError(f"wrong synthetic vector field length: {name}")
    return value


def credential_digest(transcript: bytes, lane: str) -> bytes:
    if lane == "sha256":
        return hashlib.sha256(transcript).digest()
    if len(transcript) > 515:
        raise ValueError("Poseidon2 transcript exceeds bounded input")
    result = subprocess.run(
        [str(POSEIDON2_ORACLE)],
        input=",".join(str(byte) for byte in transcript) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    values = result.stdout.strip().split(",")
    if len(values) != 32:
        raise ValueError("invalid Poseidon2 oracle output")
    try:
        return bytes(int(value) for value in values)
    except ValueError as error:
        raise ValueError("non-byte Poseidon2 oracle output") from error


def claim_inner(value: bytes, salt: bytes, lane: str) -> bytes:
    return credential_digest(
        b"CLM1" + len(value).to_bytes(4, "big") + value + salt,
        lane,
    )


CLAIM_TREE_DEPTH = 6


def fixed_depth_root(lineage_leaf: bytes, selected_leaf: bytes, lane: str) -> bytes:
    """Root of the two-leaf claim tree padded to the fixed depth with empties."""
    node = credential_digest(b"NODE1" + lineage_leaf + selected_leaf, lane)
    empty = bytes(32)
    for _ in range(1, CLAIM_TREE_DEPTH):
        empty = credential_digest(b"NODE1" + empty + empty, lane)
        node = credential_digest(b"NODE1" + node + empty, lane)
    return node


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("lane", choices=tuple(COMMITMENT_VECTORS))
    args = parser.parse_args()
    commitments = read_rows(COMMITMENT_VECTORS[args.lane], FIELDS)
    derivations = read_rows(
        DERIVATION_VECTOR,
        (
            "root_hex", "issuer_x_hex", "issuer_y_hex", "did_hash_hex",
            "subject_x_hex", "subject_y_hex", "nonce_hex", "context_hash_hex",
            "lineage_tag_hex",
        ),
    )
    for commitment, derivation in zip(commitments, derivations, strict=True):
        context_hash = field(commitment, "context_hash_hex")
        lineage_tag = field(commitment, "lineage_tag_hex")
        if (
            context_hash != field(derivation, "context_hash_hex")
            or lineage_tag != field(derivation, "lineage_tag_hex")
        ):
            raise ValueError("commitment vector does not match lineage derivation")
        lineage_salt = field(commitment, "lineage_salt_hex", 16)
        selected_salt = field(commitment, "selected_salt_hex", 16)
        selected_name = field(commitment, "selected_name_hash_hex")
        selected_value = field(commitment, "selected_value_hex", None)
        if (
            not any(lineage_salt)
            or not any(selected_salt)
            or selected_name == LINEAGE_NAME_HASH
            or not 1 <= len(selected_value) <= 64
        ):
            raise ValueError("invalid synthetic credential claim material")

        lineage_inner = claim_inner(
            context_hash + lineage_tag, lineage_salt, args.lane,
        )
        lineage_leaf = credential_digest(
            b"LEAF1" + LINEAGE_NAME_HASH + lineage_inner, args.lane,
        )
        selected_inner = claim_inner(selected_value, selected_salt, args.lane)
        selected_leaf = credential_digest(
            b"LEAF1" + selected_name + selected_inner, args.lane,
        )
        merkle_root = fixed_depth_root(lineage_leaf, selected_leaf, args.lane)
        for name, actual in (
            ("lineage_inner_hex", lineage_inner),
            ("lineage_leaf_hex", lineage_leaf),
            ("selected_inner_hex", selected_inner),
            ("selected_leaf_hex", selected_leaf),
            ("merkle_root_hex", merkle_root),
        ):
            if actual != field(commitment, name):
                raise ValueError(f"synthetic commitment mismatch: {name}")
    print(f"common-credential-root v1 {args.lane} commitment vectors passed")


if __name__ == "__main__":
    main()
