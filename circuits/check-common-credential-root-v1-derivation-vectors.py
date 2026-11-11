# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check fixed synthetic issuance vectors with an independent HKDF oracle."""

from __future__ import annotations

import csv
import hashlib
import hmac
from pathlib import Path


VECTOR_PATH = Path(__file__).resolve().parent.parent / "vectors/common-credential-root-v1-derivation.tsv"
EXTRACT_SALT = hashlib.sha256(b"ReallyMe/common-credential-root/v1/HKDF-Extract").digest()
FIELDS = (
    "root_hex", "issuer_x_hex", "issuer_y_hex", "did_hash_hex",
    "subject_x_hex", "subject_y_hex", "nonce_hex", "context_hash_hex",
    "lineage_tag_hex",
)


def decode_field(row: dict[str, str], field: str) -> bytes:
    try:
        value = bytes.fromhex(row[field])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid synthetic vector field: {field}") from error
    if len(value) != 32:
        raise ValueError(f"wrong synthetic vector field length: {field}")
    return value


def main() -> None:
    with VECTOR_PATH.open(newline="") as vector_file:
        rows = csv.DictReader(
            (line for line in vector_file if not line.startswith("#")),
            delimiter="\t",
        )
        if rows.fieldnames != ["case", *FIELDS]:
            raise ValueError("unexpected common-credential-root vector schema")
        cases = list(rows)
    if [row["case"] for row in cases] != ["university", "employer"]:
        raise ValueError("missing or reordered common-credential-root vector cases")
    contexts: set[bytes] = set()
    tags: set[bytes] = set()
    for row in cases:
        if None in row:
            raise ValueError("extra common-credential-root vector column")
        values = {field: decode_field(row, field) for field in FIELDS}
        context = hashlib.sha256(
            b"RMCTX1"
            + values["issuer_x_hex"] + values["issuer_y_hex"]
            + values["did_hash_hex"]
            + values["subject_x_hex"] + values["subject_y_hex"]
            + values["nonce_hex"]
        ).digest()
        prk = hmac.new(EXTRACT_SALT, values["root_hex"], hashlib.sha256).digest()
        tag = hmac.new(prk, context + b"\x01", hashlib.sha256).digest()
        if not hmac.compare_digest(context, values["context_hash_hex"]):
            raise ValueError("relationship context vector mismatch")
        if not hmac.compare_digest(tag, values["lineage_tag_hex"]):
            raise ValueError("lineage derivation vector mismatch")
        contexts.add(context)
        tags.add(tag)
    if len(contexts) != len(cases) or len(tags) != len(cases):
        raise ValueError("distinct relationships share a context or lineage tag")
    print("common-credential-root v1 derivation vectors passed")


if __name__ == "__main__":
    main()
