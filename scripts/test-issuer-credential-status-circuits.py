# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Execute the signed-validity/current-status proof in both hash lanes."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
NARGO = os.environ.get("NARGO", "nargo")


def replace_line(source: str, original: str, replacement: str) -> str:
    if source.count(original) != 1:
        raise ValueError("fixture field is not unique")
    return source.replace(original, replacement, 1)


def execute(folder: Path, prover_name: str, expected_failure: str | None) -> None:
    completed = subprocess.run(
        [NARGO, "execute", "--prover-name", prover_name],
        cwd=folder,
        text=True,
        capture_output=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if expected_failure is None:
        if completed.returncode != 0:
            raise RuntimeError(f"valid {folder.parent.parent.parent.name} fixture failed: {output}")
    elif completed.returncode == 0 or expected_failure not in output:
        raise RuntimeError(f"negative {prover_name} did not fail as required: {output}")


def exercise_multichunk_path(folder: Path, lane: str) -> None:
    # The standard fixture has one chunk and cannot exercise Merkle sibling
    # ordering. Select an index in the third chunk of a three-chunk list so
    # both a right-child branch and the padded final leaf are checked.
    with tempfile.TemporaryDirectory(prefix="reallyme-issuer-status-") as temporary_root:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate-issuer-credential-status-fixtures.py"),
                lane,
                "--output-root",
                temporary_root,
                "--status-length",
                "520",
                "--status-index",
                "513",
            ],
            check=True,
            text=True,
        )
        fixture = (Path(temporary_root) / "Prover.toml").read_text()
    parsed = tomllib.loads(fixture)
    if parsed["witness"]["path_len"] != 2:
        raise ValueError("multi-chunk fixture has the wrong path depth")
    sibling_first = parsed["witness"]["path"][0][0]
    variants = (
        ("IssuerStatusMultiChunk", fixture, None),
        (
            "IssuerStatusWrongSibling",
            replace_line(
                fixture,
                f"path = [[{sibling_first},",
                f"path = [[{sibling_first ^ 1},",
            ),
            "issuer status root mismatch",
        ),
    )
    for name, contents, expected_failure in variants:
        temporary = folder / f"{name}.toml"
        if temporary.exists():
            raise FileExistsError(temporary)
        try:
            temporary.write_text(contents)
            execute(folder, name, expected_failure)
        finally:
            temporary.unlink(missing_ok=True)


def exercise_lane(lane: str) -> None:
    folder = ROOT / "circuits" / lane / "families" / "common_credential_root_v1" / "issuer_credential_status"
    fixture = (folder / "Prover.toml").read_text()
    parsed = tomllib.loads(fixture)
    slot = parsed["slot"]
    witness = parsed["witness"]
    root_first = slot["status_root"][0]
    binding_first = slot["credential_binding"][0]
    list_id_first = slot["status_list_id"][0]
    status_index = witness["status_index"]
    status_chunk_first = witness["status_chunk"][0]
    execute(folder, "Prover", None)

    mutations = (
        (
            "InvalidSession",
            f"verifier_now = {slot['verifier_now']}",
            f"verifier_now = {slot['presentation_expiry'] + 1}",
            "invalid session interval",
        ),
        (
            "Revoked",
            f"status_chunk = [{status_chunk_first},",
            f"status_chunk = [{status_chunk_first | (1 << (status_index % 8))},",
            "credential inactive",
        ),
        (
            "WrongIndex",
            f"status_index = {status_index}",
            f"status_index = {status_index + 1}",
            "issuer validity or status signature invalid",
        ),
        (
            "WrongList",
            f"status_list_id = [{list_id_first},",
            f"status_list_id = [{list_id_first ^ 1},",
            "issuer validity or status signature invalid",
        ),
        ("WrongRoot", f"status_root = [{root_first},", f"status_root = [{root_first ^ 1},", "issuer status root mismatch"),
        ("WrongCredential", f"credential_binding = [{binding_first},", f"credential_binding = [{binding_first ^ 1},", "credential binding mismatch"),
    )
    for name, original, replacement, expected in mutations:
        prover_name = f"IssuerStatusNegative{name}"
        temporary = folder / f"{prover_name}.toml"
        if temporary.exists():
            raise FileExistsError(temporary)
        try:
            temporary.write_text(replace_line(fixture, original, replacement))
            execute(folder, prover_name, expected)
        finally:
            temporary.unlink(missing_ok=True)
    execute(folder, "ExpiresInSession", "credential expires in session")
    exercise_multichunk_path(folder, lane)


for selected_lane in ("sha256", "poseidon2"):
    exercise_lane(selected_lane)
print("issuer credential-status circuits: single- and multi-chunk positives and eight negatives passed in both lanes")
