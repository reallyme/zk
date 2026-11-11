# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Exercise v1 prepared current-state witnesses in both supported hash lanes."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
NARGO = os.environ.get("NARGO", "nargo")


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("fixture mutation field is not unique")
    return source.replace(old, new, 1)


def execute(folder: Path, fixture_name: str, failure: str | None) -> None:
    result = subprocess.run(
        [NARGO, "execute", "--prover-name", fixture_name],
        cwd=folder,
        text=True,
        capture_output=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if failure is None and result.returncode != 0:
        raise RuntimeError(f"prepared current-state valid witness failed: {output}")
    if failure is not None and (result.returncode == 0 or failure not in output):
        raise RuntimeError(f"prepared current-state negative was accepted: {output}")


def temporary_fixture(
    folder: Path,
    fixture_name: str,
    contents: str,
    failure: str | None,
) -> None:
    path = folder / f"{fixture_name}.toml"
    if path.exists():
        raise FileExistsError(path)
    try:
        path.write_text(contents)
        execute(folder, fixture_name, failure)
    finally:
        path.unlink(missing_ok=True)


def exercise_lane(lane: str) -> None:
    folder = ROOT / "circuits" / lane / "families" / "persona_credential_evidence_v1" / "current_state"
    source = (folder / "Prover.toml").read_text()
    parsed = tomllib.loads(source)
    slot = parsed["slot"]
    witness = parsed["witness"]
    execute(folder, "Prover", None)
    execute(folder, "OutsideIssuerWindow", "prepared after credential validity")

    mutations = (
        (
            "WrongTokenNonce",
            f"token_nonce = [{slot['token_nonce'][0]},",
            f"token_nonce = [{slot['token_nonce'][0] ^ 1},",
            "credential binding mismatch",
        ),
        (
            "WrongHolderKey",
            f"holder_x = [{slot['holder_x'][0]},",
            f"holder_x = [{slot['holder_x'][0] ^ 1},",
            "credential binding mismatch",
        ),
        (
            "WrongSubjectKey",
            f"subject_x = [{witness['subject_x'][0]},",
            f"subject_x = [{witness['subject_x'][0] ^ 1},",
            "credential binding mismatch",
        ),
        (
            "WrongStatusRoot",
            f"status_root = [{slot['status_root'][0]},",
            f"status_root = [{slot['status_root'][0] ^ 1},",
            "issuer status root mismatch",
        ),
        (
            "Revoked",
            f"status_chunk = [{witness['status_chunk'][0]},",
            f"status_chunk = [{witness['status_chunk'][0] | (1 << (witness['status_index'] % 8))},",
            "credential inactive",
        ),
        (
            "WrongIndex",
            f"status_index = {witness['status_index']}",
            f"status_index = {witness['status_index'] + 1}",
            "issuer validity or status signature invalid",
        ),
        (
            "WrongList",
            f"status_list_id = [{slot['status_list_id'][0]},",
            f"status_list_id = [{slot['status_list_id'][0] ^ 1},",
            "issuer validity or status signature invalid",
        ),
        (
            "WrongValidityStatusSignature",
            f"issuer_validity_status_signature = [{witness['issuer_validity_status_signature'][0]},",
            f"issuer_validity_status_signature = [{witness['issuer_validity_status_signature'][0] ^ 1},",
            "issuer validity or status signature invalid",
        ),
        (
            "WrongBinding",
            f"credential_binding = [{slot['credential_binding'][0]},",
            f"credential_binding = [{slot['credential_binding'][0] ^ 1},",
            "credential binding mismatch",
        ),
        (
            "InvalidWindow",
            f"prepared_from = {slot['prepared_from']}",
            f"prepared_from = {slot['prepared_until']}",
            "invalid prepared interval",
        ),
        (
            "BeforeIssuerValidity",
            f"prepared_from = {slot['prepared_from']}",
            f"prepared_from = {witness['valid_from'] - 1}",
            "prepared before credential validity",
        ),
    )
    for name, original, replacement, failure in mutations:
        temporary_fixture(
            folder,
            f"EvidenceCurrentState{name}",
            replace_once(source, original, replacement),
            failure,
        )

    # A three-chunk list selects the final chunk. This exercises both sibling
    # ordering and the padded Merkle leaf, which a one-chunk fixture cannot.
    with tempfile.TemporaryDirectory(prefix="reallyme-prepared-status-") as temporary:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate-issuer-credential-status-fixtures.py"),
                lane,
                "--prepared",
                "--output-root",
                temporary,
                "--status-length",
                "520",
                "--status-index",
                "513",
                "--token-index",
                "1",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        multi = (Path(temporary) / "Prover.toml").read_text()
    multi_parsed = tomllib.loads(multi)
    if multi_parsed["witness"]["path_len"] != 2:
        raise ValueError("prepared multi-chunk fixture has wrong path depth")
    temporary_fixture(folder, "EvidenceCurrentStateMultiChunk", multi, None)
    first_sibling = multi_parsed["witness"]["path"][0][0]
    temporary_fixture(
        folder,
        "EvidenceCurrentStateWrongSibling",
        replace_once(multi, f"path = [[{first_sibling},", f"path = [[{first_sibling ^ 1},"),
        "issuer status root mismatch",
    )


for selected_lane in ("sha256", "poseidon2"):
    exercise_lane(selected_lane)
print("prepared current-state v1: two lanes, two valid paths, and twelve negatives each passed")
