# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Require every status-circuit presence guard to reject its empty input."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parent.parent
NARGO = os.environ.get("NARGO", "nargo")
FIELD_BYTES = 32


@dataclass(frozen=True)
class Guard:
    fields: tuple[str, ...]
    failure: str


PERSONA_GUARDS = (
    Guard(("issuer_x", "issuer_y"), "empty issuer key"),
    Guard(("holder_x", "holder_y"), "empty holder key"),
    Guard(("subject_x", "subject_y"), "empty subject key"),
    Guard(("token_nonce",), "empty token nonce"),
    Guard(("envelope_hash",), "empty envelope hash"),
    Guard(("claims_root",), "empty claims root"),
)


def empty_fields(source: str, fields: tuple[str, ...]) -> str:
    # Replace whole public fixture fields rather than flipping a byte: a
    # nonzero mutation would exercise a signature/join check, not this guard.
    parsed = tomllib.loads(source)
    for field in fields:
        values = [
            table[field]
            for table in parsed.values()
            if isinstance(table, dict) and field in table
        ]
        if (
            len(values) != 1
            or not isinstance(values[0], list)
            or len(values[0]) != FIELD_BYTES
            or any(type(value) is not int or not 0 <= value <= 255 for value in values[0])
        ):
            raise ValueError("required status fixture field is missing or ambiguous")
        if not any(values[0]):
            raise ValueError("positive status fixture already has an empty field")
        source, count = re.subn(
            rf"(?m)^{re.escape(field)}\s*=\s*\[[^\]\n]*\]",
            f"{field} = [{', '.join('0' for _ in range(FIELD_BYTES))}]",
            source,
        )
        if count != 1:
            raise ValueError("required status fixture field cannot be replaced uniquely")
    return source


def execute(folder: Path, fixture: str, failure: str | None) -> None:
    completed = subprocess.run(
        [NARGO, "execute", "--prover-name", fixture],
        cwd=folder,
        capture_output=True,
        text=True,
        check=False,
    )
    if failure is None:
        if completed.returncode != 0:
            raise RuntimeError(f"{folder.parent.name}/{folder.name}: positive status witness failed")
    elif completed.returncode == 0 or failure not in completed.stdout + completed.stderr:
        raise RuntimeError(f"{folder.parent.name}/{folder.name}: {fixture} missed its presence guard")


def exercise(lane: str, family: str, fixture: str, guards: tuple[Guard, ...]) -> int:
    folder = ROOT / "circuits" / lane / "families" / family
    source = (folder / f"{fixture}.toml").read_text()
    execute(folder, fixture, None)
    for index, guard in enumerate(guards):
        name = f"RequiredStatusFieldNegative{index}"
        temporary = folder / f"{name}.toml"
        # Exclusive creation preserves concurrent user work and prevents a
        # negative test from accidentally reusing a pre-existing witness.
        output = temporary.open("x")
        try:
            with output:
                output.write(empty_fields(source, guard.fields))
            execute(folder, name, guard.failure)
        finally:
            temporary.unlink(missing_ok=True)
    return len(guards)


def main() -> None:
    count = 0
    for lane in ("sha256", "poseidon2"):
        count += exercise(
            lane,
            "common_credential_root_v1/issuer_credential_status",
            "Prover",
            (
                Guard(("issuer_x", "issuer_y"), "issuer key is zero"),
                Guard(("envelope_hash",), "envelope hash is zero"),
                Guard(("claims_root",), "claims root is zero"),
            ),
        )
        for stage in ("signed_validity", "current_state"):
            for mode in ("Public", "Private"):
                count += exercise(
                    lane,
                    f"persona_credential_evidence_v1/{stage}",
                    f"{mode}Joined",
                    PERSONA_GUARDS,
                )
    print(f"required status fields: {count} negative witnesses rejected in both hash lanes")


if __name__ == "__main__":
    main()
