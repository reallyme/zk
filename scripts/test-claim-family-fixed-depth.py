#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check the request-bound claim-family fixtures and their fixed-depth rule.

The checked-in fixtures must match their generator. Every single-claim and
four-claim circuit must solve the full-depth fixture and must reject a
correctly bound tree one level short of the fixed depth at the depth
assertion, not at an unrelated constraint.
"""

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
NARGO = os.environ.get("NARGO", "nargo")
FIXED_DEPTH_FAILURE = "claim tree path must have fixed depth"
LANES = ("sha256", "poseidon2")
FAMILIES = ("credential_subject_claim_v1", "private_persona_claim_v1")
CLAIM_STAGES = ("claim", "claim_bundle_4")


def execute(folder: Path, prover_name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [NARGO, "execute", "--prover-name", prover_name],
        cwd=folder,
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    generator = ROOT / "scripts" / "generate-claim-family-fixtures.py"
    checked = subprocess.run([sys.executable, str(generator), "check"], check=False)
    if checked.returncode != 0:
        print("claim-family fixtures do not match their generator", file=sys.stderr)
        return 1
    for lane in LANES:
        for family in FAMILIES:
            for stage in CLAIM_STAGES:
                folder = ROOT / "circuits" / lane / "families" / family / stage
                valid = execute(folder, "Prover")
                if valid.returncode != 0:
                    print(f"full-depth witness failed: {lane}/{family}/{stage}", file=sys.stderr)
                    return 1
                short = execute(folder, "ProverShortPath")
                output = short.stdout + short.stderr
                if short.returncode == 0 or FIXED_DEPTH_FAILURE not in output:
                    print(
                        f"short claim path was not rejected at the depth gate: "
                        f"{lane}/{family}/{stage}",
                        file=sys.stderr,
                    )
                    return 1
    print(
        "claim-family fixed depth: eight circuits solve the full-depth witness "
        "and reject the short path in both hash lanes"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
