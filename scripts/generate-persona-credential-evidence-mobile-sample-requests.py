# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Regenerate synthetic persona-credential-evidence mobile proving requests.

These requests contain only fixed, published test keys. They are example-app
fixtures, never holder credentials or a source of production one-time tokens.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "crates/proto/proto/reallyme/zk/v1/manifest.proto"
OUTPUT = ROOT / "vectors/persona-credential-evidence-mobile-requests-v1"
NARGO = os.environ.get("NARGO", "nargo")
PROTOC = os.environ.get("PROTOC", "protoc")
SUITE = "ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA"
FAMILY = "ZK_CIRCUIT_FAMILY_PERSONA_CREDENTIAL_EVIDENCE_V1"
ENCODING = "ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1"


def escaped_bytes(value: bytes) -> str:
    return '"' + "".join(f"\\{byte:03o}" for byte in value) + '"'


def reference(stage: str, lane: str) -> str:
    strategy = "ZK_CREDENTIAL_HASH_ALGORITHM_SHA256" if lane == "sha256" else "ZK_CREDENTIAL_HASH_ALGORITHM_POSEIDON2"
    return f"family: {FAMILY} stage: {stage} credential_hash_algorithm: {strategy} circuit_revision: 1"


def execute(folder: Path, prover_name: str, witness_name: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="reallyme-prepared-mobile-nargo-") as home:
        env = os.environ.copy()
        env["HOME"] = home
        env["XDG_CACHE_HOME"] = str(Path(home) / "cache")
        subprocess.run(
            [NARGO, "execute", "--prover-name", prover_name],
            cwd=folder,
            env=env,
            check=True,
        )
    witness = (folder / "target" / f"{witness_name}.gz").read_bytes()
    if not witness:
        raise ValueError("Noir returned an empty witness")
    return witness


def encode_request(mode: str, stage: str, lane: str, witness: bytes) -> bytes:
    ref = reference(stage, lane)
    source = (
        "prove_persona_credential_evidence_stage {\n"
        f"  mode: {mode}\n"
        f"  circuit_ref {{ {ref} }}\n"
        f"  proof_suite: {SUITE}\n"
        "  witness {\n"
        f"    encoded: {escaped_bytes(witness)}\n"
        f"    circuit_ref {{ {ref} }}\n"
        f"    encoding: {ENCODING}\n"
        "  }\n"
        "}\n"
    ).encode("ascii")
    result = subprocess.run(
        [
            PROTOC,
            f"--proto_path={ROOT / 'crates/proto/proto'}",
            "--encode=reallyme.zk.v1.ZkProviderOperationRequest",
            str(PROTO),
        ],
        input=source,
        capture_output=True,
        check=True,
    )
    return result.stdout


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    manifest = ["filename\tsha256"]
    for lane in ("sha256", "poseidon2"):
        family = ROOT / "circuits" / lane / "families/persona_credential_evidence_v1"
        for persona in ("public", "private"):
            mode = (
                "ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1"
                if persona == "public"
                else "ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1"
            )
            claim_stage = (
                "ZK_CIRCUIT_STAGE_EVIDENCE_PUBLIC_CLAIM"
                if persona == "public"
                else "ZK_CIRCUIT_STAGE_EVIDENCE_PRIVATE_CLAIM"
            )
            for part, folder, prover, stage, circuit in (
                (
                    "issuer",
                    family / "issuer_envelope",
                    f"{persona.capitalize()}Joined",
                    "ZK_CIRCUIT_STAGE_EVIDENCE_ISSUER_ENVELOPE",
                    f"credential_persona_credential_evidence_v1_issuer_envelope_{lane}",
                ),
                (
                    "root",
                    family / "claim_root",
                    f"{persona.capitalize()}Joined",
                    "ZK_CIRCUIT_STAGE_EVIDENCE_CLAIM_ROOT",
                    f"credential_persona_credential_evidence_v1_claim_root_{lane}",
                ),
                (
                    "validity",
                    family / "signed_validity",
                    f"{persona.capitalize()}Joined",
                    "ZK_CIRCUIT_STAGE_EVIDENCE_SIGNED_VALIDITY",
                    f"credential_persona_credential_evidence_v1_signed_validity_{lane}",
                ),
                (
                    "claim",
                    family / f"{persona}_claim",
                    "Prover",
                    claim_stage,
                    f"credential_persona_credential_evidence_v1_{persona}_claim_{lane}",
                ),
                (
                    "status",
                    family / "current_state",
                    f"{persona.capitalize()}Joined",
                    "ZK_CIRCUIT_STAGE_EVIDENCE_CURRENT_STATE",
                    f"credential_persona_credential_evidence_v1_current_state_{lane}",
                ),
            ):
                witness = execute(folder, prover, circuit)
                encoded = encode_request(mode, stage, lane, witness)
                name = f"{lane}-{persona}-{part}.pb"
                (OUTPUT / name).write_bytes(encoded)
                manifest.append(f"{name}\t{sha256(encoded).hexdigest()}")
    (OUTPUT / "sha256.tsv").write_text("\n".join(manifest) + "\n")


if __name__ == "__main__":
    main()
