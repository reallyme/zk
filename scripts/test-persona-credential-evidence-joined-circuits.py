# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Exercise joined prepared claim/status witnesses and tampered inputs."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parent.parent
NARGO = os.environ.get("NARGO", "nargo")


def run(folder: Path, name: str, expected_failure: str | None) -> None:
    result = subprocess.run(
        [NARGO, "execute", "--prover-name", name],
        cwd=folder,
        text=True,
        capture_output=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if expected_failure is None and result.returncode != 0:
        raise RuntimeError(f"valid prepared witness failed in {folder}: {output}")
    if expected_failure is not None and (
        result.returncode == 0 or expected_failure not in output
    ):
        raise RuntimeError(f"invalid prepared witness was accepted in {folder}: {output}")


def mutate(folder: Path, source: str, field: str, expected_failure: str) -> None:
    parsed = tomllib.loads(source)
    value = parsed.get(field)
    if value is None:
        raise ValueError(f"missing fixture field: {field}")
    if isinstance(value, list):
        old = f"{field} = [{value[0]},"
        new = f"{field} = [{value[0] ^ 1},"
    else:
        raise ValueError(f"expected byte-array fixture field: {field}")
    if source.count(old) != 1:
        raise ValueError(f"fixture field is not unique: {field}")
    name = f"Negative{field.replace('_', '').title()}"
    path = folder / f"{name}.toml"
    if path.exists():
        raise FileExistsError(path)
    try:
        path.write_text(source.replace(old, new, 1))
        run(folder, name, expected_failure)
    finally:
        path.unlink(missing_ok=True)


def check_join(claim: dict, status: dict, envelope: dict, root: dict, validity: dict) -> None:
    slot = status["slot"]
    witness = status["witness"]
    for key in (
        "holder_x",
        "holder_y",
        "token_nonce",
        "prepared_from",
        "prepared_until",
        "credential_binding",
    ):
        if claim[key] != slot[key]:
            raise ValueError(f"prepared proof join differs: {key}")
    for claim_key, status_key in (
        ("pk_issuer_x", "issuer_x"),
        ("pk_issuer_y", "issuer_y"),
    ):
        if claim[claim_key] != slot[status_key]:
            raise ValueError(f"prepared issuer join differs: {claim_key}")
    if claim["envelope_hash"] != witness["envelope_hash"]:
        raise ValueError("hidden credential envelope differs")
    if claim["merkle_root"] != witness["claims_root"]:
        raise ValueError("hidden credential claim root differs")
    if claim["pk_subject_x"] != witness["subject_x"] or claim["pk_subject_y"] != witness["subject_y"]:
        raise ValueError("hidden credential subject differs")
    for stage in (envelope, root):
        for key in (
            "pk_issuer_x",
            "pk_issuer_y",
            "holder_x",
            "holder_y",
            "token_nonce",
            "prepared_from",
            "prepared_until",
            "credential_binding",
            "envelope_hash",
        ):
            if stage[key] != claim[key]:
                raise ValueError(f"prepared evidence stage join differs: {key}")
        if stage["claims_root"] != claim["merkle_root"]:
            raise ValueError("prepared evidence stage claim root differs")
        if stage["pk_subject_x"] != claim["pk_subject_x"] or stage["pk_subject_y"] != claim["pk_subject_y"]:
            raise ValueError("prepared evidence stage subject differs")
    if envelope["pk_subject_x"] != claim["pk_subject_x"]:
        raise ValueError("issuer-envelope subject differs")
    if envelope["pk_subject_y"] != claim["pk_subject_y"]:
        raise ValueError("issuer-envelope subject differs")
    validity_slot = validity["slot"]
    validity_witness = validity["witness"]
    for key in ("holder_x", "holder_y", "token_nonce", "prepared_from", "prepared_until", "credential_binding"):
        if validity_slot[key] != claim[key]:
            raise ValueError(f"prepared validity join differs: {key}")
    if validity_witness["envelope_hash"] != claim["envelope_hash"]:
        raise ValueError("prepared validity envelope differs")
    if validity_witness["claims_root"] != claim["merkle_root"]:
        raise ValueError("prepared validity claim root differs")
    if validity_witness["subject_x"] != claim["pk_subject_x"] or validity_witness["subject_y"] != claim["pk_subject_y"]:
        raise ValueError("prepared validity subject differs")
    for key in ("status_list_id", "status_url_hash", "status_purpose"):
        if validity_slot[key] != slot[key]:
            raise ValueError(f"prepared validity status pointer differs: {key}")


for lane in ("sha256", "poseidon2"):
    family = ROOT / "circuits" / lane / "families" / "persona_credential_evidence_v1"
    for mode in ("public", "private"):
        claim_folder = family / f"{mode}_claim"
        status_folder = family / "current_state"
        source = (claim_folder / "Prover.toml").read_text()
        joined_name = f"{mode.capitalize()}Joined"
        claim = tomllib.loads(source)
        status = tomllib.loads((status_folder / f"{joined_name}.toml").read_text())
        envelope_folder = family / "issuer_envelope"
        root_folder = family / "claim_root"
        validity_folder = family / "signed_validity"
        envelope = tomllib.loads((envelope_folder / f"{joined_name}.toml").read_text())
        root = tomllib.loads((root_folder / f"{joined_name}.toml").read_text())
        validity = tomllib.loads((validity_folder / f"{joined_name}.toml").read_text())
        check_join(claim, status, envelope, root, validity)
        for stage_folder in (envelope_folder, root_folder):
            run(stage_folder, joined_name, None)
            run(stage_folder, f"{joined_name}WrongSignature", "signature invalid")
            run(stage_folder, f"{joined_name}WrongJoin", "token binding mismatch")
        run(
            envelope_folder,
            f"{joined_name}WrongEnvelopeSignature",
            "issuer envelope signature invalid",
        )
        run(validity_folder, joined_name, None)
        for negative_name, failure in (
            ("WrongSignature", "issuer validity signature invalid"),
            ("OutsideIssuerWindow", "prepared after credential validity"),
            ("WrongStatusIndex", "issuer validity signature invalid"),
            ("WrongStatusList", "issuer validity signature invalid"),
            ("WrongSubject", "credential binding mismatch"),
            ("WrongJoin", "credential binding mismatch"),
        ):
            run(validity_folder, f"{joined_name}{negative_name}", failure)
        run(claim_folder, "Prover", None)
        run(claim_folder, "ProverShortPath", "claim tree path must have fixed depth")
        run(status_folder, joined_name, None)
        mutate(claim_folder, source, "credential_binding", "credential binding mismatch")
        mutate(claim_folder, source, "issuer_subject_bind_sig", "issuer envelope-subject binding signature invalid")
        mutate(claim_folder, source, "val_pub", "merkle root mismatch")
        if mode == "private":
            mutate(claim_folder, source, "persona_token_auth_sig", "hidden persona did not authorize one-time key")
            mutate(claim_folder, source, "subject_link_sig", "subject-private-persona link signature invalid")
        else:
            mutate(claim_folder, source, "subject_link_sig", "subject link signature invalid")
        if status["slot"]["credential_binding"] == tomllib.loads(
            (status_folder / f"{('private' if mode == 'public' else 'public').capitalize()}Joined.toml").read_text()
        )["slot"]["credential_binding"]:
            raise ValueError("public and private tokens share a credential binding")

print("persona credential evidence issuer, root, signed-validity, claim, and status witnesses and negatives passed in both hash lanes")
