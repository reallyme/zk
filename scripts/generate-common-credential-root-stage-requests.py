#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Encode synthetic Noir stage fixtures as typed provider protobuf requests.

The outputs are pinned public test vectors. They contain deterministic test
secrets from the circuit fixture tree and must never be used for real issuance.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTO_ROOT = ROOT / "crates/proto/proto"
PROTO_FILE = "reallyme/zk/v1/manifest.proto"
OUTPUT_ROOT = ROOT / "vectors/common-credential-root-stage-requests-v1"
MANIFEST = ROOT / "vectors/common-credential-root-stage-requests-v1.sha256.tsv"
FIXTURE_ROOT = ROOT / "circuits"
SUITE = "ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA"
ABSENT_TRANSACTION_DATA_HASH = [
    0x5B, 0x4E, 0xF1, 0x58, 0x07, 0xE8, 0x7E, 0xB1,
    0xB1, 0x83, 0x6D, 0x70, 0x02, 0x04, 0x58, 0x3B,
    0x78, 0x95, 0xB9, 0x13, 0xC4, 0x56, 0x79, 0xC4,
    0xAA, 0xC5, 0x66, 0x0E, 0x51, 0x6E, 0x8F, 0xC4,
]


def block(name: str, *fields: str) -> str:
    return f"{name} {{\n" + "\n".join(fields) + "\n}"


def byte_field(name: str, values: list[int], length: int) -> str:
    if len(values) != length or any(not isinstance(v, int) or not 0 <= v <= 255 for v in values):
        raise ValueError("invalid synthetic fixture byte field")
    encoded = "".join(f"\\x{value:02x}" for value in values)
    return block(name, f'value: "{encoded}"')


def expected_binding(data: dict) -> str:
    fields = [
        f'nonce_hash: "{"".join(f"\\x{byte:02x}" for byte in data["challenge"])}"',
        f'audience_hash: "{"".join(f"\\x{byte:02x}" for byte in data["audience_hash"])}"',
    ]
    if data["transaction_data_hash"] != ABSENT_TRANSACTION_DATA_HASH:
        fields.append(
            f'transaction_data_hash: "{"".join(f"\\x{byte:02x}" for byte in data["transaction_data_hash"])}"'
        )
    return block("expected_binding", *fields)


def key(name: str, x: list[int], y: list[int]) -> str:
    return block(name, byte_field("x", x, 32), byte_field("y", y, 32))


def presentation(data: dict) -> str:
    if "presentation_expiry_unix" in data:
        expiry_unix = data["presentation_expiry_unix"]
    elif "presentation_expiry" in data:
        expiry_unix = data["presentation_expiry"]
    elif "slot" in data and "presentation_expiry" in data["slot"]:
        expiry_unix = data["slot"]["presentation_expiry"]
    elif "slot" in data and "expiry_unix" in data["slot"]:
        expiry_unix = data["slot"]["expiry_unix"]
    else:
        expiry_unix = data["expiry_unix"]
    return block(
        "presentation",
        byte_field("challenge", data["challenge"], 32),
        byte_field("audience_hash", data["audience_hash"], 32),
        byte_field("transaction_data_hash", data["transaction_data_hash"], 32),
        f"expiry_unix: {expiry_unix}",
    )


def issuer_context(data: dict) -> str:
    return block(
        "issuer_context",
        key("issuer_public_key", data["pk_issuer_x"], data["pk_issuer_y"]),
        byte_field("challenge", data["challenge"], 32),
        byte_field("audience_hash", data["audience_hash"], 32),
        f'expiry_unix: {data["expiry_unix"]}',
        byte_field("transaction_data_hash", data["transaction_data_hash"], 32),
    )


def path(name: str, length: int, siblings: list[list[int]], limit: int) -> str:
    if len(siblings) != limit or not 0 <= length <= limit:
        raise ValueError("invalid synthetic fixture Merkle path")
    return block(
        name,
        f"path_length: {length}",
        *(byte_field("siblings", sibling, 32) for sibling in siblings[:length]),
    )


def root_attestation(data: dict) -> str:
    return block(
        "root_attestation",
        presentation(data),
        key("reallyme_public_key", data["reallyme_x"], data["reallyme_y"]),
        byte_field("assurance_policy_id", data["assurance_policy_id"], 32),
        f'request_unix: {data["request_unix"]}',
        byte_field("root_join", data["root_join"], 32),
        byte_field("attestation_join", data["attestation_join"], 32),
        byte_field("root", data["root"], 32),
        f'attestation_issued_unix: {data["attestation_issued_unix"]}',
        f'attestation_expires_unix: {data["attestation_expires_unix"]}',
        f'attestation_epoch: {data["attestation_epoch"]}',
        byte_field("attestation_signature", data["attestation_signature"], 64),
        byte_field("join_salt", data["join_salt"], 32),
    )


def root_status(data: dict) -> str:
    return block(
        "root_status",
        presentation(data),
        byte_field("active_status_root", data["active_status_root"], 32),
        byte_field("root_join", data["root_join"], 32),
        byte_field("attestation_join", data["attestation_join"], 32),
        byte_field("root", data["root"], 32),
        byte_field("attestation_id", data["attestation_id"], 32),
        byte_field("join_salt", data["join_salt"], 32),
        f'status_index: {data["status_index"]}',
        path("status_path", data["status_path_len"], data["status_path"], 20),
    )


def lineage(data: dict) -> str:
    slot = data["slot"]
    witness = data["witness"]
    return block(
        "lineage",
        presentation(data),
        byte_field("root_join", data["root_join"], 32),
        block(
            "slot",
            key("issuer_public_key", slot["issuer_x"], slot["issuer_y"]),
            f'expiry_unix: {slot["expiry_unix"]}',
            byte_field("credential_binding", slot["credential_binding"], 32),
            byte_field("subject_join", slot["subject_join"], 32),
        ),
        byte_field("root", data["root"], 32),
        byte_field("join_salt", data["join_salt"], 32),
        block(
            "witness",
            byte_field("envelope_hash", witness["envelope_hash"], 32),
            byte_field("merkle_root", witness["merkle_root"], 32),
            byte_field("issuer_root_binding_signature", witness["issuer_root_bind_sig"], 64),
            key("subject_public_key", witness["subject_x"], witness["subject_y"]),
            byte_field("relationship_did_hash", witness["relationship_did_hash"], 32),
            byte_field("relationship_nonce", witness["relationship_nonce"], 32),
            byte_field("claim_salt", witness["claim_salt"], 16),
            f'merkle_leaf_index: {witness["leaf_index"]}',
            path("merkle_path", witness["path_len"], witness["path"], 6),
        ),
    )


def selected_claim(data: dict, mode: str) -> str:
    fields = [issuer_context(data)]
    if mode == "public":
        fields.append(key("persona_public_key", data["pk_persona_x"], data["pk_persona_y"]))
    fields.extend(
        [
            byte_field("session_binding", data["session_binding"], 32),
            byte_field("subject_join", data["subject_join"], 32),
            block(
                "disclosure",
                byte_field("credential_binding", data["credential_binding"], 32),
                f'value_length: {data["val_len"]}',
                byte_field("value", data["val_pub"], 64),
                byte_field("claim_name_hash", data["name_hash"], 32),
            ),
            block(
                "proof",
                byte_field("envelope_hash", data["envelope_hash"], 32),
                byte_field("merkle_root", data["merkle_root"], 32),
                byte_field("claim_salt", data["salt"], 16),
                f'leaf_index: {data["index"]}',
                path("path", data["path_len"], data["path"], 6),
            ),
        ]
    )
    link_fields = [
        byte_field("issuer_subject_binding_signature", data["issuer_subject_bind_sig"], 64),
        key("subject_public_key", data["pk_subject_x"], data["pk_subject_y"]),
    ]
    if mode == "private":
        link_fields.append(key("persona_public_key", data["pk_persona_x"], data["pk_persona_y"]))
    link_fields.append(byte_field("subject_link_signature", data["subject_link_sig"], 64))
    fields.append(block("link", *link_fields))
    fields.append(byte_field("join_salt", data["join_salt"], 32))
    return block(f"{mode}_persona_claim", *fields)


def session(data: dict, mode: str) -> str:
    fields = []
    if mode == "public":
        fields.append(key("persona_public_key", data["pk_persona_x"], data["pk_persona_y"]))
    fields.append(
        block(
            "session_context",
            byte_field("challenge", data["challenge"], 32),
            byte_field("audience_hash", data["audience_hash"], 32),
            f'expiry_unix: {data["expiry_unix"]}',
            byte_field("session_binding", data["session_binding"], 32),
            byte_field("transaction_data_hash", data["transaction_data_hash"], 32),
        )
    )
    if mode == "private":
        fields.append(
            block(
                "authorization",
                key("persona_public_key", data["pk_persona_x"], data["pk_persona_y"]),
                byte_field("persona_signature", data["persona_sig"], 64),
            )
        )
    else:
        fields.append(block("authorization", byte_field("persona_fresh_signature", data["persona_fresh_sig"], 64)))
    return block(f"{mode}_persona_session", *fields)


def issuer_credential_status(data: dict) -> str:
    slot = data["slot"]
    witness = data["witness"]
    if len(witness["path"]) != 12:
        raise ValueError("issuer status path must have exactly twelve slots")
    return block(
        "issuer_credential_status",
        presentation(data),
        key("issuer_public_key", slot["issuer_x"], slot["issuer_y"]),
        f'presentation_expiry: {slot["presentation_expiry"]}',
        byte_field("credential_binding", slot["credential_binding"], 32),
        byte_field("status_root", slot["status_root"], 32),
        f'status_length: {slot["status_length"]}',
        byte_field("status_list_id", slot["status_list_id"], 32),
        byte_field("status_url_hash", slot["status_url_hash"], 32),
        f'status_purpose: {slot["status_purpose"]}',
        f'verifier_now: {slot["verifier_now"]}',
        byte_field("envelope_hash", witness["envelope_hash"], 32),
        byte_field("claims_root", witness["claims_root"], 32),
        byte_field("issuer_validity_status_signature", witness["issuer_validity_status_signature"], 64),
        f'valid_from: {witness["valid_from"]}',
        f'valid_until: {witness["valid_until"]}',
        f'status_index: {witness["status_index"]}',
        byte_field("status_chunk", witness["status_chunk"], 32),
        f'path_length: {witness["path_len"]}',
        *(byte_field("path", sibling, 32) for sibling in witness["path"][:witness["path_len"]]),
    )


def load(
    fixture_root: pathlib.Path,
    lane: str,
    relative: str,
    filename: str = "Prover.toml",
) -> dict:
    fixture = fixture_root / lane / "families/common_credential_root_v1" / relative / filename
    with fixture.open("rb") as source:
        return tomllib.load(source)


def request_text(fixture_root: pathlib.Path, lane: str, mode: str, slot: int) -> str:
    slot_enum = [
        "ROOT_ATTESTATION", "ROOT_STATUS", "LINEAGE_0", "LINEAGE_1",
        "SELECTED_CLAIM_0", "SELECTED_CLAIM_1", "SESSION",
        "ISSUER_CREDENTIAL_STATUS_0", "ISSUER_CREDENTIAL_STATUS_1",
    ][slot]
    stage = [
        "ROOT_ATTESTATION", "ROOT_STATUS", "LINEAGE", "LINEAGE",
        f"{mode.upper()}_PERSONA_CLAIM", f"{mode.upper()}_PERSONA_CLAIM",
        "PUBLIC_SESSION" if mode == "public" else "SESSION",
        "ISSUER_CREDENTIAL_STATUS", "ISSUER_CREDENTIAL_STATUS",
    ][slot]
    family = "PRIVATE_PERSONA_CLAIM_V1" if slot == 6 and mode == "private" else "COMMON_CREDENTIAL_ROOT_V1"
    if slot == 0:
        data = load(fixture_root, lane, "root_attestation")
        input_text = root_attestation(data)
    elif slot == 1:
        data = load(fixture_root, lane, "root_status")
        attestation = load(fixture_root, lane, "root_attestation")
        data["presentation_expiry_unix"] = attestation["presentation_expiry_unix"]
        input_text = root_status(data)
    elif slot in (2, 3):
        data = load(
            fixture_root,
            lane,
            "lineage",
            "ProverEmployer.toml" if slot == 3 else "Prover.toml",
        )
        data["presentation_expiry_unix"] = data["slot"]["expiry_unix"]
        input_text = lineage(data)
    elif slot in (4, 5):
        data = load(
            fixture_root,
            lane,
            f"{mode}_persona_claim",
            "ProverEmployer.toml" if slot == 5 else "Prover.toml",
        )
        input_text = selected_claim(data, mode)
    elif slot == 6:
        data = load(fixture_root, lane, f"session_fixtures/{mode}")
        input_text = session(data, mode)
    else:
        data = load(
            fixture_root, lane, "issuer_credential_status",
            "ProverEmployer.toml" if slot == 8 else "Prover.toml",
        )
        input_text = issuer_credential_status(data)
    return block(
        "prove_common_credential_root_stage",
        f"persona_mode: ZK_COMMON_CREDENTIAL_ROOT_PERSONA_MODE_{mode.upper()}_PERSONA_V1",
        f"slot: ZK_COMMON_CREDENTIAL_ROOT_PROOF_SLOT_{slot_enum}",
        block(
            "circuit_ref",
            f'credential_hash_algorithm: ZK_CREDENTIAL_HASH_ALGORITHM_{"SHA256" if lane == "sha256" else "POSEIDON2"}',
            f"family: ZK_CIRCUIT_FAMILY_{family}",
            f"stage: ZK_CIRCUIT_STAGE_{stage}",
            "circuit_revision: 1",
        ),
        f"proof_suite: {SUITE}",
        expected_binding(data),
        input_text,
    )


def write_requests(
    output_root: pathlib.Path,
    manifest_path: pathlib.Path | None,
    fixture_root: pathlib.Path = FIXTURE_ROOT,
    lanes: tuple[str, ...] = ("sha256", "poseidon2"),
    modes: tuple[str, ...] = ("private", "public"),
) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str]] = []
    for lane in lanes:
        for mode in modes:
            for slot in range(9):
                text = request_text(fixture_root, lane, mode, slot)
                result = subprocess.run(
                    [
                        "protoc",
                        f"--proto_path={PROTO_ROOT}",
                        "--encode=reallyme.zk.v1.ZkProviderOperationRequest",
                        PROTO_FILE,
                    ],
                    input=text.encode("ascii"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if result.returncode != 0:
                    raise ValueError("synthetic provider request protobuf encoding failed")
                filename = f"{lane}-{mode}-{slot}.pb"
                # The schema numbers ordinary fields before oneof inputs, so
                # protoc and Buffa now produce the same canonical field order.
                encoded = result.stdout
                (output_root / filename).write_bytes(encoded)
                rows.append((filename, sha256(encoded).hexdigest()))
    if manifest_path is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            "filename\tsha256\n"
            + "".join(f"{filename}\t{digest}\n" for filename, digest in sorted(rows)),
            encoding="ascii",
        )


def check_requests() -> None:
    if not OUTPUT_ROOT.is_dir() or not MANIFEST.is_file():
        raise ValueError("common-credential-root stage request vectors are missing")
    with tempfile.TemporaryDirectory(prefix="reallyme-zk-common-credential-root-stage-requests.") as temporary:
        temporary_root = pathlib.Path(temporary)
        generated_root = temporary_root / "requests"
        generated_manifest = temporary_root / "sha256.tsv"
        write_requests(generated_root, generated_manifest)
        if MANIFEST.read_bytes() != generated_manifest.read_bytes():
            raise ValueError("common-credential-root stage request manifest is stale")
        for generated_file in sorted(generated_root.iterdir()):
            if not generated_file.is_file():
                raise ValueError("common-credential-root stage request output is malformed")
            checked_in_file = OUTPUT_ROOT / generated_file.name
            if checked_in_file.read_bytes() != generated_file.read_bytes():
                raise ValueError("common-credential-root stage request vector is stale")
        checked_in_names = sorted(path.name for path in OUTPUT_ROOT.iterdir() if path.is_file())
        generated_names = sorted(path.name for path in generated_root.iterdir() if path.is_file())
        if checked_in_names != generated_names:
            raise ValueError("common-credential-root stage request vector set is stale")


def main() -> int:
    if len(sys.argv) == 1:
        write_requests(OUTPUT_ROOT, MANIFEST)
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "check":
        check_requests()
        return 0
    if len(sys.argv) in (3, 5, 7) and sys.argv[1] == "generate":
        output_root = pathlib.Path(sys.argv[2]).resolve()
        manifest_path = output_root.parent / f"{output_root.name}.sha256.tsv"
        if output_root == OUTPUT_ROOT:
            manifest_path = MANIFEST
        fixture_root = FIXTURE_ROOT
        if len(sys.argv) >= 5:
            if sys.argv[3] != "--fixture-root":
                raise ValueError("usage: generate-common-credential-root-stage-requests.py generate OUTPUT_ROOT [--fixture-root FIXTURE_ROOT]")
            fixture_root = pathlib.Path(sys.argv[4]).resolve()
        lanes = ("sha256", "poseidon2")
        modes = ("private", "public")
        if len(sys.argv) == 7:
            if sys.argv[5] != "--fixture-variant" or sys.argv[6] not in (
                "sha256-private", "sha256-public", "poseidon2-private", "poseidon2-public"
            ):
                raise ValueError("invalid common-credential-root request fixture variant")
            lane, mode = sys.argv[6].split("-", 1)
            lanes = (lane,)
            modes = (mode,)
        if output_root.exists():
            shutil.rmtree(output_root)
        write_requests(output_root, manifest_path, fixture_root, lanes, modes)
        return 0
    raise ValueError("usage: generate-common-credential-root-stage-requests.py [check|generate OUTPUT_ROOT [--fixture-root FIXTURE_ROOT [--fixture-variant LANE-MODE]]]")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, ValueError) as error:
        print(f"common-credential-root stage request generation failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
