# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Deterministic synthetic vectors for the memory-bounded compound profile."""

from __future__ import annotations

import hashlib
import hmac
import sys
import argparse
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "fixture_support"))
import generate_fixtures as common  # noqa: E402


def credential_digest(data: bytes) -> bytes:
    if hasattr(common, "credential_digest"):
        return common.credential_digest(data)
    return common.digest(data)


def write_toml(folder: Path, name: str, fields: dict[str, object]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved",
        "#",
        "# SPDX-License-Identifier: MIT OR Apache-2.0",
        "#",
        "# Deterministic synthetic keys only. Never use these keys for issuance.",
        "",
    ]
    for key, value in fields.items():
        if not isinstance(value, dict):
            lines.append(f"{key} = {common.toml_value(value)}")
    for key, value in fields.items():
        if isinstance(value, dict):
            lines.extend(["", f"[{key}]"])
            for child_key, child in value.items():
                lines.append(f"{child_key} = {common.toml_value(child)}")
    (folder / f"{name}.toml").write_text("\n".join(lines) + "\n")


def issuer_status_fixture(
    public: dict[str, object], witness: dict[str, object],
    issuer_scalar: int, label: bytes, challenge: bytes,
    audience: bytes, transaction: bytes,
) -> dict[str, object]:
    """Bind the status witness to the same issuer credential as the claim stages."""
    issuer_private, issuer_x, issuer_y = common.key_pair(issuer_scalar)
    envelope = witness["envelope_hash"]
    claims_root = witness["merkle_root"]
    assert isinstance(envelope, bytes) and isinstance(claims_root, bytes)
    assert public["issuer_x"] == issuer_x and public["issuer_y"] == issuer_y
    expiry = public["expiry_unix"]
    assert isinstance(expiry, int)
    status_length = 8
    status_index = 0 if label == b"university" else 1
    status_chunk = bytes(32)
    status_root = hashlib.sha256(
        b"RMCSR1" + status_length.to_bytes(8, "big")
        + hashlib.sha256(b"RMCSL1" + status_chunk).digest()
    ).digest()
    list_id = hashlib.sha256(b"fixture status list:" + label).digest()
    url_hash = hashlib.sha256(b"https://issuer.example/status/" + label).digest()
    valid_from = 1_800_000_000
    valid_until = 2_000_000_000
    transcript = (
        b"BINDVLD1" + envelope + claims_root
        + valid_from.to_bytes(8, "big") + valid_until.to_bytes(8, "big")
        + url_hash + list_id + status_index.to_bytes(8, "big") + b"\x01"
    )
    signature = common.sign(issuer_private, hashlib.sha256(transcript).digest())
    return {
        "challenge": challenge,
        "audience_hash": audience,
        "transaction_data_hash": transaction,
        "slot": {
            "issuer_x": issuer_x,
            "issuer_y": issuer_y,
            "presentation_expiry": expiry,
            "credential_binding": public["credential_binding"],
            "status_root": status_root,
            "status_length": status_length,
            "status_list_id": list_id,
            "status_url_hash": url_hash,
            "status_purpose": 1,
            "verifier_now": common.FIXTURE_REQUEST_UNIX,
        },
        "witness": {
            "envelope_hash": envelope,
            "claims_root": claims_root,
            "issuer_validity_status_signature": signature,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "status_index": status_index,
            "status_chunk": status_chunk,
            "path_len": 0,
            "path": [bytes(32) for _ in range(12)],
        },
    }


def selected_claim_fixture(
    public: dict[str, object], witness: dict[str, object],
    issuer_scalar: int, subject_scalar: int, label: bytes,
    challenge: bytes, audience: bytes, transaction: bytes,
    join_salt: bytes, persona_mode: int, persona_scalar: int = 29,
    disclose_lineage: bool = False,
) -> dict[str, object]:
    issuer_private, issuer_x, issuer_y = common.key_pair(issuer_scalar)
    subject_private, subject_x, subject_y = common.key_pair(subject_scalar)
    _, persona_x, persona_y = common.key_pair(persona_scalar)
    envelope = witness["envelope_hash"]
    root = witness["merkle_root"]
    did_hash = witness["relationship_did_hash"]
    nonce = witness["relationship_nonce"]
    lineage_salt = witness["claim_salt"]
    expiry = public["expiry_unix"]
    assert all(isinstance(item, bytes) for item in (envelope, root, did_hash, nonce, lineage_salt))
    assert isinstance(expiry, int)
    context = common.digest(
        b"RMCTX1" + issuer_x + issuer_y + did_hash
        + witness["subject_x"] + witness["subject_y"] + nonce
    )
    prk = hmac.new(common.EXTRACT_SALT, bytes(range(1, 33)), hashlib.sha256).digest()
    lineage_tag = hmac.new(prk, context + b"\x01", hashlib.sha256).digest()
    lineage_value = context + lineage_tag
    lineage_inner = credential_digest(
        b"CLM1" + len(lineage_value).to_bytes(4, "big")
        + lineage_value + lineage_salt
    )
    lineage_leaf = credential_digest(b"LEAF1" + common.LINEAGE_NAME_HASH + lineage_inner)
    selected_name_hash, selected_value, selected_salt, claim_leaf = common.selected_claim(label)
    assert root == common.fold_claim_path(
        lineage_leaf, 0, common.two_leaf_claim_path(claim_leaf)
    )
    if disclose_lineage:
        name_hash, value, salt = common.LINEAGE_NAME_HASH, lineage_value, lineage_salt
        claim_index, claim_sibling = 0, claim_leaf
    else:
        name_hash, value, salt = selected_name_hash, selected_value, selected_salt
        claim_index, claim_sibling = 1, lineage_leaf
    compressed_persona = bytes([2 | (persona_y[-1] & 1)]) + persona_x
    signature = common.sign(
        issuer_private,
        credential_digest(b"BINDSUB1" + envelope + subject_x + subject_y),
    )
    link_signature = common.sign(
        subject_private, credential_digest(b"LINK1" + compressed_persona),
    )
    session_binding = credential_digest(
        (b"PSESB1" if persona_mode == 1 else b"PSESB2")
        + persona_x + persona_y + challenge + audience + transaction
        + expiry.to_bytes(8, "big")
    )
    subject_join = common.digest(
        b"RMSJOIN1" + subject_x + subject_y + join_salt
        + challenge + audience + transaction
    )
    return {
        "pk_issuer_x": issuer_x,
        "pk_issuer_y": issuer_y,
        "pk_persona_x": persona_x,
        "pk_persona_y": persona_y,
        "challenge": challenge,
        "audience_hash": audience,
        "transaction_data_hash": transaction,
        "expiry_unix": expiry,
        "session_binding": session_binding,
        "credential_binding": public["credential_binding"],
        "subject_join": subject_join,
        "val_len": len(value),
        "val_pub": value + bytes(64 - len(value)),
        "name_hash": name_hash,
        "envelope_hash": envelope,
        "merkle_root": root,
        "issuer_subject_bind_sig": signature,
        "pk_subject_x": subject_x,
        "pk_subject_y": subject_y,
        "subject_link_sig": link_signature,
        "join_salt": join_salt,
        "salt": salt,
        "index": claim_index,
        "path_len": common.CLAIM_TREE_DEPTH,
        "path": common.two_leaf_claim_path(claim_sibling),
    }


def lineage_leaf_digest(
    witness: dict[str, object], issuer_scalar: int, prk: bytes,
) -> bytes:
    """Recompute the reserved lineage leaf from one lineage witness."""
    _, issuer_x, issuer_y = common.key_pair(issuer_scalar)
    did_hash = witness["relationship_did_hash"]
    nonce = witness["relationship_nonce"]
    salt = witness["claim_salt"]
    subject_x = witness["subject_x"]
    subject_y = witness["subject_y"]
    assert all(
        isinstance(item, bytes)
        for item in (did_hash, nonce, salt, subject_x, subject_y)
    )
    context = common.digest(
        b"RMCTX1" + issuer_x + issuer_y + did_hash + subject_x + subject_y + nonce
    )
    lineage_tag = hmac.new(prk, context + b"\x01", hashlib.sha256).digest()
    value = context + lineage_tag
    inner = credential_digest(b"CLM1" + len(value).to_bytes(4, "big") + value + salt)
    return credential_digest(b"LEAF1" + common.LINEAGE_NAME_HASH + inner)


def short_path_claim(
    claim: dict[str, object], challenge: bytes, audience: bytes, transaction: bytes,
) -> dict[str, object]:
    """The same claim opened in a two-leaf tree with no padding levels.

    Every binding is recomputed for that shorter tree, so only the fixed-depth
    rule rejects it.
    """
    value = claim["val_pub"]
    length = claim["val_len"]
    name_hash = claim["name_hash"]
    salt = claim["salt"]
    path = claim["path"]
    index = claim["index"]
    expiry = claim["expiry_unix"]
    envelope = claim["envelope_hash"]
    issuer_x = claim["pk_issuer_x"]
    issuer_y = claim["pk_issuer_y"]
    assert isinstance(value, bytes) and isinstance(length, int)
    assert isinstance(path, list) and isinstance(index, int) and isinstance(expiry, int)
    assert all(isinstance(item, bytes) for item in (name_hash, salt, envelope, issuer_x, issuer_y))
    inner = credential_digest(
        b"CLM1" + length.to_bytes(4, "big") + value[:length] + salt
    )
    leaf = credential_digest(b"LEAF1" + name_hash + inner)
    sibling = path[0]
    root = credential_digest(
        b"NODE1" + (leaf + sibling if index == 0 else sibling + leaf)
    )
    short = dict(claim)
    short["merkle_root"] = root
    short["path_len"] = 1
    short["path"] = [sibling] + [bytes(32) for _ in range(common.CLAIM_TREE_DEPTH - 1)]
    short["credential_binding"] = credential_digest(
        b"CREDB1" + issuer_x + issuer_y + envelope + root
        + challenge + audience + transaction + expiry.to_bytes(8, "big")
    )
    return short


def persona_session_fixture(
    persona_mode: int, challenge: bytes, audience: bytes,
    transaction: bytes, persona_scalar: int = 29,
) -> dict[str, object]:
    persona_private, persona_x, persona_y = common.key_pair(persona_scalar)
    expiry = common.FIXTURE_EXPIRY_UNIX
    expiry_bytes = expiry.to_bytes(8, "big")
    session_binding = credential_digest(
        (b"PSESB1" if persona_mode == 1 else b"PSESB2")
        + persona_x + persona_y + challenge + audience + transaction
        + expiry_bytes
    )
    message = credential_digest(
        (b"PERS1" if persona_mode == 1 else b"PERS2")
        + challenge + audience + transaction + expiry_bytes
    )
    fields: dict[str, object] = {
        "pk_persona_x": persona_x,
        "pk_persona_y": persona_y,
        "challenge": challenge,
        "audience_hash": audience,
        "transaction_data_hash": transaction,
        "expiry_unix": expiry,
        "session_binding": session_binding,
    }
    signature_name = "persona_fresh_sig" if persona_mode == 1 else "persona_sig"
    fields[signature_name] = common.sign(persona_private, message)
    return fields


def parse_bytes32(value: str | None, default: bytes) -> bytes:
    if value is None:
        return default
    parsed = bytes.fromhex(value)
    if len(parsed) != 32:
        raise ValueError("request binding overrides must be 32 bytes")
    return parsed


def main() -> None:
    global HERE
    parser = argparse.ArgumentParser(
        description="Generate deterministic common-credential-root split fixtures.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=HERE,
        help="fixture root to write; defaults to the checked-in fixture tree",
    )
    parser.add_argument("--challenge-hex", help="32-byte OpenID4VP nonce hash")
    parser.add_argument("--audience-hex", help="32-byte OpenID4VP audience hash")
    parser.add_argument(
        "--transaction-hex",
        help="32-byte OpenID4VP transaction-data public input",
    )
    args = parser.parse_args()
    HERE = args.output_root.resolve()
    HERE.mkdir(parents=True, exist_ok=True)

    root = bytes(range(1, 33))
    prk = hmac.new(common.EXTRACT_SALT, root, hashlib.sha256).digest()
    reallyme_private, reallyme_x, reallyme_y = common.key_pair(7)
    policy_id = common.digest(b"fixture assurance policy")
    challenge = parse_bytes32(args.challenge_hex, common.digest(b"fixture verifier challenge"))
    audience = parse_bytes32(args.audience_hex, common.digest(b"fixture verifier audience"))
    transaction = parse_bytes32(args.transaction_hex, common.digest(b"fixture transaction"))
    join_salt = common.digest(b"fixture private presentation join salt")
    root_join = common.digest(
        b"RMRJOIN1" + root + join_salt + challenge + audience + transaction
    )
    for persona_mode, mode_name in ((1, "public"), (2, "private")):
        folder = HERE / "session_fixtures" / mode_name
        folder.mkdir(parents=True, exist_ok=True)
        session = persona_session_fixture(
            persona_mode, challenge, audience, transaction,
        )
        write_toml(folder, "Prover", session)
        wrong_signature = dict(session)
        wrong_signature[
            "persona_fresh_sig" if persona_mode == 1 else "persona_sig"
        ] = bytes(64)
        write_toml(folder, "ProverWrongSignature", wrong_signature)
        write_toml(
            folder, "ProverOtherPersona",
            persona_session_fixture(
                persona_mode, challenge, audience, transaction,
                persona_scalar=31,
            ),
        )
    request_unix = common.FIXTURE_REQUEST_UNIX
    presentation_expiry_unix = common.FIXTURE_EXPIRY_UNIX
    issued_unix = 1_800_000_000
    expires_unix = 2_000_000_000
    epoch = 3
    commitment = common.digest(b"RMROOT1" + root)
    attestation_digest = common.digest(
        b"RMRA1" + commitment + policy_id
        + issued_unix.to_bytes(8, "big")
        + expires_unix.to_bytes(8, "big")
        + epoch.to_bytes(4, "big")
    )
    attestation_signature = common.sign(reallyme_private, attestation_digest)
    attestation_id = common.digest(
        b"RMRAID1" + reallyme_x + reallyme_y
        + attestation_digest + attestation_signature
    )
    attestation_join = common.digest(
        b"RMATJOIN1" + attestation_id + join_salt
        + challenge + audience + transaction
    )
    current_status_root = common.digest(b"RMSTL2" + attestation_id)
    assurance = {
        "reallyme_x": reallyme_x,
        "reallyme_y": reallyme_y,
        "assurance_policy_id": policy_id,
        "request_unix": request_unix,
        "presentation_expiry_unix": presentation_expiry_unix,
        "challenge": challenge,
        "audience_hash": audience,
        "transaction_data_hash": transaction,
        "active_status_root": current_status_root,
        "root_join": root_join,
        "root": root,
        "attestation_issued_unix": issued_unix,
        "attestation_expires_unix": expires_unix,
        "attestation_epoch": epoch,
        "attestation_signature": attestation_signature,
        "join_salt": join_salt,
        "status_index": 0,
        "status_path_len": 0,
        "status_path": [bytes(32) for _ in range(20)],
    }
    status_path = dict(assurance)
    status_sibling = common.digest(b"synthetic active status sibling")
    status_path["status_index"] = 1
    status_path["status_path_len"] = 1
    status_path["status_path"] = [status_sibling] + [bytes(32) for _ in range(19)]
    status_path["active_status_root"] = common.digest(
        b"RMSTN1" + status_sibling + current_status_root
    )
    wrong_status_path = dict(status_path)
    wrong_status_path["status_path"] = [common.digest(b"wrong sibling")] + [
        bytes(32) for _ in range(19)
    ]
    attestation_fields = {
        key: assurance[key] for key in (
            "reallyme_x", "reallyme_y", "assurance_policy_id",
            "request_unix", "presentation_expiry_unix", "challenge", "audience_hash",
            "transaction_data_hash", "root_join", "root",
            "attestation_issued_unix", "attestation_expires_unix",
            "attestation_epoch", "attestation_signature", "join_salt",
        )
    }
    attestation_fields["attestation_join"] = attestation_join
    status_fields = {
        key: assurance[key] for key in (
            "challenge", "audience_hash", "transaction_data_hash",
            "active_status_root", "root_join", "root", "join_salt",
            "status_index", "status_path_len", "status_path",
        )
    }
    status_fields["active_status_root"] = current_status_root
    status_fields["attestation_join"] = attestation_join
    status_fields["attestation_id"] = attestation_id
    write_toml(HERE / "root_attestation", "Prover", attestation_fields)
    write_toml(
        HERE / "root_attestation", "ProverBackdated",
        {**attestation_fields, "request_unix": issued_unix + 1},
    )
    other_policy = common.digest(b"different valid assurance policy")
    other_digest = common.digest(
        b"RMRA1" + commitment + other_policy
        + issued_unix.to_bytes(8, "big")
        + expires_unix.to_bytes(8, "big")
        + epoch.to_bytes(4, "big")
    )
    other_signature = common.sign(reallyme_private, other_digest)
    other_id = common.digest(
        b"RMRAID1" + reallyme_x + reallyme_y + other_digest + other_signature
    )
    other_join = common.digest(
        b"RMATJOIN1" + other_id + join_salt
        + challenge + audience + transaction
    )
    write_toml(
        HERE / "root_attestation", "ProverOtherAttestation",
        {
            **attestation_fields,
            "assurance_policy_id": other_policy,
            "attestation_signature": other_signature,
            "attestation_join": other_join,
        },
    )
    write_toml(HERE / "root_status", "Prover", status_fields)
    write_toml(
        HERE / "root_attestation", "ProverWrongRoot",
        {**attestation_fields, "root": common.digest(b"different root")},
    )
    write_toml(
        HERE / "root_attestation", "ProverWrongJoin",
        {**attestation_fields, "root_join": common.digest(b"different join")},
    )
    write_toml(
        HERE / "root_attestation", "ProverWrongAttestationJoin",
        {**attestation_fields, "attestation_join": common.digest(b"different attestation join")},
    )
    write_toml(
        HERE / "root_attestation", "ProverWrongPolicy",
        {
            **attestation_fields,
            "assurance_policy_id": common.digest(b"different assurance policy"),
        },
    )
    write_toml(
        HERE / "root_attestation", "ProverWrongSignature",
        {**attestation_fields, "attestation_signature": bytes(64)},
    )
    expires_before_presentation = dict(attestation_fields)
    expires_before_presentation["attestation_expires_unix"] = presentation_expiry_unix
    expires_before_presentation["attestation_signature"] = common.sign(
        reallyme_private,
        common.digest(
            b"RMRA1" + commitment + policy_id
            + issued_unix.to_bytes(8, "big")
            + presentation_expiry_unix.to_bytes(8, "big")
            + epoch.to_bytes(4, "big")
        ),
    )
    write_toml(
        HERE / "root_attestation",
        "ProverExpiresBeforePresentation",
        expires_before_presentation,
    )
    expired = dict(attestation_fields)
    expired["attestation_expires_unix"] = request_unix
    expired["attestation_signature"] = common.sign(
        reallyme_private,
        common.digest(
            b"RMRA1" + commitment + policy_id
            + issued_unix.to_bytes(8, "big")
            + request_unix.to_bytes(8, "big")
            + epoch.to_bytes(4, "big")
        ),
    )
    write_toml(HERE / "root_attestation", "ProverExpired", expired)
    write_toml(
        HERE / "root_status", "ProverWrongStatus",
        {**status_fields, "active_status_root": common.digest(b"wrong status")},
    )
    write_toml(
        HERE / "root_status", "ProverWrongJoin",
        {**status_fields, "root_join": common.digest(b"different join")},
    )
    write_toml(
        HERE / "root_status", "ProverWrongAttestationJoin",
        {**status_fields, "attestation_join": common.digest(b"different attestation join")},
    )
    write_toml(
        HERE / "root_status", "ProverWrongAttestationId",
        {**status_fields, "attestation_id": other_id, "attestation_join": other_join},
    )
    write_toml(
        HERE / "root_status", "ProverWrongRoot",
        {**status_fields, "root": common.digest(b"different root")},
    )
    path_fields = dict(status_fields)
    for key in ("status_index", "status_path_len", "status_path"):
        path_fields[key] = status_path[key]
    path_fields["active_status_root"] = common.digest(
        b"RMSTN1" + status_sibling + current_status_root
    )
    write_toml(HERE / "root_status", "ProverStatusPath", path_fields)
    write_toml(
        HERE / "root_status", "ProverWrongStatusPath",
        {**path_fields, "status_path": wrong_status_path["status_path"]},
    )

    for fixture_name, issuer_scalar, subject_scalar, label in (
        ("Prover", 11, 13, b"university"),
        ("ProverEmployer", 17, 19, b"employer"),
    ):
        public, witness = common.slot(
            issuer_scalar, subject_scalar, label, prk,
            challenge, audience, transaction, join_salt,
        )
        lineage = {
            "challenge": challenge,
            "audience_hash": audience,
            "transaction_data_hash": transaction,
            "root_join": root_join,
            "root": root,
            "join_salt": join_salt,
            "slot": public,
            "witness": witness,
        }
        write_toml(HERE / "lineage", fixture_name, lineage)
        write_toml(
            HERE / "issuer_credential_status", fixture_name,
            issuer_status_fixture(
                public, witness, issuer_scalar, label,
                challenge, audience, transaction,
            ),
        )
        for persona_mode, folder_name in (
            (1, "public_persona_claim"),
            (2, "private_persona_claim"),
        ):
            claim = selected_claim_fixture(
                public, witness, issuer_scalar, subject_scalar, label,
                challenge, audience, transaction, join_salt, persona_mode,
            )
            write_toml(HERE / folder_name, fixture_name, claim)
            if fixture_name == "ProverEmployer":
                different_persona = selected_claim_fixture(
                    public, witness, issuer_scalar, subject_scalar, label,
                    challenge, audience, transaction, join_salt, persona_mode,
                    persona_scalar=31,
                )
                write_toml(
                    HERE / folder_name, "ProverEmployerDifferentPersona",
                    different_persona,
                )
            if fixture_name == "Prover":
                lineage_disclosure = selected_claim_fixture(
                    public, witness, issuer_scalar, subject_scalar, label,
                    challenge, audience, transaction, join_salt, persona_mode,
                    disclose_lineage=True,
                )
                write_toml(
                    HERE / folder_name, "ProverLineageDisclosure", lineage_disclosure,
                )
                write_toml(
                    HERE / folder_name, "ProverShortPath",
                    short_path_claim(claim, challenge, audience, transaction),
                )
                wrong_join_claim = dict(claim)
                wrong_join_claim["subject_join"] = common.digest(b"wrong subject join")
                write_toml(HERE / folder_name, "ProverWrongJoin", wrong_join_claim)
                alternate_subject = selected_claim_fixture(
                    public, witness, issuer_scalar, 23, label,
                    challenge, audience, transaction, join_salt, persona_mode,
                )
                write_toml(HERE / folder_name, "ProverOtherValidSubject", alternate_subject)
                wrong_claim = dict(claim)
                wrong_claim["val_pub"] = b"invalid:" + label + bytes(64 - len(b"invalid:" + label))
                write_toml(HERE / folder_name, "ProverWrongClaim", wrong_claim)
        if fixture_name == "Prover":
            wrong_slot = dict(lineage)
            wrong_slot_witness = dict(witness)
            wrong_slot_witness["leaf_index"] = 1
            wrong_slot["witness"] = wrong_slot_witness
            write_toml(HERE / "lineage", "ProverWrongLineageSlot", wrong_slot)
            bad_root = dict(lineage)
            bad_root["root"] = common.digest(b"different root")
            write_toml(HERE / "lineage", "ProverWrongRoot", bad_root)
            bad_subject = dict(lineage)
            bad_witness = dict(witness)
            _, bad_witness["subject_x"], bad_witness["subject_y"] = common.key_pair(23)
            bad_subject["witness"] = bad_witness
            write_toml(HERE / "lineage", "ProverWrongSubject", bad_subject)
            bad_claim = dict(lineage)
            bad_witness = dict(witness)
            bad_witness["relationship_nonce"] = common.digest(b"different nonce")
            bad_claim["witness"] = bad_witness
            write_toml(HERE / "lineage", "ProverWrongLineage", bad_claim)
            bad_binding = dict(lineage)
            bad_slot = dict(public)
            bad_slot["credential_binding"] = common.digest(b"different credential")
            bad_binding["slot"] = bad_slot
            write_toml(HERE / "lineage", "ProverWrongBinding", bad_binding)
            bad_join = dict(lineage)
            bad_join["root_join"] = common.digest(b"different root join")
            write_toml(HERE / "lineage", "ProverWrongJoin", bad_join)

            bad_signature = dict(lineage)
            bad_witness = dict(witness)
            bad_witness["issuer_root_bind_sig"] = bytes(64)
            bad_signature["witness"] = bad_witness
            write_toml(HERE / "lineage", "ProverWrongIssuerSignature", bad_signature)

            def lineage_case(path: list[bytes], path_len: int) -> dict[str, object]:
                """Lineage fixture whose issuer signature covers the given path's root."""
                case = dict(lineage)
                case_witness = dict(witness)
                envelope = witness["envelope_hash"]
                assert isinstance(envelope, bytes)
                node = lineage_leaf_digest(witness, issuer_scalar, prk)
                for sibling in path[:path_len]:
                    node = credential_digest(b"NODE1" + node + sibling)
                case_witness["merkle_root"] = node
                case_witness["path_len"] = path_len
                case_witness["path"] = path[:path_len] + [
                    bytes(32) for _ in range(common.CLAIM_TREE_DEPTH - path_len)
                ]
                issuer_private, issuer_x, issuer_y = common.key_pair(issuer_scalar)
                case_witness["issuer_root_bind_sig"] = common.sign(
                    issuer_private,
                    credential_digest(b"BINDMRK1" + envelope + node),
                )
                case_slot = dict(public)
                expiry = case_slot["expiry_unix"]
                assert isinstance(expiry, int)
                case_slot["credential_binding"] = credential_digest(
                    b"CREDB1" + issuer_x + issuer_y + envelope + node
                    + challenge + audience + transaction + expiry.to_bytes(8, "big")
                )
                case["slot"] = case_slot
                case["witness"] = case_witness
                return case

            full_path = witness["path"]
            assert isinstance(full_path, list)
            # A populated second-level sibling exercises a non-empty upper path.
            sibling = credential_digest(b"synthetic lineage sibling")
            populated_path = [full_path[0], sibling] + full_path[2:]
            path_case = lineage_case(populated_path, common.CLAIM_TREE_DEPTH)
            write_toml(HERE / "lineage", "ProverMerklePath", path_case)
            wrong_path = dict(path_case)
            wrong_witness = dict(path_case["witness"])
            wrong_witness["path"] = [
                full_path[0], credential_digest(b"wrong sibling")
            ] + full_path[2:]
            wrong_path["witness"] = wrong_witness
            write_toml(HERE / "lineage", "ProverWrongMerklePath", wrong_path)
            # Correctly signed trees of every shorter depth must be rejected:
            # only the fixed depth is a valid claim tree.
            write_toml(
                HERE / "lineage", "ProverShortPath", lineage_case(full_path, 1),
            )
            write_toml(
                HERE / "lineage", "ProverShortPathFive",
                lineage_case(full_path, common.CLAIM_TREE_DEPTH - 1),
            )


if __name__ == "__main__":
    main()
