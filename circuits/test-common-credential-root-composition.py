# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Conformance checks over verified common-credential-root proof public inputs.

The caller must verify each Barretenberg proof against its pinned VK first.
This test checks mandatory joins, including a selected claim with a distinct
valid issuer-bound subject for the same credential envelope and Merkle root.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path


FIELD_BYTES = 32
SPLIT_FIELDS = 257
ATTESTATION_FIELDS = 258
STATUS_FIELDS = 192
CREDENTIAL_SUBJECT_CLAIM_FIELDS = 354
PUBLIC_CLAIM_FIELDS = 418
PRIVATE_SESSION_FIELDS = 129
PUBLIC_SESSION_FIELDS = 193
ACTIVE_REQUEST_UNIX = 1_900_000_000
MAX_PRESENTATION_LIFETIME_SECONDS = 300
ACTIVE_CHALLENGE = hashlib.sha256(b"fixture verifier challenge").digest()
ACTIVE_AUDIENCE_HASH = hashlib.sha256(b"fixture verifier audience").digest()
ACTIVE_TRANSACTION_DATA_HASH = hashlib.sha256(b"fixture transaction").digest()
# Synthetic verifier trust policy. These values are independent of the proof
# public inputs and model the signers, policy, and signed status snapshot that
# a real verifier resolves from its own trust configuration.
TRUSTED_REALLYME_KEY = (
    bytes.fromhex("8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3"),
    bytes.fromhex("73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4"),
)
TRUSTED_ASSURANCE_POLICY = bytes.fromhex(
    "ad1927afb41bd21ab87899732707f7c8aa5a75d97f4a43457cbc5f846095321d"
)
TRUSTED_STATUS_ROOT = bytes.fromhex(
    "b2079dd0ae99debe99a236712b550503afcd60eab87c7cdec364dc6152e02feb"
)
TRUSTED_ISSUER_KEYS = (
    (
        bytes.fromhex("3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1"),
        bytes.fromhex("9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740"),
    ),
    (
        bytes.fromhex("47776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73e"),
        bytes.fromhex("aa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc"),
    ),
)


@dataclass(frozen=True)
class Slot:
    issuer_x: bytes
    issuer_y: bytes
    expiry_unix: int
    credential_binding: bytes
    subject_join: bytes


@dataclass(frozen=True)
class CommonCredentialRoot:
    challenge: bytes
    audience_hash: bytes
    transaction_data_hash: bytes
    slots: tuple[Slot, Slot]


@dataclass(frozen=True)
class Assurance:
    challenge: bytes
    audience_hash: bytes
    transaction_data_hash: bytes
    root_join: bytes
    request_unix: int
    attestation_join: bytes
    signer_key: tuple[bytes, bytes] | None = None
    policy_id: bytes | None = None
    status_root: bytes | None = None


@dataclass(frozen=True)
class Lineage:
    challenge: bytes
    audience_hash: bytes
    transaction_data_hash: bytes
    root_join: bytes
    slot: Slot


@dataclass(frozen=True)
class SelectedClaim:
    issuer_x: bytes
    issuer_y: bytes
    challenge: bytes
    audience_hash: bytes
    transaction_data_hash: bytes
    expiry_unix: int
    persona_mode: int
    session_binding: bytes
    credential_binding: bytes
    subject_join: bytes
    persona_key: tuple[bytes, bytes] | None
    claim_name_hash: bytes
    claim_value: bytes


@dataclass(frozen=True)
class PersonaSession:
    challenge: bytes
    audience_hash: bytes
    transaction_data_hash: bytes
    expiry_unix: int
    session_binding: bytes
    persona_key: tuple[bytes, bytes] | None


def read_fields(path: Path, expected: int) -> list[bytes]:
    raw = path.read_bytes()
    if len(raw) != expected * FIELD_BYTES:
        raise ValueError("invalid public input count")
    return [raw[i * FIELD_BYTES:(i + 1) * FIELD_BYTES] for i in range(expected)]


def bytes32(fields: list[bytes], first: int) -> bytes:
    selected = fields[first:first + 32]
    if len(selected) != 32 or any(field[:-1] != bytes(31) for field in selected):
        raise ValueError("noncanonical byte public input")
    return bytes(field[-1] for field in selected)


def bytes64(fields: list[bytes], first: int) -> bytes:
    selected = fields[first:first + 64]
    if len(selected) != 64 or any(field[:-1] != bytes(31) for field in selected):
        raise ValueError("noncanonical selected-claim byte public input")
    return bytes(field[-1] for field in selected)


def integer(fields: list[bytes], index: int, max_value: int) -> int:
    value = int.from_bytes(fields[index], "big")
    if value > max_value:
        raise ValueError("integer public input out of range")
    return value


def read_selected_claim(path: Path, persona_mode: int) -> SelectedClaim:
    if persona_mode == 1:
        fields = read_fields(path, PUBLIC_CLAIM_FIELDS)
        offset = 64
    elif persona_mode == 2:
        fields = read_fields(path, CREDENTIAL_SUBJECT_CLAIM_FIELDS)
        offset = 0
    else:
        raise ValueError("unsupported persona mode")
    value_length = integer(fields, offset + 257, 64)
    padded_value = bytes64(fields, offset + 258)
    if value_length == 0 or any(padded_value[value_length:]):
        raise ValueError("invalid selected-claim length or padding")
    return SelectedClaim(
        issuer_x=bytes32(fields, 0),
        issuer_y=bytes32(fields, 32),
        challenge=bytes32(fields, offset + 64),
        audience_hash=bytes32(fields, offset + 96),
        transaction_data_hash=bytes32(fields, offset + 128),
        expiry_unix=integer(fields, offset + 160, (1 << 64) - 1),
        persona_mode=persona_mode,
        session_binding=bytes32(fields, offset + 161),
        credential_binding=bytes32(fields, offset + 193),
        subject_join=bytes32(fields, offset + 225),
        persona_key=(bytes32(fields, 64), bytes32(fields, 96))
        if persona_mode == 1 else None,
        claim_name_hash=bytes32(fields, offset + 322),
        claim_value=padded_value[:value_length],
    )


def read_persona_session(path: Path, persona_mode: int) -> PersonaSession:
    if persona_mode == 1:
        fields = read_fields(path, PUBLIC_SESSION_FIELDS)
        offset = 64
    elif persona_mode == 2:
        fields = read_fields(path, PRIVATE_SESSION_FIELDS)
        offset = 0
    else:
        raise ValueError("unsupported persona mode")
    return PersonaSession(
        challenge=bytes32(fields, offset),
        audience_hash=bytes32(fields, offset + 32),
        transaction_data_hash=bytes32(fields, offset + 64),
        expiry_unix=integer(fields, offset + 96, (1 << 64) - 1),
        session_binding=bytes32(fields, offset + 97),
        persona_key=(bytes32(fields, 0), bytes32(fields, 32))
        if persona_mode == 1 else None,
    )


def read_attestation(path: Path) -> Assurance:
    fields = read_fields(path, ATTESTATION_FIELDS)
    return Assurance(
        challenge=bytes32(fields, 98),
        audience_hash=bytes32(fields, 130),
        transaction_data_hash=bytes32(fields, 162),
        root_join=bytes32(fields, 194),
        request_unix=integer(fields, 96, (1 << 64) - 1),
        attestation_join=bytes32(fields, 226),
        signer_key=(bytes32(fields, 0), bytes32(fields, 32)),
        policy_id=bytes32(fields, 64),
    )


def read_status(path: Path) -> Assurance:
    fields = read_fields(path, STATUS_FIELDS)
    return Assurance(
        challenge=bytes32(fields, 0),
        audience_hash=bytes32(fields, 32),
        transaction_data_hash=bytes32(fields, 64),
        root_join=bytes32(fields, 128),
        request_unix=0,
        attestation_join=bytes32(fields, 160),
        status_root=bytes32(fields, 96),
    )


def read_lineage(path: Path) -> Lineage:
    fields = read_fields(path, SPLIT_FIELDS)
    return Lineage(
        challenge=bytes32(fields, 0),
        audience_hash=bytes32(fields, 32),
        transaction_data_hash=bytes32(fields, 64),
        root_join=bytes32(fields, 96),
        slot=Slot(
            issuer_x=bytes32(fields, 128),
            issuer_y=bytes32(fields, 160),
            expiry_unix=integer(fields, 192, (1 << 64) - 1),
            credential_binding=bytes32(fields, 193),
            subject_join=bytes32(fields, 225),
        ),
    )


def split_root(assurance: Assurance, lineages: tuple[Lineage, Lineage]) -> CommonCredentialRoot:
    for lineage in lineages:
        if (
            lineage.root_join != assurance.root_join
            or lineage.challenge != assurance.challenge
            or lineage.audience_hash != assurance.audience_hash
            or lineage.transaction_data_hash != assurance.transaction_data_hash
        ):
            raise ValueError("lineage does not join assured root and active session")
    return CommonCredentialRoot(
        challenge=assurance.challenge,
        audience_hash=assurance.audience_hash,
        transaction_data_hash=assurance.transaction_data_hash,
        slots=(lineages[0].slot, lineages[1].slot),
    )


def matches_active_time(assurance: Assurance) -> bool:
    return assurance.request_unix == ACTIVE_REQUEST_UNIX


def matches_active_request(
    challenge: bytes,
    audience_hash: bytes,
    transaction_data_hash: bytes,
) -> bool:
    return (
        challenge == ACTIVE_CHALLENGE
        and audience_hash == ACTIVE_AUDIENCE_HASH
        and transaction_data_hash == ACTIVE_TRANSACTION_DATA_HASH
    )


def valid_presentation_expiry(expiry_unix: int) -> bool:
    lifetime = expiry_unix - ACTIVE_REQUEST_UNIX
    return 0 < lifetime <= MAX_PRESENTATION_LIFETIME_SECONDS


def valid_active_root(root: CommonCredentialRoot) -> bool:
    return (
        matches_active_request(
            root.challenge, root.audience_hash, root.transaction_data_hash,
        )
        and root.slots[0].credential_binding != root.slots[1].credential_binding
        and all(valid_presentation_expiry(slot.expiry_unix) for slot in root.slots)
        and all(
            (slot.issuer_x, slot.issuer_y) == TRUSTED_ISSUER_KEYS[index]
            for index, slot in enumerate(root.slots)
        )
    )


def trusted_assurance_and_status(attestation: Assurance, status: Assurance) -> bool:
    return (
        attestation.signer_key == TRUSTED_REALLYME_KEY
        and attestation.policy_id == TRUSTED_ASSURANCE_POLICY
        and status.status_root == TRUSTED_STATUS_ROOT
        and assurance_status_join(attestation, status)
    )


def assurance_status_join(attestation: Assurance, status: Assurance) -> bool:
    return (
        attestation.challenge == status.challenge
        and attestation.audience_hash == status.audience_hash
        and attestation.transaction_data_hash == status.transaction_data_hash
        and attestation.root_join == status.root_join
        and attestation.attestation_join == status.attestation_join
    )


def joins_match(
    root: CommonCredentialRoot,
    links: tuple[SelectedClaim, SelectedClaim],
) -> bool:
    if links[0].persona_mode != links[1].persona_mode:
        return False
    if links[0].session_binding != links[1].session_binding:
        return False
    for slot, link in zip(root.slots, links, strict=True):
        if (
            slot.issuer_x != link.issuer_x
            or slot.issuer_y != link.issuer_y
            or slot.expiry_unix != link.expiry_unix
            or slot.credential_binding != link.credential_binding
            or slot.subject_join != link.subject_join
            or root.challenge != link.challenge
            or root.audience_hash != link.audience_hash
            or root.transaction_data_hash != link.transaction_data_hash
        ):
            return False
    return True


def session_matches(
    root: CommonCredentialRoot,
    claims: tuple[SelectedClaim, SelectedClaim],
    session: PersonaSession,
) -> bool:
    for claim in claims:
        if (
            session.challenge != root.challenge
            or session.audience_hash != root.audience_hash
            or session.transaction_data_hash != root.transaction_data_hash
            or session.expiry_unix != claim.expiry_unix
            or session.session_binding != claim.session_binding
            or session.persona_key != claim.persona_key
        ):
            return False
    return True


def requested_claim_matches(claim: SelectedClaim, role: bytes) -> bool:
    return (
        claim.claim_name_hash
        == hashlib.sha256(b"fixture selected claim name:" + role).digest()
        and claim.claim_value == b"verified:" + role
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("lane", choices=("sha256", "poseidon2"))
    parser.add_argument("--joined-claims", choices=("private", "public"))
    args = parser.parse_args()
    family = Path(__file__).resolve().parent / args.lane / "families/common_credential_root_v1"
    assurance = read_attestation(
        family / "root_attestation/target/attestation-proof/public_inputs"
    )
    status = read_status(
        family / "root_status/target/status-proof/public_inputs"
    )
    if not trusted_assurance_and_status(assurance, status):
        raise ValueError("assurance or status is outside verifier trust policy")
    if trusted_assurance_and_status(
        replace(assurance, signer_key=(bytes(32), bytes(32))), status,
    ):
        raise ValueError("untrusted ReallyMe signer accepted")
    if trusted_assurance_and_status(
        replace(assurance, policy_id=bytes(32)), status,
    ):
        raise ValueError("untrusted assurance policy accepted")
    if trusted_assurance_and_status(
        assurance, replace(status, status_root=bytes(32)),
    ):
        raise ValueError("untrusted status snapshot accepted")
    backdated = read_attestation(
        family / "root_attestation/target/attestation-proof-backdated/public_inputs"
    )
    if matches_active_time(backdated):
        raise ValueError("backdated proof accepted active request time")
    if (
        backdated.challenge != status.challenge
        or backdated.root_join != status.root_join
    ):
        raise ValueError("backdated proof was not otherwise joinable")
    other_attestation = read_attestation(
        family / "root_attestation/target/attestation-proof-other/public_inputs"
    )
    if other_attestation.root_join != status.root_join:
        raise ValueError("distinct attestation test changed the root")
    if assurance_status_join(other_attestation, status):
        raise ValueError("another attestation for the same root joined status")
    if not matches_active_time(assurance):
        raise ValueError("assurance request time differs from active request")
    university_lineage = read_lineage(
        family / "lineage/target/lineage-proof/public_inputs"
    )
    employer_lineage = read_lineage(
        family / "lineage/target/lineage-proof-employer/public_inputs"
    )
    root = split_root(assurance, (university_lineage, employer_lineage))
    if split_root(assurance, (employer_lineage, university_lineage)).slots == root.slots:
        raise ValueError("ordered slots were not preserved")
    mismatched_join = Lineage(
        challenge=employer_lineage.challenge,
        audience_hash=employer_lineage.audience_hash,
        transaction_data_hash=employer_lineage.transaction_data_hash,
        root_join=bytes(32),
        slot=employer_lineage.slot,
    )
    try:
        split_root(assurance, (university_lineage, mismatched_join))
    except ValueError:
        pass
    else:
        raise ValueError("unrelated root lineage joined")
    if not valid_active_root(root):
        raise ValueError("compound proof does not match the live request policy")
    if valid_active_root(replace(root, slots=(
        replace(root.slots[0], issuer_x=bytes(32)), root.slots[1],
    ))):
        raise ValueError("untrusted issuer accepted for first credential role")
    if valid_active_root(replace(root, slots=(
        root.slots[0], replace(root.slots[1], issuer_y=bytes(32)),
    ))):
        raise ValueError("untrusted issuer accepted for second credential role")
    if valid_active_root(CommonCredentialRoot(
        root.challenge, root.audience_hash, root.transaction_data_hash,
        (root.slots[0], root.slots[0]),
    )):
        raise ValueError("duplicate credential accepted in both slots")
    if matches_active_request(bytes(32), root.audience_hash, root.transaction_data_hash):
        raise ValueError("stale verifier challenge accepted")
    if valid_presentation_expiry(ACTIVE_REQUEST_UNIX + MAX_PRESENTATION_LIFETIME_SECONDS + 1):
        raise ValueError("overlong presentation lifetime accepted")
    if not args.joined_claims:
        print(f"{args.lane} compound public-input joins passed")
        return
    if args.joined_claims:
        mode = 2 if args.joined_claims == "private" else 1
        folder = "private_persona_claim" if mode == 2 else "public_persona_claim"
        university = read_selected_claim(
            family / f"{folder}/target/proof/public_inputs", mode,
        )
        employer = read_selected_claim(
            family / f"{folder}/target/proof-employer/public_inputs", mode,
        )
        different_persona = read_selected_claim(
            family / f"{folder}/target/proof-different-persona/public_inputs", mode,
        )
        other_subject = read_selected_claim(
            family / f"{folder}/target/proof-other-subject/public_inputs", mode,
        )
        if not requested_claim_matches(university, b"university") or not requested_claim_matches(
            employer, b"employer",
        ):
            raise ValueError("selected claims do not match ordered request roles")
        if requested_claim_matches(employer, b"university") or requested_claim_matches(
            university, b"employer",
        ):
            raise ValueError("swapped selected claims matched request roles")
        if requested_claim_matches(
            replace(university, claim_name_hash=bytes(32)), b"university",
        ):
            raise ValueError("wrong claim name matched university request")
        if requested_claim_matches(
            replace(university, claim_value=b"wrong value"), b"university",
        ):
            raise ValueError("wrong claim value matched university request")
        if joins_match(root, (other_subject, employer)):
            raise ValueError("another valid subject for the same credential joined")
        if other_subject.credential_binding != university.credential_binding:
            raise ValueError("other-subject gate changed the credential")
        session_package = (
            family.parent
            / "private_persona_claim_v1/session/target"
            if mode == 2 else family / "public_session/target"
        )
        session = read_persona_session(
            session_package / "common-credential-root-session-proof/public_inputs", mode,
        )
        other_persona_session = read_persona_session(
            session_package / "common-credential-root-other-persona-proof/public_inputs", mode,
        )
        if not session_matches(root, (university, employer), session):
            raise ValueError("persona session proof does not join both selected claims")
        if not matches_active_request(
            session.challenge, session.audience_hash, session.transaction_data_hash,
        ) or not valid_presentation_expiry(session.expiry_unix):
            raise ValueError("persona session proof does not match the live request")
        if session_matches(root, (university, employer), other_persona_session):
            raise ValueError("different valid persona session joined selected claims")
    if not joins_match(root, (university, employer)):
        raise ValueError("valid compound presentation failed to join")
    if joins_match(root, (employer, university)):
        raise ValueError("swapped slots joined")
    if joins_match(root, (university, university)):
        raise ValueError("duplicated credential joined")
    if joins_match(root, (university, different_persona)):
        raise ValueError("different presenting personas joined")
    print(f"{args.lane} compound public-input joins passed")


if __name__ == "__main__":
    main()
