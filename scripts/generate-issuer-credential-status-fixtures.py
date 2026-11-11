# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Generate synthetic, deterministic issuer-status proof fixtures for both hash lanes."""

from hashlib import sha256
import argparse
import os
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256


def array(value: bytes) -> str:
    return "[" + ", ".join(str(byte) for byte in value) + "]"


def be64(value: int) -> bytes:
    return value.to_bytes(8, "big")


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def bytes32_override(value: str | None, default: bytes) -> bytes:
    if value is None:
        return default
    parsed = bytes.fromhex(value)
    if len(parsed) != 32:
        raise ValueError("presentation binding overrides must be 32 bytes")
    return parsed


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mode", nargs="?", choices=("sha256", "poseidon2"), default="sha256")
parser.add_argument("--output-root", type=Path)
parser.add_argument("--challenge-hex")
parser.add_argument("--audience-hex")
parser.add_argument("--transaction-hex")
parser.add_argument("--verifier-now", type=int, default=1_800_000_000)
parser.add_argument("--presentation-expiry", type=int, default=1_800_000_120)
parser.add_argument("--status-length", type=int, default=8)
parser.add_argument("--status-index", type=int, default=3)
parser.add_argument("--prepared", action="store_true")
parser.add_argument("--token-index", type=int, default=0)
parser.add_argument("--prepared-from", type=int, default=1_800_000_000)
parser.add_argument("--prepared-until", type=int, default=1_800_086_400)
args = parser.parse_args()
if args.verifier_now < 0 or args.presentation_expiry <= args.verifier_now:
    raise ValueError("presentation expiry must follow verifier time")
if args.status_length < 1 or args.status_length > 1_000_000:
    raise ValueError("status length is outside the circuit limit")
if args.status_index < 0 or args.status_index >= args.status_length:
    raise ValueError("status index is outside the list")
if args.prepared and (args.token_index < 0 or args.prepared_from >= args.prepared_until):
    raise ValueError("invalid prepared token or window")

key = ec.derive_private_key(123456789, ec.SECP256R1())
mode = args.mode
numbers = key.public_key().public_numbers()
issuer_x = numbers.x.to_bytes(32, "big")
issuer_y = numbers.y.to_bytes(32, "big")
challenge = bytes32_override(args.challenge_hex, bytes([0x11]) * 32)
audience = bytes32_override(args.audience_hex, bytes([0x22]) * 32)
transaction = bytes32_override(args.transaction_hex, bytes([0x44]) * 32)
envelope = bytes([0xAA]) * 32
claims = bytes([0xBB]) * 32
list_id = bytes([0x33]) * 32
url_hash = sha256(b"https://issuer.example/status/shared").digest()
length = args.status_length
index = args.status_index
chunk = bytes(32)
valid_from = 1_700_000_000
verifier_now = args.verifier_now
presentation_expiry = args.presentation_expiry
valid_until = max(1_900_000_000, presentation_expiry + 1, args.prepared_until + 1)
leaves = [sha256(b"RMCSL1" + chunk).digest() for _ in range((length + 255) // 256)]
width = 1 << (len(leaves) - 1).bit_length()
leaves.extend([sha256(b"RMCSE1").digest()] * (width - len(leaves)))
path = []
position = index // 256
while len(leaves) > 1:
    path.append(leaves[position ^ 1])
    leaves = [
        sha256(b"RMCSN1" + leaves[offset] + leaves[offset + 1]).digest()
        for offset in range(0, len(leaves), 2)
    ]
    position //= 2
status_root = sha256(b"RMCSR1" + be64(length) + leaves[0]).digest()
if len(path) > 12:
    raise ValueError("status path exceeds the circuit limit")
p256_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def sign_validity(until: int) -> bytes:
    transcript = (
        b"BINDVLD1"
        + envelope
        + claims
        + be64(valid_from)
        + be64(until)
        + url_hash
        + list_id
        + be64(index)
        + bytes([1])
    )
    r, s = decode_dss_signature(key.sign(transcript, ec.ECDSA(SHA256(), deterministic_signing=True)))
    if s > p256_order // 2:
        s = p256_order - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


signature = sign_validity(valid_until)
holder_key = ec.derive_private_key(987654321 + args.token_index, ec.SECP256R1())
holder_numbers = holder_key.public_key().public_numbers()
holder_x = holder_numbers.x.to_bytes(32, "big")
holder_y = holder_numbers.y.to_bytes(32, "big")
subject_key = ec.derive_private_key(246813579, ec.SECP256R1())
subject_numbers = subject_key.public_key().public_numbers()
subject_x = subject_numbers.x.to_bytes(32, "big")
subject_y = subject_numbers.y.to_bytes(32, "big")
token_nonce = sha256(b"ReallyMe prepared test token" + be64(args.token_index)).digest()
if args.prepared:
    binding_preimage = (
        b"PRECB2"
        + issuer_x
        + issuer_y
        + envelope
        + claims
        + subject_x
        + subject_y
        + holder_x
        + holder_y
        + token_nonce
        + be64(args.prepared_from)
        + be64(args.prepared_until)
    )
else:
    binding_preimage = (
        b"CREDB1"
        + issuer_x
        + issuer_y
        + envelope
        + claims
        + challenge
        + audience
        + transaction
        + be64(presentation_expiry)
    )
if mode == "sha256":
    binding = sha256(binding_preimage).digest()
else:
    fixture_bin = os.environ.get(
        "POSEIDON2_FIXTURE_BIN",
        str(REPOSITORY_ROOT / "target/debug/poseidon2-bounded-fixture"),
    )
    result = subprocess.run(
        [fixture_bin],
        input=",".join(str(byte) for byte in binding_preimage) + "\n",
        text=True,
        check=True,
        capture_output=True,
    )
    binding = bytes(int(value) for value in result.stdout.strip().split(","))
lines = [
    "# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved",
    "#",
    "# SPDX-License-Identifier: MIT OR Apache-2.0",
    "# Synthetic fixture for circuit verification. The key is never used for issuance.",
    "[slot]",
    f"issuer_x = {array(issuer_x)}",
    f"issuer_y = {array(issuer_y)}",
    f"credential_binding = {array(binding)}",
    f"status_root = {array(status_root)}",
    f"status_length = {length}",
    f"status_list_id = {array(list_id)}",
    f"status_url_hash = {array(url_hash)}",
    "status_purpose = 1",
    "[witness]",
    f"envelope_hash = {array(envelope)}",
    f"claims_root = {array(claims)}",
    f"issuer_validity_status_signature = {array(signature)}",
    f"valid_from = {valid_from}",
    f"valid_until = {valid_until}",
    f"status_index = {index}",
    f"status_chunk = {array(chunk)}",
    f"path_len = {len(path)}",
    "path = [" + ", ".join(array(sibling) for sibling in path + [bytes(32)] * (12 - len(path))) + "]",
]
if args.prepared:
    lines[4:4] = []
    slot_index = lines.index("[slot]")
    lines[slot_index + 3:slot_index + 3] = [
        f"holder_x = {array(holder_x)}",
        f"holder_y = {array(holder_y)}",
        f"token_nonce = {array(token_nonce)}",
        f"prepared_from = {args.prepared_from}",
        f"prepared_until = {args.prepared_until}",
    ]
    witness_index = lines.index("[witness]")
    lines[witness_index + 3:witness_index + 3] = [
        f"subject_x = {array(subject_x)}",
        f"subject_y = {array(subject_y)}",
    ]
else:
    lines[4:4] = [
        f"challenge = {array(challenge)}",
        f"audience_hash = {array(audience)}",
        f"transaction_data_hash = {array(transaction)}",
    ]
    slot_index = lines.index("[slot]")
    lines[slot_index + 3:slot_index + 3] = [f"presentation_expiry = {presentation_expiry}"]
    witness_index = lines.index("[witness]")
    lines[witness_index:witness_index] = [f"verifier_now = {verifier_now}"]
folder = (
    args.output_root.resolve()
    if args.output_root is not None
    else REPOSITORY_ROOT / "circuits" / mode / "families" / (
        "persona_credential_evidence_v1" if args.prepared else "common_credential_root_v1"
    ) / ("current_state" if args.prepared else "issuer_credential_status")
)
folder.mkdir(parents=True, exist_ok=True)
fixture = "\n".join(lines) + "\n"
(folder / "Prover.toml").write_text(fixture)
expiring_until = args.prepared_until - 1 if args.prepared else verifier_now + 60
(folder / ("OutsideIssuerWindow.toml" if args.prepared else "ExpiresInSession.toml")).write_text(
    fixture.replace(f"valid_until = {valid_until}", f"valid_until = {expiring_until}")
    .replace(
        f"issuer_validity_status_signature = {array(signature)}",
        f"issuer_validity_status_signature = {array(sign_validity(expiring_until))}",
    )
)
