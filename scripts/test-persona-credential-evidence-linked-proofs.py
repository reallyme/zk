# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Prove and verify all prepared credential and current-status stages.

REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE=1 also checks the linked
backend and mobile FFI. To include the separate local Identity/Wallet
workspace, additionally set REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_IDENTITY=1.
"""

from __future__ import annotations

import os
import shutil
from hashlib import sha256
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
NARGO = os.environ.get("NARGO", "nargo")
BB = os.environ.get("BB", "bb")
CRS = os.environ.get("BB_CRS_DIR")
FIELD_BYTES = 32


@dataclass(frozen=True)
class ProofResult:
    public_fields: list[int]
    artifact_path: Path
    proof_path: Path
    public_inputs_path: Path
    vk_path: Path
    witness_path: Path


def run(
    args: list[str],
    cwd: Path | None = None,
    should_pass: bool = True,
    env: dict[str, str] | None = None,
) -> None:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if (result.returncode == 0) != should_pass:
        raise RuntimeError(f"unexpected command result: {args}: {result.stdout}{result.stderr}")


def run_exact_rust_test(args: list[str], exact_name: str, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or "running 1 test" not in result.stdout or (
        f"test {exact_name} ... ok" not in result.stdout
    ):
        raise RuntimeError(f"exact Rust test did not pass: {exact_name}: {result.stdout}{result.stderr}")


def fields(path: Path, count: int) -> list[int]:
    encoded = path.read_bytes()
    if len(encoded) != count * FIELD_BYTES:
        raise ValueError("compiled public-input field count changed")
    return [
        int.from_bytes(encoded[start : start + FIELD_BYTES], "big")
        for start in range(0, len(encoded), FIELD_BYTES)
    ]


def array(fields_: list[int], start: int, length: int) -> bytes:
    values = fields_[start : start + length]
    if len(values) != length or any(value > 255 for value in values):
        raise ValueError("noncanonical public byte field")
    return bytes(values)


def check_join(claim: list[int], status: list[int]) -> None:
    # Compiler ABI order: issuer, holder, token nonce, interval, binding.
    # The status stage extends this prefix with public status-feed material.
    if claim[:194] != status[:194]:
        raise ValueError("prepared claim and current state have different public joins")
    if claim[160] >= claim[161]:
        raise ValueError("prepared proof window is empty")
    for start, length in ((0, 160), (162, 32)):
        array(claim, start, length)


def check_fixture_abi(claim: list[int], status: list[int], claim_fixture: dict, status_fixture: dict) -> None:
    slot = status_fixture["slot"]
    for field, claim_start, status_start in (
        ("holder_x", 64, 64),
        ("holder_y", 96, 96),
        ("token_nonce", 128, 128),
        ("credential_binding", 162, 162),
    ):
        expected = bytes(claim_fixture[field])
        if expected != array(claim, claim_start, 32) or expected != array(status, status_start, 32):
            raise ValueError(f"compiled prepared ABI differs: {field}")
    for claim_field, status_field, start in (
        ("pk_issuer_x", "issuer_x", 0),
        ("pk_issuer_y", "issuer_y", 32),
    ):
        expected = bytes(claim_fixture[claim_field])
        if expected != array(claim, start, 32) or bytes(slot[status_field]) != array(status, start, 32):
            raise ValueError("compiled prepared issuer ABI differs")
    if claim[160:162] != [claim_fixture["prepared_from"], claim_fixture["prepared_until"]]:
        raise ValueError("compiled prepared interval ABI differs")
    value = bytes(claim_fixture["val_pub"])
    if claim[194] != claim_fixture["val_len"] or array(claim, 195, 64) != value:
        raise ValueError("compiled prepared claim ABI differs")
    if array(claim, 259, 32) != bytes(claim_fixture["name_hash"]):
        raise ValueError("compiled prepared claim name ABI differs")
    for field, start in (("status_root", 194), ("status_list_id", 227), ("status_url_hash", 259)):
        if array(status, start, 32) != bytes(slot[field]):
            raise ValueError(f"compiled prepared status ABI differs: {field}")
    if status[226] != slot["status_length"] or status[291] != slot["status_purpose"]:
        raise ValueError("compiled prepared status scalar ABI differs")


def prove(folder: Path, fixture: str, output: Path, key_root: Path) -> ProofResult:
    package = folder / "Nargo.toml"
    text = package.read_text()
    name = next(
        (line.split("=", 1)[1].strip().strip('"') for line in text.splitlines() if line.startswith("name = ")),
        None,
    )
    if name is None:
        raise ValueError("missing Noir package name")
    # Nargo takes an exclusive cache lock even when a circuit has no Git
    # dependencies. Keep this invocation isolated from the user's installed
    # toolchain and from concurrent CI jobs.
    nargo_home = output.parent / "nargo-home"
    nargo_cache = nargo_home / "cache"
    nargo_cache.mkdir(parents=True, exist_ok=True)
    nargo_env = os.environ.copy()
    nargo_env["HOME"] = str(nargo_home)
    nargo_env["XDG_CACHE_HOME"] = str(nargo_cache)
    run([NARGO, "compile", "--force"], cwd=folder, env=nargo_env)
    run([NARGO, "execute", "--prover-name", fixture], cwd=folder, env=nargo_env)
    artifact = folder / "target" / f"{name}.json"
    witness = folder / "target" / f"{name}.gz"
    retained_witness = output.parent / f"{output.name}.witness.gz"
    shutil.copyfile(witness, retained_witness)
    artifact_hash = sha256(artifact.read_bytes()).hexdigest()
    key_dir = key_root / name / artifact_hash
    if not (key_dir / "vk").is_file():
        key_dir.mkdir(parents=True, exist_ok=True)
        run([BB, "write_vk", "-t", "evm", "-c", CRS, "-b", str(artifact), "-o", str(key_dir)])
    run([BB, "prove", "-t", "evm", "-c", CRS, "-b", str(artifact), "-w", str(witness), "-k", str(key_dir / "vk"), "-o", str(output)])
    key = key_dir / "vk"
    verify = [BB, "verify", "-t", "evm", "-c", CRS, "-k", str(key), "-p", str(output / "proof"), "-i", str(output / "public_inputs")]
    run(verify)
    tampered = output / "proof.tampered"
    changed = bytearray((output / "proof").read_bytes())
    changed[0] ^= 1
    tampered.write_bytes(changed)
    run([BB, "verify", "-t", "evm", "-c", CRS, "-k", str(key), "-p", str(tampered), "-i", str(output / "public_inputs")], should_pass=False)
    tampered_inputs = output / "public_inputs.tampered"
    changed_inputs = bytearray((output / "public_inputs").read_bytes())
    changed_inputs[-1] ^= 1
    tampered_inputs.write_bytes(changed_inputs)
    run([BB, "verify", "-t", "evm", "-c", CRS, "-k", str(key), "-p", str(output / "proof"), "-i", str(tampered_inputs)], should_pass=False)
    count = {
        "issuer_envelope": 194,
        "claim_root": 194,
        "signed_validity": 259,
        "public_claim": 291,
        "private_claim": 291,
        "current_state": 292,
    }.get(folder.name)
    if count is None:
        raise ValueError("unregistered prepared circuit stage")
    return ProofResult(fields(output / "public_inputs", count), artifact, output / "proof", output / "public_inputs", key, retained_witness)


def identity_integration_enabled() -> bool:
    # A standalone checkout must still exercise its native and FFI boundaries.
    # The separate application's tests require an explicitly supplied workspace.
    if os.environ.get("REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_IDENTITY") != "1":
        return False
    if os.environ.get("REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE") != "1":
        raise ValueError("Identity conformance requires native proof verification")
    if not (ROOT.parent / "identity" / "Cargo.toml").is_file():
        raise ValueError("Identity conformance requires the sibling Identity workspace")
    return True


def verify_identity_integrations(env: dict[str, str]) -> None:
    if not identity_integration_enabled():
        return
    # Keep the cross-repository conformance build inside this repo's
    # writable target tree. Cargo otherwise writes into Identity's
    # checkout, which is unnecessary for this read-only integration
    # test and can fail under a restricted release runner.
    identity_env = env.copy()
    identity_env["CARGO_TARGET_DIR"] = os.environ.get(
        "REALLYME_IDENTITY_CARGO_TARGET_DIR", str(ROOT / "target")
    )
    # A consumer's source-only conformance dependencies may require a
    # newer compiler than ZK's public-package MSRV. Keep that choice
    # explicit and scoped to the consumer build.
    identity_toolchain = os.environ.get("REALLYME_IDENTITY_RUST_TOOLCHAIN")
    if identity_toolchain is not None:
        identity_env["RUSTUP_TOOLCHAIN"] = identity_toolchain
    run_exact_rust_test(
        [
            "cargo", "test", "--locked", "--offline",
            "--manifest-path", str(ROOT.parent / "identity" / "Cargo.toml"),
            "-p", "reallyme-identity-openid4vp-prepared-adapter", "--lib",
            "linked_tests::fresh_linked_proofs_cross_openid4vp_prepared_boundary",
            "--", "--ignored", "--exact", "--nocapture",
        ],
        "linked_tests::fresh_linked_proofs_cross_openid4vp_prepared_boundary",
        identity_env,
    )
    print("verified linked public and private prepared proofs through OpenID4VP in both hash lanes")
    # The separate conformance host proves both prepared modes from
    # an SSI-issued, encrypted Wallet record. It also signs and verifies
    # the selected-record presentation and burns the private token.
    run_exact_rust_test(
        [
            "cargo", "test", "--locked", "--offline",
            "--manifest-path", str(ROOT.parent / "identity" / "Cargo.toml"),
            "-p", "reallyme-identity-oidf-openid4vp-wallet-host",
            "--features", "native-zk-platform", "--lib",
            "select_inventory_presentations::mixed_record_tests::prepared_live_source::selected_ssi_vci_record_builds_signed_native_persona_credential_evidence_presentation",
            "--", "--ignored", "--exact", "--nocapture",
        ],
        "select_inventory_presentations::mixed_record_tests::prepared_live_source::selected_ssi_vci_record_builds_signed_native_persona_credential_evidence_presentation",
        identity_env,
    )
    print("proved and verified signed public and once-only private presentations from an SSI-issued Wallet record")


def main() -> None:
    identity_integration_enabled()
    if CRS is None:
        raise ValueError("BB_CRS_DIR must name the pinned CRS")
    with tempfile.TemporaryDirectory(prefix="reallyme-prepared-linked-") as temporary:
        output_root = Path(temporary)
        native_rows: list[str] = []
        for lane in ("sha256", "poseidon2"):
            family = ROOT / "circuits" / lane / "families" / "persona_credential_evidence_v1"
            for mode in ("public", "private"):
                claim_folder = family / f"{mode}_claim"
                status_folder = family / "current_state"
                issuer_folder = family / "issuer_envelope"
                root_folder = family / "claim_root"
                validity_folder = family / "signed_validity"
                joined_name = f"{mode.capitalize()}Joined"
                claim_fixture = tomllib.loads((claim_folder / "Prover.toml").read_text())
                status_fixture = tomllib.loads((status_folder / f"{joined_name}.toml").read_text())
                if claim_fixture["credential_binding"] != status_fixture["slot"]["credential_binding"]:
                    raise ValueError("fixture join differs before proving")
                claim = prove(claim_folder, "Prover", output_root / f"{lane}-{mode}-claim", output_root / "vks")
                issuer = prove(issuer_folder, joined_name, output_root / f"{lane}-{mode}-issuer", output_root / "vks")
                root = prove(root_folder, joined_name, output_root / f"{lane}-{mode}-root", output_root / "vks")
                validity = prove(validity_folder, joined_name, output_root / f"{lane}-{mode}-validity", output_root / "vks")
                status = prove(status_folder, joined_name, output_root / f"{lane}-{mode}-status", output_root / "vks")
                native_rows.extend(
                    "\t".join((lane, mode, stage, str(result.artifact_path), str(result.vk_path), str(result.proof_path), str(result.public_inputs_path), str(result.witness_path)))
                    for stage, result in (("issuer_envelope", issuer), ("claim_root", root), ("signed_validity", validity), (f"{mode}_claim", claim), ("current_state", status))
                )
                check_join(claim.public_fields, status.public_fields)
                for stage in (issuer, root, validity):
                    if stage.public_fields[:194] != claim.public_fields[:194]:
                        raise ValueError("prepared credential evidence has a different token join")
                if validity.public_fields[194:259] != status.public_fields[227:292]:
                    raise ValueError("issuer-signed status pointer differs from current-state proof")
                check_fixture_abi(claim.public_fields, status.public_fields, claim_fixture, status_fixture)
                run([BB, "verify", "-t", "evm", "-c", CRS, "-k", str(status.vk_path), "-p", str(claim.proof_path), "-i", str(claim.public_inputs_path)], should_pass=False)
                # A valid proof for each stage cannot be paired with another
                # prepared token merely because its verification key matches.
                modified = status.public_fields.copy()
                modified[162] ^= 1
                try:
                    check_join(claim.public_fields, modified)
                except ValueError:
                    pass
                else:
                    raise ValueError("mismatched prepared token was accepted")
                print(f"verified linked prepared {mode} proof in {lane}")
        # The final current-state execution in each lane uses PrivateJoined.
        # Compare the typed Rust witness owner with those exact retained Noir
        # stacks before testing the linked native verifier.
        run_exact_rust_test(
            [
                "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-noir-witness-core",
                "--lib", "compiled_prepared_status_witness_matches_noir_in_both_lanes",
                "--", "--ignored",
            ],
            "circuits::persona_credential_evidence_v1_current_state::tests::compiled_prepared_status_witness_matches_noir_in_both_lanes",
        )
        print("verified typed prepared current-state witness parity in both lanes")
        run_exact_rust_test(
            [
                "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-noir-witness-core",
                "--lib", "compiled_issuer_envelope_witness_matches_noir_in_both_lanes",
                "--", "--ignored",
            ],
            "circuits::persona_credential_evidence_v1_issuer_envelope::tests::compiled_issuer_envelope_witness_matches_noir_in_both_lanes",
        )
        print("verified typed prepared issuer-envelope witness parity in both lanes")
        run_exact_rust_test(
            [
                "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-noir-witness-core",
                "--lib", "compiled_claim_root_witness_matches_noir_in_both_lanes",
                "--", "--ignored",
            ],
            "circuits::persona_credential_evidence_v1_claim_root::tests::compiled_claim_root_witness_matches_noir_in_both_lanes",
        )
        print("verified typed prepared claim-root witness parity in both lanes")
        run_exact_rust_test(
            [
                "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-noir-witness-core",
                "--lib", "compiled_signed_validity_witness_matches_noir_in_both_lanes",
                "--", "--ignored",
            ],
            "circuits::persona_credential_evidence_v1_signed_validity::tests::compiled_signed_validity_witness_matches_noir_in_both_lanes",
        )
        print("verified typed prepared signed-validity witness parity in both lanes")
        run_exact_rust_test(
            [
                "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-noir-witness-core",
                "--lib", "compiled_prepared_claim_witness_matches_noir_in_both_lanes",
                "--", "--ignored",
            ],
            "circuits::persona_credential_evidence_v1_claim::tests::compiled_prepared_claim_witness_matches_noir_in_both_lanes",
        )
        print("verified typed prepared claim witness parity in both lanes")
        if os.environ.get("REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE") == "1":
            native_lib_dir = os.environ.get("REALLYME_BARRETENBERG_LIB_DIR")
            if native_lib_dir is None:
                raise ValueError("REALLYME_BARRETENBERG_LIB_DIR is required for linked native verification")
            evidence_path = output_root / "native-evidence.tsv"
            evidence_path.write_text("\n".join(native_rows) + "\n")
            env = os.environ.copy()
            env["REALLYME_PREPARED_LINKED_EVIDENCE"] = str(evidence_path)
            run_exact_rust_test(
                [
                    "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-cli",
                    "--test", "prepared_mobile_witnesses",
                    "demo_prepared_requests_match_current_noir_witnesses",
                    "--", "--ignored", "--exact",
                ],
                "demo_prepared_requests_match_current_noir_witnesses",
                env,
            )
            print("matched all twenty frozen mobile requests to fresh Noir witnesses")
            run_exact_rust_test(
                ["cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-backend-bb", "--features", "native", "--test", "native_linked_persona_credential_evidence", "--", "--ignored", "--nocapture"],
                "fresh_prepared_proofs_verify_through_linked_library",
                env,
            )
            print("proved and verified twenty prepared proofs through linked native Barretenberg")
            verify_identity_integrations(env)
            run_exact_rust_test(
                [
                    "cargo", "test", "--locked", "--offline", "-p", "reallyme-zk-platform-ffi",
                    "--features", "native", "--lib",
                    "dispatch::tests::mobile_package_verifies_prepared_proofs_from_exact_candidate",
                    "--", "--ignored", "--exact", "--nocapture",
                ],
                "dispatch::tests::mobile_package_verifies_prepared_proofs_from_exact_candidate",
                env,
            )
            print("verified prepared proofs and tamper negatives through the mobile protobuf FFI")


if __name__ == "__main__":
    main()
