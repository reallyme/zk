// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const check = (body) => {
  const result = spawnSync("python3", ["-c", `
import ast
import contextlib
import io
import os
from pathlib import Path
import runpy
import tempfile
from unittest.mock import patch

script = "scripts/test-persona-credential-evidence-linked-proofs.py"
module = runpy.run_path(script, run_name="linked_proof_checks")
scope = module["verify_identity_integrations"].__globals__
calls = []
scope["run_exact_rust_test"] = lambda args, name, env: calls.append((args, name, env))
with tempfile.TemporaryDirectory() as temporary:
    scope["ROOT"] = Path(temporary) / "zk"
${body}
`], { encoding: "utf8", timeout: 10_000, maxBuffer: 65_536 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
};

test("native proof checks do not require an unrelated Identity checkout", () => check(`
    with patch.dict(os.environ, {"REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE": "1"}, clear=True):
        scope["verify_identity_integrations"]({})
        assert calls == []
`));

test("explicit Identity conformance requires native verification", () => check(`
    with patch.dict(os.environ, {"REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_IDENTITY": "1"}, clear=True):
        try:
            scope["identity_integration_enabled"]()
        except ValueError:
            pass
        else:
            raise AssertionError("Identity mode accepted without native verification")
`));

test("explicit Identity conformance fails if its workspace is missing", () => check(`
    with patch.dict(os.environ, {
        "REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE": "1",
        "REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_IDENTITY": "1",
    }, clear=True):
        try:
            scope["identity_integration_enabled"]()
        except ValueError:
            pass
        else:
            raise AssertionError("missing Identity workspace was silently skipped")
`));

test("explicit local conformance retains both exact offline consumer tests", () => check(`
    identity = Path(temporary) / "identity"
    identity.mkdir()
    (identity / "Cargo.toml").write_text("")
    evidence = {"REALLYME_PREPARED_LINKED_EVIDENCE": "evidence.tsv"}
    with patch.dict(os.environ, {
        "REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE": "1",
        "REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_IDENTITY": "1",
        "REALLYME_IDENTITY_RUST_TOOLCHAIN": "1.99.0",
    }, clear=True), contextlib.redirect_stdout(io.StringIO()):
        scope["verify_identity_integrations"](evidence)
    assert len(calls) == 2
    assert calls[0][1] == "linked_tests::fresh_linked_proofs_cross_openid4vp_prepared_boundary"
    assert calls[1][1].endswith("selected_ssi_vci_record_builds_signed_native_persona_credential_evidence_presentation")
    for args, name, env in calls:
        assert "--locked" in args and "--offline" in args and "--exact" in args
        assert args[args.index("--manifest-path") + 1] == str(identity / "Cargo.toml")
        assert env["CARGO_TARGET_DIR"] == str(scope["ROOT"] / "target")
        assert env["RUSTUP_TOOLCHAIN"] == "1.99.0"
        assert env["REALLYME_PREPARED_LINKED_EVIDENCE"] == "evidence.tsv"
    assert evidence == {"REALLYME_PREPARED_LINKED_EVIDENCE": "evidence.tsv"}
`));

test("standalone native mode retains linked backend and mobile FFI proof checks", () => check(`
    tree = ast.parse(Path(script).read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    native = next(node for node in ast.walk(main) if isinstance(node, ast.If)
        and "REALLYME_VERIFY_PERSONA_CREDENTIAL_EVIDENCE_NATIVE" in ast.unparse(node.test))
    direct_calls = [node.value for node in native.body if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)]
    tests = [call.args[1].value for call in direct_calls if call.func.id == "run_exact_rust_test"]
    assert tests == [
        "demo_prepared_requests_match_current_noir_witnesses",
        "fresh_prepared_proofs_verify_through_linked_library",
        "dispatch::tests::mobile_package_verifies_prepared_proofs_from_exact_candidate",
    ]
    assert any(call.func.id == "verify_identity_integrations" for call in direct_calls)
`));
