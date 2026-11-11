// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retained source-contract tests for the imported Noir circuit boundary rules.
//!
//! The linked prove/verify matrix catches generated witness and backend
//! regressions, while this test keeps the source-level boundary assertions from
//! silently drifting before the next retained proof matrix is regenerated.

use std::{
    fs,
    path::{Path, PathBuf},
};

const HASH_STRATEGIES: [&str; 2] = ["sha256", "poseidon2"];
const FAMILIES: [&str; 2] = ["credential_subject_claim_v1", "private_persona_claim_v1"];
const STAGES: [&str; 5] = [
    "session",
    "credential_envelope",
    "credential_root",
    "claim",
    "claim_bundle_4",
];
const EXPECTED_CURRENT_SOURCE_CIRCUITS: usize = 20;

#[test]
fn all_current_source_circuits_keep_boundary_and_tail_contracts() -> Result<(), TestError> {
    let circuits_root = circuits_root()?;
    let mut checked = 0_usize;

    for credential_hash_algorithm in HASH_STRATEGIES {
        for family in FAMILIES {
            for stage in STAGES {
                let circuit_dir = circuits_root
                    .join(credential_hash_algorithm)
                    .join("families")
                    .join(family)
                    .join(stage);
                let main_path = circuit_dir.join("src/main.nr");
                let main = fs::read_to_string(&main_path).map_err(|_| TestError::Io)?;
                assert_common_session_binding_contract(&main, &main_path);
                assert_bounded_hash_source_contract(credential_hash_algorithm, &circuit_dir)?;

                match stage {
                    "claim" => assert_single_claim_contract(&main, &main_path),
                    "claim_bundle_4" => assert_claim_proof_bundle_contract(&main, &main_path),
                    _ => assert_non_claim_stage_has_no_claim_value_boundary(&main, &main_path),
                }
                if is_persona_claim_stage(family, stage) {
                    assert_persona_distinct_key_contract(&main, &main_path);
                }

                checked = checked.checked_add(1).ok_or(TestError::Count)?;
            }
        }
    }

    assert_eq!(checked, EXPECTED_CURRENT_SOURCE_CIRCUITS);
    Ok(())
}

fn circuits_root() -> Result<PathBuf, TestError> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("circuits"))
        .ok_or(TestError::Path)
}

fn assert_common_session_binding_contract(source: &str, path: &Path) {
    for token in [
        "assert(!is_zero32(challenge), \"challenge must be non-zero\")",
        "assert(!is_zero32(audience_hash), \"audience hash must be non-zero\")",
        "assert(!is_zero32(transaction_data_hash), \"transaction data hash must be non-zero\")",
    ] {
        assert_contains(source, token, path);
    }
}

fn assert_single_claim_contract(source: &str, path: &Path) {
    for token in [
        "global MAX_LEAF_COUNT: u32 = 64",
        "assert(val_len > 0u32, \"empty value\")",
        "assert(val_len <= MAX_VAL_LEN, \"value too long\")",
        "assert(path_len == MAX_DEPTH, \"claim tree path must have fixed depth\")",
        "assert(index < MAX_LEAF_COUNT, \"index exceeds path depth\")",
        "if j >= val_len",
        "assert(val_pub[j] == 0u8, \"value tail must be zero-padded\")",
        "for j in 0..MAX_VAL_LEN { if j < val_len",
        "off = off + val_len",
        "let inner_len: u32 = CLM_TAG_LEN + 4u32 + val_len + SALT_LEN",
    ] {
        assert_contains(source, token, path);
    }
}

fn assert_claim_proof_bundle_contract(source: &str, path: &Path) {
    for token in [
        "global MAX_LEAF_COUNT: u32 = 64",
        "assert(bundle_count > 0u32, \"bundle must contain at least one claim\")",
        "assert(bundle_count <= MAX_BUNDLE_CLAIMS, \"bundle_count too large\")",
        "if slot < bundle_count",
        "assert(val_lens[slot] > 0u32, \"empty value in active bundle slot\")",
        "assert(val_lens[slot] <= MAX_VAL_LEN, \"value too long\")",
        "assert(path_lens[slot] == MAX_DEPTH, \"claim tree path must have fixed depth\")",
        "assert(indices[slot] < MAX_LEAF_COUNT, \"index exceeds path depth\")",
        "if j >= val_lens[slot]",
        "assert(val_pubs[slot][j] == 0u8, \"value tail must be zero-padded\")",
        "if j < val_lens[slot]",
        "boff = boff + val_lens[slot]",
        "off = off + val_lens[slot]",
        "let inner_len: u32 = CLM_TAG_LEN + 4u32 + val_lens[slot] + SALT_LEN",
        "assert(val_lens[slot] == 0u32, \"unused bundle slot must have zero val_len\")",
        "assert(path_lens[slot] == 0u32, \"unused bundle slot must have zero path_len\")",
        "assert(indices[slot] == 0u32, \"unused bundle slot must have zero index\")",
        "assert(is_zero32(name_hashes[slot]), \"unused bundle slot must have zero name_hash\")",
        "assert(is_zero_val(val_pubs[slot]), \"unused bundle slot must have zero value bytes\")",
        "assert(is_zero_salt(salts[slot]), \"unused bundle slot must have zero salt\")",
        "unused bundle slot path must be zero",
    ] {
        assert_contains(source, token, path);
    }
}

fn is_persona_claim_stage(family: &str, stage: &str) -> bool {
    matches!(
        (family, stage),
        ("private_persona_claim_v1", "claim" | "claim_bundle_4")
    )
}

fn assert_persona_distinct_key_contract(source: &str, path: &Path) {
    assert!(
        source.contains("persona x must differ from subject x")
            || source.contains("private persona x must differ from credential subject x"),
        "{} is missing reviewed persona-key x-coordinate separation",
        path.display()
    );
}

fn assert_non_claim_stage_has_no_claim_value_boundary(source: &str, path: &Path) {
    for forbidden in ["val_len", "val_lens", "val_pub", "val_pubs", "bundle_count"] {
        assert!(
            !source.contains(forbidden),
            "{} unexpectedly contains claim-value boundary token {forbidden}",
            path.display()
        );
    }
}

fn assert_bounded_hash_source_contract(
    credential_hash_algorithm: &str,
    circuit_dir: &Path,
) -> Result<(), TestError> {
    let helper_name = match credential_hash_algorithm {
        "sha256" => "sha256_bounded.nr",
        "poseidon2" => "poseidon2_bounded.nr",
        _ => return Err(TestError::Path),
    };
    let helper_path = circuit_dir.join("src").join(helper_name);
    let helper = fs::read_to_string(&helper_path).map_err(|_| TestError::Io)?;
    match credential_hash_algorithm {
        "sha256" => assert_sha256_bounded_contract(&helper, &helper_path),
        "poseidon2" => assert_poseidon2_bounded_contract(&helper, &helper_path),
        _ => return Err(TestError::Path),
    }
    Ok(())
}

fn assert_sha256_bounded_contract(source: &str, path: &Path) {
    for token in [
        "assert(len <= MAX_LEN)",
        "let len_plus_9: u32 = len + 9u32",
        "assert(B <= MAX_BLOCKS)",
        "if g < len",
        "by = msg[g]",
        "else if g == len",
        "let bitlen_lo: u32 = len * 8u32",
    ] {
        assert_contains(source, token, path);
    }
}

fn assert_poseidon2_bounded_contract(source: &str, path: &Path) {
    for token in [
        "assert(len <= MAX_LEN)",
        "if i < len",
        "fields[i] = msg[i] as Field",
        "Poseidon2::hash(fields, len)",
    ] {
        assert_contains(source, token, path);
    }
}

fn assert_contains(source: &str, token: &str, path: &Path) {
    assert!(
        source.contains(token),
        "{} is missing reviewed boundary token {token}",
        path.display()
    );
}

#[derive(Debug)]
enum TestError {
    Count,
    Io,
    Path,
}
