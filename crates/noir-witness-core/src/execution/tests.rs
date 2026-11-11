// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use acir::{
    circuit::{
        opcodes::{AcirFunctionId, Opcode},
        Circuit, Program, PublicInputs,
    },
    native_types::{Expression, Witness, WitnessMap, WitnessStack},
};
use acvm::FieldElement;
use noirc_abi::{
    input_parser::Format, Abi, AbiParameter, AbiReturnType, AbiType, AbiVisibility, InputMap,
    ABI_VERSION,
};
use noirc_artifacts::program::ProgramArtifact;
use reallyme_zk_api::circuits::{ZkCircuitFamily, ZkCircuitRef};

use super::{execute_pinned_program, generate_witness, validate_artifact_abi, MAX_ACIR_CALL_DEPTH};
use crate::witness_serialization::serialize_witness_stack;
use crate::{CompiledProgramArtifactJson, WitnessError, WitnessErrorReason};

const ALL_CIRCUITS_V1_ROOT_ENV: &str = "REALLYME_ZK_ALL_CIRCUITS_V1_ROOT";
const EXPECTED_ALL_CIRCUITS_V1_FIXTURE_COUNT: usize = 20;

fn parameter(name: &str, visibility: AbiVisibility) -> AbiParameter {
    AbiParameter {
        name: name.to_owned(),
        typ: AbiType::Integer {
            sign: noirc_abi::Sign::Unsigned,
            width: 32,
        },
        visibility,
    }
}

fn abi(parameters: Vec<AbiParameter>, return_type: Option<AbiReturnType>) -> Abi {
    Abi {
        abi_version: ABI_VERSION,
        parameters,
        return_type,
        error_types: Default::default(),
    }
}

fn empty_returning_circuit(name: &str, return_witness: Witness) -> Circuit<FieldElement> {
    Circuit {
        function_name: name.to_owned(),
        opcodes: Vec::new(),
        private_parameters: BTreeSet::new(),
        public_parameters: PublicInputs::default(),
        return_values: PublicInputs(BTreeSet::from([return_witness])),
        assert_messages: Vec::new(),
    }
}

fn call_opcode(function_index: u32, output_witness: Witness) -> Opcode<FieldElement> {
    Opcode::Call {
        id: AcirFunctionId::new(function_index),
        inputs: vec![Witness::new(0)],
        outputs: vec![output_witness],
        predicate: Expression::from(FieldElement::from(1_u128)),
    }
}

fn calling_circuit(
    name: &str,
    function_index: u32,
    output_witness: Witness,
) -> Circuit<FieldElement> {
    Circuit {
        function_name: name.to_owned(),
        opcodes: vec![call_opcode(function_index, output_witness)],
        private_parameters: BTreeSet::new(),
        public_parameters: PublicInputs::default(),
        return_values: PublicInputs(BTreeSet::from([output_witness])),
        assert_messages: Vec::new(),
    }
}

fn initial_witness(value: u128) -> WitnessMap<FieldElement> {
    let mut initial_witness = WitnessMap::new();
    initial_witness.insert(Witness::new(0), FieldElement::from(value));
    initial_witness
}

fn test_failure() -> WitnessError {
    WitnessError::new(WitnessErrorReason::CircuitExecutionFailed)
}

fn request_bound_prover_files(root: &Path) -> Result<Vec<PathBuf>, WitnessError> {
    // Other circuit families and negative-test workspaces live under the same
    // tree. Only canonical request-bound programs belong to this parity gate.
    let mut files = Vec::new();
    for circuit in ZkCircuitRef::ALL.iter().filter(|circuit| {
        matches!(
            circuit.family,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1
        )
    }) {
        let path = root
            .join(circuit.credential_hash_algorithm.source_dir())
            .join("families")
            .join(circuit.family.source_dir())
            .join(circuit.stage.source_dir())
            .join("Prover.toml");
        if !fs::symlink_metadata(&path)
            .map_err(|_| test_failure())?
            .is_file()
        {
            return Err(test_failure());
        }
        files.push(path);
    }
    if files.len() != EXPECTED_ALL_CIRCUITS_V1_FIXTURE_COUNT {
        return Err(test_failure());
    }
    Ok(files)
}

fn single_file_with_extension(directory: &Path, extension: &str) -> Result<PathBuf, WitnessError> {
    let mut matches = Vec::new();
    let target = directory.join("target");
    for entry in fs::read_dir(target).map_err(|_| test_failure())? {
        let path = entry.map_err(|_| test_failure())?.path();
        if path
            .extension()
            .and_then(|actual| actual.to_str())
            .is_some_and(|actual| actual == extension)
        {
            matches.push(path);
        }
    }
    matches.sort();
    if matches.len() != 1 {
        return Err(test_failure());
    }
    matches.pop().ok_or(test_failure())
}

#[test]
fn artifact_parser_rejects_non_utf8_before_json_parsing() -> Result<(), crate::WitnessError> {
    let bytes = [0xff_u8];
    let artifact = CompiledProgramArtifactJson::try_from_bytes(&bytes)?;
    let error = generate_witness(artifact, &[], InputMap::new())
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::ArtifactUtf8Invalid));
    Ok(())
}

#[test]
fn artifact_parser_rejects_malformed_json() -> Result<(), crate::WitnessError> {
    let artifact = CompiledProgramArtifactJson::try_from_bytes(b"{")?;
    let error = generate_witness(artifact, &[], InputMap::new())
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::ArtifactJsonInvalid));
    Ok(())
}

#[test]
fn exact_abi_is_accepted() -> Result<(), crate::WitnessError> {
    let expected = [parameter("value", AbiVisibility::Public)];
    let actual = abi(expected.to_vec(), None);

    validate_artifact_abi(&actual, &expected)
}

#[test]
fn abi_parameter_name_type_and_visibility_must_match() {
    let expected = [parameter("value", AbiVisibility::Public)];
    let cases = [
        abi(vec![parameter("other", AbiVisibility::Public)], None),
        abi(
            vec![AbiParameter {
                name: "value".to_owned(),
                typ: AbiType::Integer {
                    sign: noirc_abi::Sign::Unsigned,
                    width: 64,
                },
                visibility: AbiVisibility::Public,
            }],
            None,
        ),
        abi(vec![parameter("value", AbiVisibility::Private)], None),
    ];

    for actual in cases {
        let error = validate_artifact_abi(&actual, &expected)
            .err()
            .map(|error| error.reason);
        assert_eq!(error, Some(WitnessErrorReason::ArtifactAbiMismatch));
    }
}

#[test]
fn abi_parameter_count_and_return_type_must_match() {
    let expected = [parameter("value", AbiVisibility::Public)];
    let cases = [
        abi(Vec::new(), None),
        abi(
            expected.to_vec(),
            Some(AbiReturnType {
                abi_type: AbiType::Integer {
                    sign: noirc_abi::Sign::Unsigned,
                    width: 32,
                },
                visibility: AbiVisibility::Public,
            }),
        ),
    ];

    for actual in cases {
        let error = validate_artifact_abi(&actual, &expected)
            .err()
            .map(|error| error.reason);
        assert_eq!(error, Some(WitnessErrorReason::ArtifactAbiMismatch));
    }
}

#[test]
fn direct_acvm_executor_preserves_child_call_witness_stack_order() -> Result<(), crate::WitnessError>
{
    let child = empty_returning_circuit("child", Witness::new(0));
    let main = calling_circuit("main", 1, Witness::new(2));
    let program = Program {
        functions: vec![main, child],
        unconstrained_functions: Vec::new(),
    };

    let mut stack = execute_pinned_program(&program, initial_witness(7))?;

    assert_eq!(stack.length(), 2);
    let main_item = stack.pop().ok_or(crate::WitnessError::new(
        WitnessErrorReason::CircuitExecutionFailed,
    ))?;
    assert_eq!(main_item.index, 0);
    assert_eq!(
        main_item.witness.get_index(2).copied(),
        Some(FieldElement::from(7_u128))
    );
    let child_item = stack.pop().ok_or(crate::WitnessError::new(
        WitnessErrorReason::CircuitExecutionFailed,
    ))?;
    assert_eq!(child_item.index, 1);
    assert_eq!(
        child_item.witness.get_index(0).copied(),
        Some(FieldElement::from(7_u128))
    );

    Ok(())
}

#[test]
fn direct_acvm_executor_allows_repeated_non_recursive_child_calls(
) -> Result<(), crate::WitnessError> {
    let child = empty_returning_circuit("child", Witness::new(0));
    let main = Circuit {
        function_name: "main".to_owned(),
        opcodes: vec![
            call_opcode(1, Witness::new(2)),
            call_opcode(1, Witness::new(3)),
        ],
        private_parameters: BTreeSet::new(),
        public_parameters: PublicInputs::default(),
        return_values: PublicInputs(BTreeSet::from([Witness::new(2), Witness::new(3)])),
        assert_messages: Vec::new(),
    };
    let program = Program {
        functions: vec![main, child],
        unconstrained_functions: Vec::new(),
    };

    let stack = execute_pinned_program(&program, initial_witness(11))?;

    assert_eq!(stack.length(), 3);
    Ok(())
}

#[test]
fn direct_acvm_executor_rejects_recursive_acir_call_cycles() {
    let main = calling_circuit("main", 1, Witness::new(2));
    let child = calling_circuit("child", 1, Witness::new(1));
    let program = Program {
        functions: vec![main, child],
        unconstrained_functions: Vec::new(),
    };

    let error = execute_pinned_program(&program, initial_witness(13))
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::CircuitExecutionFailed));
}

#[test]
fn direct_acvm_executor_rejects_excessive_acir_call_depth() -> Result<(), WitnessError> {
    let function_count = MAX_ACIR_CALL_DEPTH.checked_add(2).ok_or(WitnessError::new(
        WitnessErrorReason::CircuitExecutionFailed,
    ))?;
    let mut functions = Vec::new();
    functions
        .try_reserve_exact(function_count)
        .map_err(|_| WitnessError::new(WitnessErrorReason::CircuitExecutionFailed))?;
    for function_index in 0..function_count {
        let next_index = function_index.checked_add(1).ok_or(WitnessError::new(
            WitnessErrorReason::CircuitExecutionFailed,
        ))?;
        if next_index == function_count {
            functions.push(empty_returning_circuit("leaf", Witness::new(0)));
        } else {
            let next_index = u32::try_from(next_index)
                .map_err(|_| WitnessError::new(WitnessErrorReason::CircuitExecutionFailed))?;
            functions.push(calling_circuit("link", next_index, Witness::new(1)));
        }
    }
    let program = Program {
        functions,
        unconstrained_functions: Vec::new(),
    };

    let error = execute_pinned_program(&program, initial_witness(17))
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::CircuitExecutionFailed));
    Ok(())
}

fn all_circuits_v1_fixture_root_from_value(value: Option<&str>) -> Result<PathBuf, WitnessError> {
    let root = value
        .filter(|root| !root.is_empty())
        .ok_or(WitnessError::new(
            WitnessErrorReason::RequiredFixtureRootMissing,
        ))?;
    Ok(PathBuf::from(root))
}

fn all_circuits_v1_fixture_root_from_env() -> Result<PathBuf, WitnessError> {
    let root = std::env::var(ALL_CIRCUITS_V1_ROOT_ENV)
        .map_err(|_| WitnessError::new(WitnessErrorReason::RequiredFixtureRootMissing))?;
    all_circuits_v1_fixture_root_from_value(Some(&root))
}

#[test]
fn all_circuits_v1_fixture_root_is_required_for_parity_gate() {
    let error = all_circuits_v1_fixture_root_from_value(None)
        .err()
        .map(|error| error.reason);

    assert_eq!(error, Some(WitnessErrorReason::RequiredFixtureRootMissing));
}

#[test]
fn request_bound_parity_selects_only_canonical_production_fixtures() -> Result<(), WitnessError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits");
    let files = request_bound_prover_files(&root)?;
    assert_eq!(files.len(), EXPECTED_ALL_CIRCUITS_V1_FIXTURE_COUNT);
    assert_eq!(files.iter().collect::<BTreeSet<_>>().len(), files.len());
    for path in files {
        let relative = path.strip_prefix(&root).map_err(|_| test_failure())?;
        assert!(!relative.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("common_credential_root_v1" | "persona_credential_evidence_v1" | "target")
            )
        }));
    }
    Ok(())
}

#[test]
fn request_bound_parity_rejects_missing_required_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits/missing-parity-fixture");
    let error = request_bound_prover_files(&root)
        .err()
        .map(|error| error.reason);
    assert_eq!(error, Some(WitnessErrorReason::CircuitExecutionFailed));
}

#[test]
#[ignore = "requires pinned all-circuits v1 fixtures and retained Nargo witness files"]
fn opt_in_all_circuits_v1_fixture_witness_parity() -> Result<(), WitnessError> {
    let root = all_circuits_v1_fixture_root_from_env()?;
    let processed = run_all_circuits_v1_fixture_witness_parity(&root)?;
    assert_eq!(processed, EXPECTED_ALL_CIRCUITS_V1_FIXTURE_COUNT);
    Ok(())
}

fn run_all_circuits_v1_fixture_witness_parity(root: &Path) -> Result<usize, WitnessError> {
    let prover_files = request_bound_prover_files(root)?;
    let processed = prover_files.len();
    for prover_file in &prover_files {
        let circuit_dir = prover_file.parent().ok_or(test_failure())?;
        let artifact_path = single_file_with_extension(circuit_dir, "json")?;
        let retained_witness_path = single_file_with_extension(circuit_dir, "gz")?;

        let artifact_bytes = fs::read(&artifact_path).map_err(|_| test_failure())?;
        let artifact_json = CompiledProgramArtifactJson::try_from_bytes(&artifact_bytes)?;
        let artifact_source =
            std::str::from_utf8(artifact_json.as_bytes()).map_err(|_| test_failure())?;
        let artifact =
            serde_json::from_str::<ProgramArtifact>(artifact_source).map_err(|_| test_failure())?;

        let prover_source = fs::read_to_string(prover_file).map_err(|_| test_failure())?;
        let input_map = Format::Toml
            .parse(&prover_source, &artifact.abi)
            .map_err(|_| test_failure())?;
        let initial_witness = artifact
            .abi
            .encode(&input_map, None)
            .map_err(|_| test_failure())?;
        let produced = execute_pinned_program(&artifact.bytecode, initial_witness)?;

        let retained_bytes = fs::read(retained_witness_path).map_err(|_| test_failure())?;
        let retained = WitnessStack::<FieldElement>::deserialize(&retained_bytes)
            .map_err(|_| test_failure())?;

        // Do not use `assert_eq!` here: its failure output would render the
        // complete witness stacks into CI logs. A parity failure only needs a
        // stable, redacted error classification.
        if produced != retained {
            return Err(test_failure());
        }

        // Exercise the zeroizing serializer on every real circuit witness.
        // Compare decoded values without printing private witness material.
        let serialized = serialize_witness_stack(&produced)?;
        let round_trip = WitnessStack::<FieldElement>::deserialize(serialized.as_bytes())
            .map_err(|_| test_failure())?;
        if round_trip != retained {
            return Err(test_failure());
        }
    }

    Ok(processed)
}
