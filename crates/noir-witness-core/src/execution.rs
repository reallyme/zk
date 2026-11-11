// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use acir::{
    circuit::{Circuit, Program},
    native_types::{WitnessMap, WitnessStack},
};
use acvm::pwg::{ACVMStatus, ACVM};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use noirc_abi::{input_parser::Format, Abi, AbiParameter, InputMap};
use noirc_artifacts::program::ProgramArtifact;

use crate::domain::{CompiledProgramArtifactJson, SerializedWitnessStack};
use crate::error::{WitnessError, WitnessErrorReason};
use crate::input_cleanup::{wipe_abi_error, wipe_parser_error, InputMapOwner};
use crate::witness_serialization::serialize_witness_stack;

const MAX_ACIR_CALL_DEPTH: usize = 32;

pub(crate) fn generate_witness(
    artifact_json: CompiledProgramArtifactJson<'_>,
    expected_parameters: &[AbiParameter],
    input_map: InputMap,
) -> Result<SerializedWitnessStack, WitnessError> {
    let input_map = InputMapOwner::new(input_map);
    let artifact = parse_program_artifact(artifact_json)?;
    validate_artifact_abi(&artifact.abi, expected_parameters)?;
    let initial_witness = artifact
        .abi
        .encode(input_map.as_map(), None)
        .map_err(|mut error| {
            wipe_abi_error(&mut error);
            WitnessError::new(WitnessErrorReason::AbiEncodingFailed)
        })?;
    drop(input_map);

    let witness_stack = execute_pinned_program(&artifact.bytecode, initial_witness)?;

    serialize_witness_stack(&witness_stack)
}

pub fn generate_witness_from_artifact_json_and_toml(
    artifact_json: CompiledProgramArtifactJson<'_>,
    prover_toml: &str,
) -> Result<SerializedWitnessStack, WitnessError> {
    let artifact = parse_program_artifact(artifact_json)?;
    let input_map = Format::Toml
        .parse(prover_toml, &artifact.abi)
        .map_err(|mut error| {
            wipe_parser_error(&mut error);
            WitnessError::new(WitnessErrorReason::AbiEncodingFailed)
        })?;
    let input_map = InputMapOwner::new(input_map);
    let initial_witness = artifact
        .abi
        .encode(input_map.as_map(), None)
        .map_err(|mut error| {
            wipe_abi_error(&mut error);
            WitnessError::new(WitnessErrorReason::AbiEncodingFailed)
        })?;
    drop(input_map);

    let witness_stack = execute_pinned_program(&artifact.bytecode, initial_witness)?;

    serialize_witness_stack(&witness_stack)
}

pub(crate) fn execute_pinned_program(
    program: &Program<acvm::FieldElement>,
    initial_witness: WitnessMap<acvm::FieldElement>,
) -> Result<WitnessStack<acvm::FieldElement>, WitnessError> {
    let blackbox_solver = Bn254BlackBoxSolver;
    let executor = ProgramExecutor::new(program, &blackbox_solver);
    executor.execute(initial_witness)
}

struct ProgramExecutor<'a> {
    program: &'a Program<acvm::FieldElement>,
    blackbox_solver: &'a Bn254BlackBoxSolver,
    witness_stack: WitnessStack<acvm::FieldElement>,
}

impl<'a> ProgramExecutor<'a> {
    const MAIN_FUNCTION_INDEX: usize = 0;

    fn new(
        program: &'a Program<acvm::FieldElement>,
        blackbox_solver: &'a Bn254BlackBoxSolver,
    ) -> Self {
        Self {
            program,
            blackbox_solver,
            witness_stack: WitnessStack::default(),
        }
    }

    fn execute(
        mut self,
        initial_witness: WitnessMap<acvm::FieldElement>,
    ) -> Result<WitnessStack<acvm::FieldElement>, WitnessError> {
        let mut active_functions = Vec::new();
        let main_witness = self.execute_circuit(
            Self::MAIN_FUNCTION_INDEX,
            initial_witness,
            &mut active_functions,
        )?;
        self.witness_stack.push(0, main_witness);
        Ok(self.witness_stack)
    }

    fn execute_circuit(
        &mut self,
        function_index: usize,
        initial_witness: WitnessMap<acvm::FieldElement>,
        active_functions: &mut Vec<usize>,
    ) -> Result<WitnessMap<acvm::FieldElement>, WitnessError> {
        if active_functions.len() >= MAX_ACIR_CALL_DEPTH
            || active_functions.contains(&function_index)
        {
            return Err(WitnessError::new(
                WitnessErrorReason::CircuitExecutionFailed,
            ));
        }
        let circuit = self
            .program
            .functions
            .get(function_index)
            .ok_or(WitnessError::new(
                WitnessErrorReason::CircuitExecutionFailed,
            ))?;
        active_functions.push(function_index);
        let mut acvm = ACVM::new(
            self.blackbox_solver,
            &circuit.opcodes,
            initial_witness,
            &self.program.unconstrained_functions,
            &circuit.assert_messages,
        );

        loop {
            match acvm.solve() {
                ACVMStatus::Solved => {
                    active_functions.pop();
                    return Ok(acvm.finalize());
                }
                ACVMStatus::InProgress | ACVMStatus::Failure(_) => {
                    active_functions.pop();
                    return Err(WitnessError::new(
                        WitnessErrorReason::CircuitExecutionFailed,
                    ));
                }
                ACVMStatus::RequiresForeignCall(_) => {
                    active_functions.pop();
                    return Err(WitnessError::new(
                        WitnessErrorReason::ForeignCallResolutionFailed,
                    ));
                }
                ACVMStatus::RequiresAcirCall(call_info) => {
                    let child_index = call_info.id.as_usize();
                    if self.program.functions.get(child_index).is_none() {
                        active_functions.pop();
                        return Err(WitnessError::new(
                            WitnessErrorReason::CircuitExecutionFailed,
                        ));
                    }
                    let child_witness = match self.execute_circuit(
                        child_index,
                        call_info.initial_witness,
                        active_functions,
                    ) {
                        Ok(witness) => witness,
                        Err(error) => {
                            active_functions.pop();
                            return Err(error);
                        }
                    };
                    let child_circuit =
                        self.program
                            .functions
                            .get(child_index)
                            .ok_or(WitnessError::new(
                                WitnessErrorReason::CircuitExecutionFailed,
                            ))?;
                    let child_outputs =
                        match return_values_for_child_call(child_circuit, &child_witness) {
                            Ok(outputs) => outputs,
                            Err(error) => {
                                active_functions.pop();
                                return Err(error);
                            }
                        };
                    acvm.resolve_pending_acir_call(child_outputs);
                    self.witness_stack
                        .push(call_info.id.as_u32(), child_witness);
                }
            }
        }
    }
}

fn return_values_for_child_call(
    child_circuit: &Circuit<acvm::FieldElement>,
    child_witness: &WitnessMap<acvm::FieldElement>,
) -> Result<Vec<acvm::FieldElement>, WitnessError> {
    let mut output_values = Vec::new();
    output_values
        .try_reserve_exact(child_circuit.return_values.indices().len())
        .map_err(|_| WitnessError::new(WitnessErrorReason::CircuitExecutionFailed))?;
    for return_witness_index in child_circuit.return_values.indices() {
        let return_value =
            child_witness
                .get_index(return_witness_index)
                .ok_or(WitnessError::new(
                    WitnessErrorReason::CircuitExecutionFailed,
                ))?;
        output_values.push(*return_value);
    }
    Ok(output_values)
}

fn parse_program_artifact(
    artifact_json: CompiledProgramArtifactJson<'_>,
) -> Result<ProgramArtifact, WitnessError> {
    let artifact_string = std::str::from_utf8(artifact_json.as_bytes())
        .map_err(|_| WitnessError::new(WitnessErrorReason::ArtifactUtf8Invalid))?;

    serde_json::from_str::<ProgramArtifact>(artifact_string)
        .map_err(|_| WitnessError::new(WitnessErrorReason::ArtifactJsonInvalid))
}

pub(crate) fn validate_artifact_abi(
    artifact_abi: &Abi,
    expected_parameters: &[AbiParameter],
) -> Result<(), WitnessError> {
    if artifact_abi.parameters.len() != expected_parameters.len() {
        return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
    }

    for (actual, expected) in artifact_abi
        .parameters
        .iter()
        .zip(expected_parameters.iter())
    {
        if actual.name != expected.name
            || actual.visibility != expected.visibility
            || actual.typ != expected.typ
        {
            return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
        }
    }

    if artifact_abi.return_type.is_some() {
        return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
