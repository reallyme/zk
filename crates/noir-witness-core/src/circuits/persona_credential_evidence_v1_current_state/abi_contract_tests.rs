// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use noirc_abi::{Abi, AbiType};

use super::expected_abi_parameters;
use crate::execution::validate_artifact_abi;
use crate::{WitnessError, WitnessErrorReason};

// These descriptors come from the reviewed Noir 1.0.0 artifacts rather than
// the adapter, so a Rust-only rename cannot silently redefine the circuit ABI.
const COMPILED_ABIS: [&str; 2] = [
    include_str!("../../../tests/fixtures/persona-evidence-current-state-sha256.abi.json"),
    include_str!("../../../tests/fixtures/persona-evidence-current-state-poseidon2.abi.json"),
];

fn compiled_abi(source: &str) -> Result<Abi, WitnessError> {
    serde_json::from_str(source)
        .map_err(|_| WitnessError::new(WitnessErrorReason::ArtifactJsonInvalid))
}

#[test]
fn reviewed_current_state_abis_match_the_typed_witness_adapter() -> Result<(), WitnessError> {
    for source in COMPILED_ABIS {
        validate_artifact_abi(&compiled_abi(source)?, &expected_abi_parameters())?;
    }
    Ok(())
}

#[test]
fn renamed_current_state_abi_structs_are_rejected() -> Result<(), WitnessError> {
    for source in COMPILED_ABIS {
        for index in [0, 1] {
            let mut abi = compiled_abi(source)?;
            let parameter = abi
                .parameters
                .get_mut(index)
                .ok_or(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch))?;
            let AbiType::Struct { path, .. } = &mut parameter.typ else {
                return Err(WitnessError::new(WitnessErrorReason::ArtifactAbiMismatch));
            };
            path.push_str("Unexpected");
            assert_eq!(
                validate_artifact_abi(&abi, &expected_abi_parameters())
                    .err()
                    .map(|error| error.reason),
                Some(WitnessErrorReason::ArtifactAbiMismatch),
            );
        }
    }
    Ok(())
}
