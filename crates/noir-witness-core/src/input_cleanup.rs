// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Best-effort cleanup for the input map passed to Noir's ABI encoder.

use core::sync::atomic::{compiler_fence, Ordering};
use noirc_abi::{
    errors::{AbiError, InputParserError},
    input_parser::{InputTypecheckingError, InputValue},
    InputMap,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Owns the caller's parsed ABI values until encoding completes or fails.
/// Noir can clone these values internally; this owner cannot wipe those copies.
pub(crate) struct InputMapOwner(InputMap);

impl InputMapOwner {
    pub(crate) fn new(input_map: InputMap) -> Self {
        Self(input_map)
    }

    pub(crate) fn as_map(&self) -> &InputMap {
        &self.0
    }
}

impl Drop for InputMapOwner {
    fn drop(&mut self) {
        wipe_input_map(&mut self.0);
    }
}

impl ZeroizeOnDrop for InputMapOwner {}

fn wipe_input_map(input_map: &mut InputMap) {
    // Wipe values where they are stored first. Removing an entry moves its
    // value out of the map node, which would otherwise leave an unwiped copy
    // of every inline field element in the node being freed.
    for value in input_map.values_mut() {
        wipe_input_value(value);
    }
    // Removing entries lets us wipe owned map keys as well as their values.
    while let Some((mut name, mut value)) = input_map.pop_first() {
        name.zeroize();
        wipe_input_value(&mut value);
    }
}

fn wipe_input_value(value: &mut InputValue) {
    match value {
        InputValue::Field(field) => wipe_field(field),
        InputValue::String(text) => text.zeroize(),
        InputValue::Vec(values) => {
            for entry in values.iter_mut() {
                wipe_input_value(entry);
            }
            values.clear();
        }
        InputValue::Struct(fields) => wipe_input_map(fields),
    }
}

/// Overwrites one field element in place.
///
/// The upstream field type does not implement `Zeroize`, and this crate
/// denies `unsafe`, so a volatile write is not available. The store is kept
/// observable to the optimizer and followed by a compiler fence so that it is
/// not removed as a dead store before the owning allocation is released.
fn wipe_field(field: &mut acvm::FieldElement) {
    *field = acvm::FieldElement::from(0_u128);
    let _observed = core::hint::black_box(&*field);
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn wipe_abi_error(error: &mut AbiError) {
    match error {
        AbiError::UnexpectedParams(names) => wipe_names(names),
        AbiError::TypeMismatch(inner) => wipe_type_error(inner),
        AbiError::MissingParam(name)
        | AbiError::MissingParamWitnessValue { name, .. }
        | AbiError::StringValueOutsideByteRange { name, .. } => name.zeroize(),
        AbiError::ReturnTypeMismatch { value, .. } | AbiError::UnexpectedReturnValue(value) => {
            wipe_input_value(value);
        }
    }
    if let AbiError::StringValueOutsideByteRange { value, .. } = error {
        wipe_field(value);
    }
}

fn wipe_type_error(error: &mut InputTypecheckingError) {
    match error {
        InputTypecheckingError::OutsideOfValidRange { path, value, .. }
        | InputTypecheckingError::LengthMismatch { path, value, .. }
        | InputTypecheckingError::IncompatibleTypes { path, value, .. } => {
            path.zeroize();
            wipe_input_value(value);
        }
        InputTypecheckingError::MissingField {
            path,
            expected_field,
            found_fields,
        } => {
            path.zeroize();
            expected_field.zeroize();
            wipe_names(found_fields);
        }
        InputTypecheckingError::UnexpectedField {
            path, extra_field, ..
        } => {
            path.zeroize();
            extra_field.zeroize();
        }
    }
}

pub(crate) fn wipe_parser_error(error: &mut InputParserError) {
    match error {
        InputParserError::ParseInputMap(value) | InputParserError::MissingArgument(value) => {
            value.zeroize()
        }
        InputParserError::ParseStr {
            arg_name,
            value,
            error,
        } => {
            arg_name.zeroize();
            value.zeroize();
            error.zeroize();
        }
        InputParserError::InputUnderflowsMinimum {
            arg_name,
            value,
            min,
        } => {
            arg_name.zeroize();
            value.zeroize();
            min.zeroize();
        }
        InputParserError::InputOverflowsMaximum {
            arg_name,
            value,
            max,
        } => {
            arg_name.zeroize();
            value.zeroize();
            max.zeroize();
        }
        InputParserError::InputExceedsFieldModulus { arg_name, value } => {
            arg_name.zeroize();
            value.zeroize();
        }
        InputParserError::AbiTypeMismatch(value, _) => value.zeroize(),
    }
}

fn wipe_names(names: &mut Vec<String>) {
    for name in names.iter_mut() {
        name.zeroize();
    }
    names.clear();
}

#[cfg(test)]
#[path = "input_cleanup/tests.rs"]
mod tests;
