// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use noirc_abi::{
    errors::{AbiError, InputParserError},
    input_parser::{InputTypecheckingError, InputValue},
    AbiType, InputMap,
};

use super::{wipe_abi_error, wipe_input_map, wipe_input_value, wipe_parser_error, InputMapOwner};

#[test]
fn wipes_scalar_and_nested_abi_values() {
    let mut field = InputValue::Field(acvm::FieldElement::from(27_u128));
    wipe_input_value(&mut field);
    assert_eq!(field, InputValue::Field(acvm::FieldElement::from(0_u128)));

    let mut text = InputValue::String(String::from("credential subject claim"));
    wipe_input_value(&mut text);
    assert_eq!(text, InputValue::String(String::new()));

    let mut nested = InputValue::Struct(BTreeMap::from([(
        String::from("claim"),
        InputValue::Vec(vec![
            InputValue::Field(acvm::FieldElement::from(42_u128)),
            InputValue::String(String::from("private value")),
        ]),
    )]));
    wipe_input_value(&mut nested);
    assert_eq!(nested, InputValue::Struct(BTreeMap::new()));
}

#[test]
fn clears_owned_map_after_recursive_cleanup() {
    let mut input_map = InputMap::from([(
        String::from("subject"),
        InputValue::Struct(BTreeMap::from([(
            String::from("key"),
            InputValue::String(String::from("holder secret")),
        )])),
    )]);
    wipe_input_map(&mut input_map);
    assert!(input_map.is_empty());

    let owner = InputMapOwner::new(InputMap::new());
    assert!(owner.as_map().is_empty());
}

#[test]
fn wipes_rejected_abi_value_and_parser_error_context() {
    let mut abi_error = AbiError::TypeMismatch(InputTypecheckingError::IncompatibleTypes {
        path: String::from("holder.secret"),
        typ: AbiType::Field,
        value: InputValue::String(String::from("private value")),
    });
    wipe_abi_error(&mut abi_error);
    assert!(matches!(
        abi_error,
        AbiError::TypeMismatch(InputTypecheckingError::IncompatibleTypes { path, value, .. })
            if path.is_empty() && value == InputValue::String(String::new())
    ));

    let mut parser_error = InputParserError::ParseStr {
        arg_name: String::from("claim"),
        value: String::from("private value"),
        error: String::from("details"),
    };
    wipe_parser_error(&mut parser_error);
    assert!(matches!(
        parser_error,
        InputParserError::ParseStr { arg_name, value, error }
            if arg_name.is_empty() && value.is_empty() && error.is_empty()
    ));
}
