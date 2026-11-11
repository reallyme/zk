// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use acir::FieldElement;
use noirc_abi::{input_parser::InputValue, AbiType, Sign};
use std::collections::BTreeMap;

const BYTE_WIDTH_BITS: u32 = 8;

pub(crate) fn input_value_for_byte_array<const LENGTH: usize>(value: &[u8; LENGTH]) -> InputValue {
    InputValue::Vec(value.iter().copied().map(input_value_for_byte).collect())
}

pub(crate) fn input_value_for_byte_array_matrix<const OUTER: usize, const INNER: usize>(
    value: &[[u8; INNER]; OUTER],
) -> InputValue {
    InputValue::Vec(value.iter().map(input_value_for_byte_array).collect())
}

pub(crate) fn input_value_for_byte_array_tensor<
    const OUTER: usize,
    const MIDDLE: usize,
    const INNER: usize,
>(
    value: &[[[u8; INNER]; MIDDLE]; OUTER],
) -> InputValue {
    InputValue::Vec(
        value
            .iter()
            .map(input_value_for_byte_array_matrix)
            .collect(),
    )
}

pub(crate) fn input_value_for_u32_array<const LENGTH: usize>(value: [u32; LENGTH]) -> InputValue {
    InputValue::Vec(value.into_iter().map(input_value_for_u32).collect())
}

pub(crate) fn input_value_for_u32(value: u32) -> InputValue {
    InputValue::Field(FieldElement::from(value))
}

pub(crate) fn input_value_for_u64(value: u64) -> InputValue {
    InputValue::Field(FieldElement::from(value))
}

pub(crate) fn input_value_for_struct(fields: BTreeMap<String, InputValue>) -> InputValue {
    InputValue::Struct(fields)
}

pub(crate) fn byte_array_type(length: u32) -> AbiType {
    AbiType::Array {
        length,
        typ: Box::new(unsigned_integer_type(BYTE_WIDTH_BITS)),
    }
}

pub(crate) fn byte_array_matrix_type(outer_length: u32, inner_length: u32) -> AbiType {
    AbiType::Array {
        length: outer_length,
        typ: Box::new(byte_array_type(inner_length)),
    }
}

pub(crate) fn byte_array_tensor_type(
    outer_length: u32,
    middle_length: u32,
    inner_length: u32,
) -> AbiType {
    AbiType::Array {
        length: outer_length,
        typ: Box::new(byte_array_matrix_type(middle_length, inner_length)),
    }
}

pub(crate) fn unsigned_integer_array_type(length: u32, width: u32) -> AbiType {
    AbiType::Array {
        length,
        typ: Box::new(unsigned_integer_type(width)),
    }
}

pub(crate) fn unsigned_integer_type(width: u32) -> AbiType {
    AbiType::Integer {
        sign: Sign::Unsigned,
        width,
    }
}

pub(crate) fn struct_type(path: &'static str, fields: Vec<(&'static str, AbiType)>) -> AbiType {
    AbiType::Struct {
        path: String::from(path),
        fields: fields
            .into_iter()
            .map(|(name, typ)| (String::from(name), typ))
            .collect(),
    }
}

fn input_value_for_byte(value: u8) -> InputValue {
    InputValue::Field(FieldElement::from(u128::from(value)))
}
