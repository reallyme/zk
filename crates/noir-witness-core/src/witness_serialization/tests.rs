// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{ErrorKind, Write};

use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acvm::FieldElement;
use zeroize::Zeroizing;

use super::{serialize_witness_stack, CapacityWriter, CountingWriter};
use crate::{WitnessError, WitnessErrorReason};

#[test]
fn serialized_bytes_match_pinned_noir_for_empty_and_nested_stacks() -> Result<(), WitnessError> {
    let empty = WitnessStack::<FieldElement>::default();
    assert_matches_pinned_noir(&empty)?;

    let mut stack = WitnessStack::default();
    let mut child = WitnessMap::new();
    child.insert(Witness::new(0), FieldElement::from(7_u128));
    child.insert(Witness::new(5), FieldElement::from(u128::MAX));
    stack.push(1, child);
    let mut main = WitnessMap::new();
    main.insert(Witness::new(0), FieldElement::from(42_u128));
    main.insert(Witness::new(2), -FieldElement::from(3_u128));
    stack.push(0, main);
    assert_matches_pinned_noir(&stack)
}

fn assert_matches_pinned_noir(stack: &WitnessStack<FieldElement>) -> Result<(), WitnessError> {
    let expected = Zeroizing::new(
        stack
            .serialize_with_format(acir::SerializationFormat::MsgpackCompact)
            .map_err(|_| WitnessError::new(WitnessErrorReason::WitnessSerializationFailed))?,
    );
    let actual = serialize_witness_stack(stack)?;
    // A mismatch must not render the complete witness into test logs.
    if actual.as_bytes() != expected.as_slice() {
        return Err(WitnessError::new(
            WitnessErrorReason::WitnessSerializationFailed,
        ));
    }
    Ok(())
}

#[test]
fn capacity_writer_rejects_growth_before_changing_secret_buffer() {
    let mut owned = Zeroizing::new(Vec::with_capacity(2));
    let mut writer = CapacityWriter {
        bytes: &mut owned,
        limit: 2,
    };
    assert!(writer.write_all(&[0xa1, 0xb2]).is_ok());
    let error = writer.write_all(&[0xc3]);
    assert!(error.is_err_and(|value| value.kind() == ErrorKind::WriteZero));
    assert!(owned.as_slice() == [0xa1, 0xb2]);
}

#[test]
fn counting_writer_rejects_length_overflow() {
    let mut writer = CountingWriter { len: usize::MAX };
    let error = writer.write_all(&[0xa1]);
    assert!(error.is_err_and(|value| value.kind() == ErrorKind::InvalidData));
}
