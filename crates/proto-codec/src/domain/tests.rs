// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{circuit_id_from_proto, pb, EnumValue, ZkErrorReason};

#[test]
fn unknown_circuit_number_fails_closed() {
    let unknown: EnumValue<pb::ZkCircuitId> = EnumValue::from(99);
    assert_eq!(
        circuit_id_from_proto(unknown)
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::UnknownCircuit)
    );
}
