// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn main(inp: Field) -> pub Field {
    let x = inp as u128;
    let mut out: Field = 0;

    if x == 0 {
        out = 1;
    } else {
        out = 2;
    }

    out
}
