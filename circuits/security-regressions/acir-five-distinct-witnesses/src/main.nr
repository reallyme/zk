// SPDX-FileCopyrightText: Copyright (c) 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn main(a: Field, b: Field, c: Field, d: Field, e: Field) {
    assert(a * b + c + d + e == 9, "five distinct witnesses must constrain");
}
