// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// SAFETY: these declarations bind the process-linked ReallyMe BBAPI shim.
// Safe Rust reaches them only through `ShimBbapiTransport`, which supplies
// live input buffers, owned output slots, and paired deallocation.
unsafe extern "C" {
    pub(super) fn reallyme_bbapi_call(
        input: *const u8,
        input_len: usize,
        output: *mut *mut u8,
        output_len: *mut usize,
    ) -> u32;

    pub(super) fn reallyme_bbapi_free(ptr: *mut u8, len: usize);
}
