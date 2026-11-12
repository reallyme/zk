// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(not(feature = "native"))]

use std::ptr;

use reallyme_zk_api::errors::ZkErrorReason;
use reallyme_zk_proto_codec::platform_abi::REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT;

use super::{reallyme_zk_platform_context_create, reallyme_zk_platform_dispatch};

#[test]
fn disabled_native_provider_fails_closed_without_reading_inputs() {
    for length in [0, 1, usize::MAX] {
        // SAFETY: Non-native stubs explicitly never dereference their arguments.
        // Null pointers and oversized lengths prove no owner or allocation is
        // created when the implementation feature is unavailable.
        let context = unsafe {
            reallyme_zk_platform_context_create(
                ptr::null(),
                length,
                ptr::null(),
                length,
                ptr::null(),
                length,
                ptr::null(),
                length,
                ptr::null(),
                length,
                u32::MAX,
            )
        };
        assert!(context.context.is_null());
        assert_eq!(
            context.status_code,
            REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
        );
        assert_eq!(
            context.error_reason_code,
            ZkErrorReason::BackendUnavailable.reason_code()
        );
        // SAFETY: The disabled implementation does not read context or request
        // pointers and never takes ownership of the null values supplied here.
        let result = unsafe { reallyme_zk_platform_dispatch(ptr::null_mut(), ptr::null(), length) };
        assert_eq!(
            result.status_code,
            REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT
        );
        assert_eq!(
            result.error_reason_code,
            ZkErrorReason::BackendUnavailable.reason_code()
        );
    }
}
