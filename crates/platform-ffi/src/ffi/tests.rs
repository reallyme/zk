// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

use reallyme_zk_api::errors::ZkErrorReason;
use reallyme_zk_proto_codec::platform_abi::{
    REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY, REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE,
};

use super::dispatch_failure_status;

#[test]
fn top_level_busy_is_distinct_from_encoding_failure() {
    assert_eq!(
        dispatch_failure_status(ZkErrorReason::BackendUnavailable),
        REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY
    );
    assert_eq!(
        dispatch_failure_status(ZkErrorReason::ResourceExhausted),
        REALLYME_ZK_PLATFORM_STATUS_ENCODE_FAILURE
    );
}
