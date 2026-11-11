// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed, non-sensitive failures shared by ZK operations and transport adapters.

pub use crate::error::{
    ZkArtifactErrorReason, ZkBackendErrorReason, ZkBindingErrorReason, ZkCircuitErrorReason,
    ZkClaimProofBundleErrorReason, ZkError, ZkErrorKind, ZkInputErrorReason, ZkProofErrorReason,
    ZkTransportErrorReason,
};
pub use crate::error_reason::ZkErrorReason;
