// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ReallyMe ZK typed platform ABI adapter.
//!
//! The platform entry points accept only canonical `reallyme.zk.v1`
//! provider-operation protobuf bytes and dispatch them through the Rust domain
//! boundary. Raw Barretenberg BBAPI MessagePack remains an internal backend
//! transport and is not exposed to Swift, Kotlin, Java, or app code.
//!
//! The exported functions contain unwind guards for profiles that permit Rust
//! unwinding. Shipped mobile artifacts use the reviewed `mobile-release`
//! profile so unexpected Rust panics can be contained as typed ABI status
//! values. Workspace `release` builds still use fail-stop `panic = "abort"`.

#[cfg(feature = "native")]
mod context;
#[cfg(feature = "native")]
mod dispatch;
#[allow(unsafe_code)]
mod ffi;
#[cfg(feature = "native")]
mod handle;
#[cfg(feature = "native")]
#[allow(unsafe_code)]
mod input;
#[cfg(feature = "native")]
mod retained_witness;
#[cfg(feature = "native")]
mod witness;

pub use ffi::{
    reallyme_zk_platform_context_create, reallyme_zk_platform_context_create_with_crs_files,
    reallyme_zk_platform_context_destroy, reallyme_zk_platform_dispatch, ReallyMeZkPlatformContext,
    ReallyMeZkPlatformContextResult, REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER,
    REALLYME_ZK_PLATFORM_CRS_MODE_VERIFIER_ONLY,
};
