// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider-independent execution of canonical ZK verification vectors.

mod error;
mod runner;

pub use error::{ConformanceError, ConformanceErrorReason};
pub use runner::{run_claim_proof_bundle_verification_vectors, VerificationConformanceSummary};
