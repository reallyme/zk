// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{Mutex, MutexGuard, OnceLock};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::Digest32;

use crate::bbapi_abi::{
    FULL_PROVER_CRS_G1_PREFIX_BYTES, VERIFIER_CRS_G1_PREFIX_BYTES, VERIFIER_CRS_G2_BYTES,
};

const PINNED_VERIFIER_G1_PREFIX_SHA256: Digest32 = Digest32::from_bytes([
    0xd6, 0xba, 0x93, 0x29, 0xf8, 0x93, 0x2c, 0x12, 0x19, 0x2b, 0x37, 0x84, 0x9f, 0x77, 0x21, 0x04,
    0xd2, 0x00, 0x48, 0xf7, 0x64, 0x34, 0xa3, 0x29, 0x05, 0x12, 0xd9, 0xd8, 0x14, 0xe4, 0x11, 0x6f,
]);
const PINNED_VERIFIER_G2_SHA256: Digest32 = Digest32::from_bytes([
    0x01, 0x79, 0x7b, 0xfc, 0x4d, 0xe5, 0xa9, 0x6f, 0x0e, 0x51, 0x6a, 0x9e, 0xa4, 0x53, 0x7d, 0x18,
    0x78, 0x6d, 0xc3, 0x0c, 0xb9, 0x91, 0xac, 0xa4, 0x27, 0x4c, 0x95, 0x82, 0x2b, 0x69, 0xc3, 0x2f,
]);
const PINNED_FULL_PROVER_G1_PREFIX_SHA256: Digest32 = Digest32::from_bytes([
    0x0f, 0x23, 0x88, 0x56, 0xe5, 0x57, 0x22, 0xf1, 0x5a, 0x4d, 0x64, 0xef, 0x0d, 0xe1, 0x2b, 0x42,
    0x60, 0xe2, 0x18, 0x24, 0x55, 0x90, 0xbd, 0x3a, 0x6c, 0x90, 0x0a, 0xee, 0x18, 0x8d, 0xe8, 0xe5,
]);
const PINNED_VERIFIER_CRS_IDENTITY: BarretenbergVerifierCrsIdentity =
    BarretenbergVerifierCrsIdentity {
        g1_prefix_sha256: PINNED_VERIFIER_G1_PREFIX_SHA256,
        g2_sha256: PINNED_VERIFIER_G2_SHA256,
    };
const PINNED_FULL_PROVER_CRS_IDENTITY: BarretenbergProverCrsIdentity =
    BarretenbergProverCrsIdentity {
        g1_prefix_sha256: PINNED_FULL_PROVER_G1_PREFIX_SHA256,
        g2_sha256: PINNED_VERIFIER_G2_SHA256,
    };

pub(super) struct BbapiProcessState {
    pub(super) crs: BbapiProcessCrsState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BarretenbergProcessCrsIdentity {
    VerifierOnly(BarretenbergVerifierCrsIdentity),
    FullProver(BarretenbergProverCrsIdentity),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BbapiProcessCrsState {
    Uninitialized,
    Poisoned,
    Ready(BarretenbergProcessCrsIdentity),
}

impl Default for BbapiProcessState {
    fn default() -> Self {
        Self {
            crs: BbapiProcessCrsState::Uninitialized,
        }
    }
}

impl BarretenbergProcessCrsIdentity {
    pub(super) fn satisfies(self, requested: Self) -> bool {
        if self == requested {
            return true;
        }
        matches!(
            (self, requested),
            (
                Self::FullProver(BarretenbergProverCrsIdentity {
                    g1_prefix_sha256: PINNED_FULL_PROVER_G1_PREFIX_SHA256,
                    g2_sha256: PINNED_VERIFIER_G2_SHA256,
                }),
                Self::VerifierOnly(BarretenbergVerifierCrsIdentity {
                    g1_prefix_sha256: PINNED_VERIFIER_G1_PREFIX_SHA256,
                    g2_sha256: PINNED_VERIFIER_G2_SHA256,
                }),
            )
        )
    }
}

static BBAPI_PROCESS_STATE: OnceLock<Mutex<BbapiProcessState>> = OnceLock::new();

fn bbapi_process_state() -> &'static Mutex<BbapiProcessState> {
    BBAPI_PROCESS_STATE.get_or_init(|| Mutex::new(BbapiProcessState::default()))
}

pub(super) fn lock_bbapi_process_state() -> Result<MutexGuard<'static, BbapiProcessState>, ZkError>
{
    bbapi_process_state()
        .lock()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))
}

/// Hash-pinned identity of the process-global verifier CRS admitted to BBAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarretenbergVerifierCrsIdentity {
    pub(super) g1_prefix_sha256: Digest32,
    pub(super) g2_sha256: Digest32,
}

impl BarretenbergVerifierCrsIdentity {
    /// Repository-pinned verifier CRS identity for the modern toolchain gate.
    #[must_use]
    pub const fn pinned_modern_verifier() -> Self {
        PINNED_VERIFIER_CRS_IDENTITY
    }

    /// SHA-256 of the single verifier G1 point prefix.
    #[must_use]
    pub const fn g1_prefix_sha256(self) -> Digest32 {
        self.g1_prefix_sha256
    }

    /// SHA-256 of the G2 point bytes.
    #[must_use]
    pub const fn g2_sha256(self) -> Digest32 {
        self.g2_sha256
    }
}

/// Hash-pinned identity of the process-global full prover CRS admitted to BBAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarretenbergProverCrsIdentity {
    pub(super) g1_prefix_sha256: Digest32,
    pub(super) g2_sha256: Digest32,
}

impl BarretenbergProverCrsIdentity {
    /// Repository-pinned full prover CRS identity for the modern toolchain gate.
    #[must_use]
    pub const fn pinned_modern_prover() -> Self {
        PINNED_FULL_PROVER_CRS_IDENTITY
    }

    /// SHA-256 of the admitted full prover G1 prefix.
    #[must_use]
    pub const fn g1_prefix_sha256(self) -> Digest32 {
        self.g1_prefix_sha256
    }

    /// SHA-256 of the G2 point bytes.
    #[must_use]
    pub const fn g2_sha256(self) -> Digest32 {
        self.g2_sha256
    }
}

/// Borrowed, hash-pinned verifier-only CRS for linked Barretenberg.
#[derive(Clone, Copy)]
pub struct BarretenbergVerifierCrs<'a> {
    pub(super) g1_prefix: &'a [u8],
    pub(super) g2_point: &'a [u8],
    pub(super) identity: BarretenbergVerifierCrsIdentity,
}

/// Borrowed, hash-pinned full prover CRS for linked Barretenberg.
#[derive(Clone, Copy)]
pub struct BarretenbergProverCrs<'a> {
    pub(super) g1_prefix: &'a [u8],
    pub(super) g2_point: &'a [u8],
    pub(super) identity: BarretenbergProverCrsIdentity,
}

impl<'a> BarretenbergProverCrs<'a> {
    /// Validates exact full-prover CRS lengths and repository-pinned identities.
    pub fn try_from_pinned_slices(
        g1_prefix: &'a [u8],
        g2_point: &'a [u8],
    ) -> Result<Self, ZkError> {
        if g1_prefix.len() != FULL_PROVER_CRS_G1_PREFIX_BYTES
            || g2_point.len() != VERIFIER_CRS_G2_BYTES
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if !PINNED_FULL_PROVER_G1_PREFIX_SHA256.matches_sha256(g1_prefix)
            || !PINNED_VERIFIER_G2_SHA256.matches_sha256(g2_point)
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(Self {
            g1_prefix,
            g2_point,
            identity: PINNED_FULL_PROVER_CRS_IDENTITY,
        })
    }

    /// Hash identity admitted to the process-global Barretenberg state.
    #[must_use]
    pub const fn identity(self) -> BarretenbergProverCrsIdentity {
        self.identity
    }

    pub(super) fn g1_prefix(self) -> &'a [u8] {
        self.g1_prefix
    }

    pub(super) fn g2_point(self) -> &'a [u8] {
        self.g2_point
    }
}

impl<'a> BarretenbergVerifierCrs<'a> {
    /// Validates exact verifier CRS lengths and repository-pinned identities.
    pub fn try_from_pinned_slices(
        g1_prefix: &'a [u8],
        g2_point: &'a [u8],
    ) -> Result<Self, ZkError> {
        if g1_prefix.len() != VERIFIER_CRS_G1_PREFIX_BYTES
            || g2_point.len() != VERIFIER_CRS_G2_BYTES
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if !PINNED_VERIFIER_G1_PREFIX_SHA256.matches_sha256(g1_prefix)
            || !PINNED_VERIFIER_G2_SHA256.matches_sha256(g2_point)
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(Self {
            g1_prefix,
            g2_point,
            identity: PINNED_VERIFIER_CRS_IDENTITY,
        })
    }

    /// Hash identity admitted to the process-global Barretenberg state.
    #[must_use]
    pub const fn identity(self) -> BarretenbergVerifierCrsIdentity {
        self.identity
    }

    pub(super) fn g1_prefix(self) -> &'a [u8] {
        self.g1_prefix
    }

    pub(super) fn g2_point(self) -> &'a [u8] {
        self.g2_point
    }
}

impl core::fmt::Debug for BarretenbergVerifierCrs<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BarretenbergVerifierCrs")
            .field("g1_prefix_len", &self.g1_prefix.len())
            .field("g2_point_len", &self.g2_point.len())
            .field("identity", &self.identity)
            .finish()
    }
}

impl core::fmt::Debug for BarretenbergProverCrs<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BarretenbergProverCrs")
            .field("g1_prefix_len", &self.g1_prefix.len())
            .field("g2_point_len", &self.g2_point.len())
            .field("identity", &self.identity)
            .finish()
    }
}
