// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact source-circuit artifact owner for promotion evidence.

use reallyme_zk_api::{
    artifacts::ZkArtifactIdentity,
    capabilities::circuit_ref_capabilities,
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::{ArtifactKind, VerifiedArtifactBytes};

/// Hash-verified material for one exact imported source circuit.
///
/// This is narrower than a production-stage manifest: it exists for promotion
/// evidence and source-circuit validation, including circuits such as
/// `claim_bundle_4` that are not part of the four-stage mobile provider
/// contract. Callers are responsible for constructing `artifact_identity` from
/// a reviewed lock or manifest before this type is built; the linked backend
/// only binds the proof envelope to that identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BbExactCircuitArtifacts {
    circuit_ref: ZkCircuitRef,
    artifact_identity: ZkArtifactIdentity,
    bytecode: VerifiedArtifactBytes,
    verification_key: VerifiedArtifactBytes,
}

impl BbExactCircuitArtifacts {
    /// Validates bounded artifact classes for one exact imported source circuit.
    pub fn try_new(
        circuit_ref: ZkCircuitRef,
        artifact_identity: impl Into<ZkArtifactIdentity>,
        bytecode: VerifiedArtifactBytes,
        verification_key: VerifiedArtifactBytes,
    ) -> Result<Self, ZkError> {
        let _capabilities = circuit_ref_capabilities(circuit_ref)?;
        if bytecode.kind() != ArtifactKind::AcirBytecode
            || verification_key.kind() != ArtifactKind::VerificationKey
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(Self {
            circuit_ref,
            artifact_identity: artifact_identity.into(),
            bytecode,
            verification_key,
        })
    }

    /// Exact imported source circuit for these artifact bytes.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Reviewed artifact-set identity for this source-circuit evidence.
    #[must_use]
    pub const fn artifact_identity(&self) -> ZkArtifactIdentity {
        self.artifact_identity
    }

    /// Hash-verified ACIR bytecode bytes.
    #[must_use]
    pub const fn bytecode(&self) -> &VerifiedArtifactBytes {
        &self.bytecode
    }

    /// Hash-verified verification-key bytes.
    #[must_use]
    pub const fn verification_key(&self) -> &VerifiedArtifactBytes {
        &self.verification_key
    }
}
