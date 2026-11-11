// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleWitness},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofSuite, ZkSessionBinding},
};

/// Request passed to an injected production bundle prover.
///
/// SDK and OpenID4VP glue construct typed application inputs first. The injected
/// provider uses the typed witness-input layer to generate one serialized witness stack for
/// each exact stage circuit, then transfers the complete zeroizing bundle into
/// this request. A stage stack must never be reused for another circuit ABI.
#[derive(Clone, Copy)]
pub struct ZkClaimProofBundleProveRequest<'a> {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    witness_bundle: &'a ZkClaimProofBundleWitness,
    session_binding: ZkSessionBinding,
}

impl<'a> ZkClaimProofBundleProveRequest<'a> {
    /// Builds a production bundle proof request for an injected provider.
    pub fn try_new(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        witness_bundle: &'a ZkClaimProofBundleWitness,
        session_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        Self::try_new_with_suite_policy(
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            witness_bundle,
            session_binding,
        )
    }

    /// Builds an explicitly acknowledged compatibility request.
    ///
    /// Compatibility suites are never selected by the production constructor
    /// because they may omit witness masking or use an unsupported transcript.
    pub fn try_new_compatibility(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        witness_bundle: &'a ZkClaimProofBundleWitness,
        session_binding: ZkSessionBinding,
        _acknowledgement: ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if proof_suite == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            witness_bundle,
            session_binding,
        )
    }

    fn try_new_with_suite_policy(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        witness_bundle: &'a ZkClaimProofBundleWitness,
        session_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        if witness_bundle.bundle_kind() != bundle_kind
            || witness_bundle.credential_hash_algorithm() != credential_hash_algorithm
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Ok(Self {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            witness_bundle,
            session_binding,
        })
    }

    /// Production bundle_kind requested by the caller.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Exact source hash lane requested by the caller.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Exact transcript and masking suite.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Four exact-circuit witness stacks.
    #[must_use]
    pub const fn witness_bundle(&self) -> &'a ZkClaimProofBundleWitness {
        self.witness_bundle
    }

    /// Session binding required in every stage.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }
}

/// Explicit acknowledgement required for non-production proof suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkCompatibilitySuiteAcknowledgement {
    private: (),
}

impl ZkCompatibilitySuiteAcknowledgement {
    /// Acknowledges that the selected compatibility suite is not approved for
    /// production disclosure and may not provide zero-knowledge masking.
    #[must_use]
    pub const fn acknowledge_non_production_risk() -> Self {
        Self { private: () }
    }
}
