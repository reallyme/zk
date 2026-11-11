// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    circuits::{ZkCircuitId, ZkCircuitRef},
    claim_bundle::ZkCompatibilitySuiteAcknowledgement,
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkDecodedPublicInputs, ZkProofSuite, ZkPublicInputs, ZkSessionBinding, ZkWitness},
};

/// Request passed to an injected prover.
#[derive(Clone, Copy)]
pub struct ZkProveRequest<'a> {
    circuit_id: ZkCircuitId,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    witness: &'a ZkWitness,
    public_inputs: &'a ZkPublicInputs,
    session_binding: ZkSessionBinding,
}

impl<'a> ZkProveRequest<'a> {
    /// Builds a fail-closed production proof request for one exact circuit.
    pub fn try_new(
        circuit_id: ZkCircuitId,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        witness: &'a ZkWitness,
        public_inputs: &'a ZkPublicInputs,
        session_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        proof_suite.require_production()?;
        Self::try_new_with_suite_policy(
            circuit_id,
            circuit_ref,
            proof_suite,
            witness,
            public_inputs,
            session_binding,
        )
    }

    /// Builds an explicitly acknowledged compatibility proof request.
    ///
    /// Compatibility suites are useful for diagnostic parity and retained
    /// cross-suite fixtures, but they must never be selected implicitly by a
    /// production caller.
    pub fn try_new_compatibility(
        circuit_id: ZkCircuitId,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        witness: &'a ZkWitness,
        public_inputs: &'a ZkPublicInputs,
        session_binding: ZkSessionBinding,
        _acknowledgement: ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if proof_suite == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(
            circuit_id,
            circuit_ref,
            proof_suite,
            witness,
            public_inputs,
            session_binding,
        )
    }

    fn try_new_with_suite_policy(
        circuit_id: ZkCircuitId,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        witness: &'a ZkWitness,
        public_inputs: &'a ZkPublicInputs,
        session_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        if circuit_ref.circuit_id() != circuit_id || witness.circuit_ref() != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        // The exact circuit reference fixes the public-input ABI. Decode before
        // handing the request to any backend so callers cannot smuggle a stale
        // or partially specified proof boundary through diagnostic APIs.
        ZkDecodedPublicInputs::try_decode(circuit_ref, public_inputs)?;
        session_binding.decode_and_validate(circuit_ref, public_inputs)?;
        Ok(Self {
            circuit_id,
            circuit_ref,
            proof_suite,
            witness,
            public_inputs,
            session_binding,
        })
    }

    /// Policy circuit requested by the caller.
    #[must_use]
    pub const fn circuit_id(&self) -> ZkCircuitId {
        self.circuit_id
    }

    /// Exact imported circuit source to prove.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Exact transcript and witness-masking suite.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Secret witness/private inputs.
    #[must_use]
    pub const fn witness(&self) -> &'a ZkWitness {
        self.witness
    }

    /// Public inputs bound to the requested circuit.
    #[must_use]
    pub const fn public_inputs(&self) -> &'a ZkPublicInputs {
        self.public_inputs
    }

    /// Active verifier-session binding encoded in the public inputs.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }
}
