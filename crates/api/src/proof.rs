// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    artifacts::ZkArtifactIdentity,
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitId, ZkCircuitRef},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkDecodedPublicInputs, ZkProofSuite, ZkPublicInputs, ZkSessionBinding},
};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum proof byte length accepted by the API boundary.
///
/// Concrete backends may impose stricter limits. This bound exists to prevent
/// accidental unbounded allocation at format and FFI boundaries before backend
/// parsing begins.
pub const MAX_PROOF_BYTES: usize = 256 * 1024;

/// Maximum secret witness byte length accepted by the API boundary.
///
/// Witness adapters must apply circuit-specific shape and field limits before
/// constructing this owner. This transport bound prevents an untrusted FFI,
/// WASM, JNI, or protobuf request from creating an unbounded secret allocation.
///
/// Current `claim_bundle_4` witnesses inflate to roughly 3.3 MiB under the
/// pinned Noir stack. Four MiB admits every current production circuit while
/// preserving a deterministic cap for FFI and transport sizing.
pub const MAX_WITNESS_BYTES: usize = 4 * 1024 * 1024;

/// Versioned serialization accepted at the proving-backend boundary.
///
/// Identity and claim fields remain strongly typed in the repository's witness-input layer.
/// This enum types only the short-lived serialized product transferred from
/// that owner into ZK orchestration, preventing an adapter from silently
/// substituting a different witness representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZkWitnessEncoding {
    /// Gzip-compressed `WitnessStack::serialize()` output produced by the
    /// reviewed Noir v1 witness generator.
    NoirWitnessStackV1,
}

/// Bounded serialized proof bytes.
///
/// Linked-library, FFI, JNI, and WASM adapters construct this owner before a
/// proof crosses into provider orchestration. Its borrowed constructor checks
/// the platform-reported length before allocating the Rust-owned copy. Proofs
/// are verifier-visible, but a prepared private proof identifies one token;
/// every owned copy is wiped when it leaves the wallet's custody.
#[derive(Clone, PartialEq, Eq)]
pub struct ZkProofBytes {
    bytes: Vec<u8>,
}

impl ZkProofBytes {
    /// Validates a platform-reported length before an adapter reads or copies
    /// the corresponding buffer.
    pub const fn validate_length(length: usize) -> Result<(), ZkError> {
        validate_proof_length(length)
    }

    /// Validates an already-owned proof buffer without copying it.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, ZkError> {
        // A rejected private prepared proof still identifies its token. Own
        // the allocation under erasure before any fallible validation.
        let mut bytes = Zeroizing::new(bytes);
        Self::validate_length(bytes.len())?;
        Ok(Self {
            bytes: core::mem::take(&mut *bytes),
        })
    }

    /// Checks a borrowed platform buffer before allocating its owned copy.
    pub fn try_copy_from_slice(bytes: &[u8]) -> Result<Self, ZkError> {
        Self::validate_length(bytes.len())?;

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    /// Borrows the bounded proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Transfers the allocation to the caller, which then owns its erasure.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl Drop for ZkProofBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for ZkProofBytes {}

impl core::fmt::Debug for ZkProofBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkProofBytes")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

const fn validate_proof_length(length: usize) -> Result<(), ZkError> {
    if length == 0 {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if length > MAX_PROOF_BYTES {
        return Err(ZkError::new(ZkErrorReason::ProofTooLarge));
    }
    Ok(())
}

/// Secret witness/private input material for a proof.
///
/// This type intentionally does not implement `Debug`, `Clone`, `Display`,
/// `Serialize`, or `Deserialize`.
pub struct ZkWitness {
    circuit_ref: ZkCircuitRef,
    encoding: ZkWitnessEncoding,
    bytes: SecretBox<Zeroizing<Vec<u8>>>,
}

impl ZkWitness {
    /// Admits one exact Noir v1 serialized witness stack into a zeroizing
    /// owner.
    ///
    /// The typed Noir bindings must validate circuit-specific fields and ABI
    /// shape before calling this transport constructor.
    pub fn try_from_noir_witness_stack_v1(
        circuit_ref: ZkCircuitRef,
        bytes: Vec<u8>,
    ) -> Result<Self, ZkError> {
        Self::try_from_noir_witness_stack_v1_zeroizing(circuit_ref, Zeroizing::new(bytes))
    }

    /// Admits an already-zeroizing Noir v1 witness stack without creating a
    /// second unmanaged owner during release or FFI admission.
    pub fn try_from_noir_witness_stack_v1_zeroizing(
        circuit_ref: ZkCircuitRef,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ZkError> {
        let _capabilities = circuit_ref_capabilities(circuit_ref)?;
        if bytes.is_empty() {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(ZkError::new(ZkErrorReason::WitnessTooLarge));
        }

        Ok(Self {
            circuit_ref,
            encoding: ZkWitnessEncoding::NoirWitnessStackV1,
            bytes: SecretBox::new(Box::new(bytes)),
        })
    }

    /// Exact circuit ABI that produced this serialized witness stack.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Exact serialized witness representation carried by this owner.
    #[must_use]
    pub const fn encoding(&self) -> ZkWitnessEncoding {
        self.encoding
    }

    /// Borrows witness bytes for the injected backend.
    ///
    /// Backend implementations must avoid logging this slice and should copy it
    /// only into other zeroizing owners.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.bytes.expose_secret().as_slice()
    }
}

/// Proof bytes with structurally checked public inputs; this owner is not verification evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct ZkProof {
    circuit_id: ZkCircuitId,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    artifact_identity: ZkArtifactIdentity,
    proof_bytes: ZkProofBytes,
    public_inputs: ZkPublicInputs,
}

impl ZkProof {
    /// Validates proof/public-input sizes and creates an exact proof container.
    pub fn try_from_exact_parts(
        circuit_id: ZkCircuitId,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        artifact_identity: impl Into<ZkArtifactIdentity>,
        proof_bytes: Vec<u8>,
        public_inputs: ZkPublicInputs,
    ) -> Result<Self, ZkError> {
        let proof_bytes = ZkProofBytes::try_from_bytes(proof_bytes)?;
        Self::try_from_exact_bounded_parts(
            circuit_id,
            circuit_ref,
            proof_suite,
            artifact_identity,
            proof_bytes,
            public_inputs,
        )
    }

    /// Creates an exact proof from proof bytes already bounded by an adapter.
    pub fn try_from_exact_bounded_parts(
        circuit_id: ZkCircuitId,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        artifact_identity: impl Into<ZkArtifactIdentity>,
        proof_bytes: ZkProofBytes,
        public_inputs: ZkPublicInputs,
    ) -> Result<Self, ZkError> {
        if circuit_ref.circuit_id() != circuit_id {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        // An exact circuit reference is a claim about the ABI as well as the
        // source identity. Reject malformed public inputs before the proof can
        // cross another adapter boundary under that claim.
        ZkDecodedPublicInputs::try_decode(circuit_ref, &public_inputs)?;

        Ok(Self {
            circuit_id,
            circuit_ref,
            proof_suite,
            artifact_identity: artifact_identity.into(),
            proof_bytes,
            public_inputs,
        })
    }

    /// Circuit claimed by this proof.
    #[must_use]
    pub const fn circuit_id(&self) -> ZkCircuitId {
        self.circuit_id
    }

    /// Exact imported circuit source claimed by this proof.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Exact proving and verification suite claimed by this proof.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Canonical artifact manifest used to create and verify this proof.
    #[must_use]
    pub const fn artifact_identity(&self) -> ZkArtifactIdentity {
        self.artifact_identity
    }

    /// Serialized proof bytes.
    #[must_use]
    pub fn proof_bytes(&self) -> &[u8] {
        self.proof_bytes.as_bytes()
    }

    /// Serialized public inputs.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkPublicInputs {
        &self.public_inputs
    }

    /// Consumes this wrapper and returns the owned parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ZkCircuitId,
        ZkProofSuite,
        ZkArtifactIdentity,
        Vec<u8>,
        ZkPublicInputs,
    ) {
        (
            self.circuit_id,
            self.proof_suite,
            self.artifact_identity,
            self.proof_bytes.into_bytes(),
            self.public_inputs,
        )
    }

    /// Consumes this wrapper and returns the exact owned parts.
    #[must_use]
    pub fn into_exact_parts(
        self,
    ) -> (
        ZkCircuitId,
        ZkCircuitRef,
        ZkProofSuite,
        ZkArtifactIdentity,
        Vec<u8>,
        ZkPublicInputs,
    ) {
        (
            self.circuit_id,
            self.circuit_ref,
            self.proof_suite,
            self.artifact_identity,
            self.proof_bytes.into_bytes(),
            self.public_inputs,
        )
    }
}

mod prove_request;
pub use prove_request::ZkProveRequest;

/// Request passed to an injected verifier.
#[derive(Debug, Clone, Copy)]
pub struct ZkVerifyRequest<'a> {
    /// Proof package to verify.
    proof: &'a ZkProof,
    /// Exact suite selected by verifier policy.
    expected_proof_suite: ZkProofSuite,
    /// Binding expected for the active verifier session.
    expected_binding: ZkSessionBinding,
}

impl<'a> ZkVerifyRequest<'a> {
    /// Builds a fail-closed stage verification request.
    pub fn try_new(
        proof: &'a ZkProof,
        expected_proof_suite: ZkProofSuite,
        expected_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        expected_proof_suite.require_production()?;
        Self::try_new_with_suite_policy(proof, expected_proof_suite, expected_binding)
    }

    /// Builds an explicitly acknowledged compatibility-stage request.
    pub fn try_new_compatibility(
        proof: &'a ZkProof,
        expected_proof_suite: ZkProofSuite,
        expected_binding: ZkSessionBinding,
        _acknowledgement: crate::claim_bundle::ZkCompatibilitySuiteAcknowledgement,
    ) -> Result<Self, ZkError> {
        if expected_proof_suite == ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Self::try_new_with_suite_policy(proof, expected_proof_suite, expected_binding)
    }

    fn try_new_with_suite_policy(
        proof: &'a ZkProof,
        expected_proof_suite: ZkProofSuite,
        expected_binding: ZkSessionBinding,
    ) -> Result<Self, ZkError> {
        if proof.proof_suite() != expected_proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        Ok(Self {
            proof,
            expected_proof_suite,
            expected_binding,
        })
    }

    /// Proof package to verify.
    #[must_use]
    pub const fn proof(&self) -> &'a ZkProof {
        self.proof
    }

    /// Exact suite selected by verifier policy.
    #[must_use]
    pub const fn expected_proof_suite(&self) -> ZkProofSuite {
        self.expected_proof_suite
    }

    /// Binding expected for the active verifier session.
    #[must_use]
    pub const fn expected_binding(&self) -> ZkSessionBinding {
        self.expected_binding
    }
}

#[cfg(test)]
mod tests;
