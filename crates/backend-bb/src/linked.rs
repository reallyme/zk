// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed boundary implemented by linked Barretenberg platform bindings.

use reallyme_zk_api::{
    artifacts::ZkArtifactIdentity,
    circuits::ZkCircuitRef,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    common_root::ZkCommonCredentialRootRawPublicInputs,
    errors::ZkError,
    persona_evidence::ZkPersonaCredentialEvidenceMode,
    proofs::{
        ZkDecodedPublicInputs, ZkProof, ZkProofBytes, ZkProofSuite, ZkPublicInputs,
        ZkSessionBinding, ZkWitness,
    },
};
use zeroize::Zeroizing;

use crate::{BbExactCircuitArtifacts, BbStageArtifacts, BbStageVerificationArtifacts};

/// Request passed from provider orchestration to a linked Barretenberg backend
/// for one production stage.
#[derive(Clone, Copy)]
pub struct BbStageProveRequest<'a> {
    /// Production profile being proven.
    pub bundle_kind: ZkClaimProofBundleKind,
    /// Production stage being proven.
    pub stage: ZkClaimProofBundleStage,
    /// Exact source circuit and artifact lane for the stage.
    pub circuit_ref: ZkCircuitRef,
    /// Exact transcript and witness-masking suite requested by the caller.
    pub proof_suite: ZkProofSuite,
    /// Hash-verified proving material for the exact stage.
    pub artifacts: &'a BbStageArtifacts,
    /// Provider-encoded witness material.
    pub witness: &'a ZkWitness,
    /// Binding that must be represented in the stage public inputs.
    pub session_binding: ZkSessionBinding,
}

/// Bounded proof material returned by a linked Barretenberg backend.
///
/// This is the normalized provider product, not a raw native-bridge result.
/// Platform adapters must separate Barretenberg proof framing and translate
/// backend field elements into the canonical compact public-input ABI before
/// constructing it.
#[derive(Debug, PartialEq, Eq)]
pub struct BbStageProveResponse {
    proof_bytes: ZkProofBytes,
    public_inputs: ZkPublicInputs,
}

impl BbStageProveResponse {
    /// Validates an already-owned linked-backend result.
    pub fn try_from_compact_bytes(
        circuit_ref: ZkCircuitRef,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Result<Self, ZkError> {
        ZkProofBytes::validate_length(proof_bytes.len())?;
        ZkPublicInputs::validate_length(public_inputs.len())?;

        Self::try_from_bounded_parts(
            circuit_ref,
            ZkProofBytes::try_from_bytes(proof_bytes)?,
            ZkPublicInputs::try_from_bytes(public_inputs)?,
        )
    }

    /// Checks platform-reported buffers before allocating Rust-owned copies.
    pub fn try_copy_from_compact_slices(
        circuit_ref: ZkCircuitRef,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<Self, ZkError> {
        // Validate both reported lengths before either allocation. Platform FFI
        // adapters should perform these same checks before creating the slices.
        ZkProofBytes::validate_length(proof_bytes.len())?;
        ZkPublicInputs::validate_length(public_inputs.len())?;

        Self::try_from_bounded_parts(
            circuit_ref,
            ZkProofBytes::try_copy_from_slice(proof_bytes)?,
            ZkPublicInputs::try_copy_from_slice(public_inputs)?,
        )
    }

    /// Validates exact public-input ABI for already bounded result owners.
    pub fn try_from_bounded_parts(
        circuit_ref: ZkCircuitRef,
        proof_bytes: ZkProofBytes,
        public_inputs: ZkPublicInputs,
    ) -> Result<Self, ZkError> {
        ZkDecodedPublicInputs::try_decode(circuit_ref, &public_inputs)?;
        Ok(Self {
            proof_bytes,
            public_inputs,
        })
    }

    /// Borrows bounded proof bytes.
    #[must_use]
    pub const fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    /// Borrows exact compact public inputs.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkPublicInputs {
        &self.public_inputs
    }

    /// Consumes the response without copying either owned buffer.
    #[must_use]
    pub fn into_parts(self) -> (ZkProofBytes, ZkPublicInputs) {
        (self.proof_bytes, self.public_inputs)
    }
}

/// Raw proof material returned for one common-credential-root proof slot.
///
/// Common credential root v1 joins consume exact Barretenberg public-input field streams
/// that are larger than the compact production ABI. This owner deliberately
/// does not implement or reuse `ZkPublicInputs`, preserving the compact four
/// KiB cap for the legacy production path.
#[derive(Debug, PartialEq, Eq)]
pub struct BbCommonCredentialRootRawProveResponse {
    proof_bytes: ZkProofBytes,
    public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

impl BbCommonCredentialRootRawProveResponse {
    /// Validates already-owned raw Barretenberg result buffers.
    pub fn try_from_raw_bytes(
        circuit_ref: ZkCircuitRef,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Result<Self, ZkError> {
        Self::try_from_raw_zeroizing_bytes(
            circuit_ref,
            Zeroizing::new(proof_bytes),
            Zeroizing::new(public_inputs),
        )
    }

    /// Validates zeroizing raw Barretenberg result buffers without ever
    /// dropping disclosed public-input bytes as a plain allocation.
    pub(crate) fn try_from_raw_zeroizing_bytes(
        circuit_ref: ZkCircuitRef,
        mut proof_bytes: Zeroizing<Vec<u8>>,
        mut public_inputs: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ZkError> {
        let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
            circuit_ref,
            core::mem::take(&mut *public_inputs),
        )?;
        let proof_bytes = ZkProofBytes::try_from_bytes(core::mem::take(&mut *proof_bytes))?;
        Self::try_from_bounded_parts(proof_bytes, public_inputs)
    }

    /// Checks borrowed native buffers before allocating Rust-owned copies.
    pub fn try_copy_from_raw_slices(
        circuit_ref: ZkCircuitRef,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<Self, ZkError> {
        Self::try_from_bounded_parts(
            ZkProofBytes::try_copy_from_slice(proof_bytes)?,
            ZkCommonCredentialRootRawPublicInputs::try_copy_from_slice(circuit_ref, public_inputs)?,
        )
    }

    /// Creates a raw result from already bounded owners.
    pub fn try_from_bounded_parts(
        proof_bytes: ZkProofBytes,
        public_inputs: ZkCommonCredentialRootRawPublicInputs,
    ) -> Result<Self, ZkError> {
        Ok(Self {
            proof_bytes,
            public_inputs,
        })
    }

    /// Borrows bounded proof bytes.
    #[must_use]
    pub const fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    /// Borrows exact raw Barretenberg public inputs.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        &self.public_inputs
    }

    /// Consumes the response without copying either owned buffer.
    #[must_use]
    pub fn into_parts(self) -> (ZkProofBytes, ZkCommonCredentialRootRawPublicInputs) {
        (self.proof_bytes, self.public_inputs)
    }
}

/// Request passed from provider orchestration to a linked Barretenberg backend
/// for one stage verification.
#[derive(Debug, Clone, Copy)]
pub struct BbStageVerifyRequest<'a> {
    /// Production profile being verified.
    pub bundle_kind: ZkClaimProofBundleKind,
    /// Production stage being verified.
    pub stage: ZkClaimProofBundleStage,
    /// Exact source circuit and artifact lane for the stage.
    pub circuit_ref: ZkCircuitRef,
    /// Exact transcript and witness-masking suite claimed by the proof.
    pub proof_suite: ZkProofSuite,
    /// Hash-verified verification material for the exact stage.
    pub artifacts: &'a BbStageVerificationArtifacts,
    /// Stage proof package.
    pub proof: &'a ZkProof,
    /// Binding expected for the active verifier session.
    pub expected_binding: ZkSessionBinding,
}

/// Request passed directly to a linked backend for one exact imported source
/// circuit.
///
/// This is used by promotion gates and evidence-only source circuits that do
/// not map to the four-stage production provider contract.
#[derive(Clone, Copy)]
pub struct BbExactCircuitProveRequest<'a> {
    /// Exact source circuit and ABI for the proof.
    pub circuit_ref: ZkCircuitRef,
    /// Exact transcript and witness-masking suite requested by the caller.
    pub proof_suite: ZkProofSuite,
    /// Reviewed artifact-set identity to retain in the proof envelope.
    pub artifact_identity: ZkArtifactIdentity,
    /// Hash-verified proving material for the exact source circuit.
    pub artifacts: &'a BbExactCircuitArtifacts,
    /// Provider-encoded witness material for the exact source circuit.
    pub witness: &'a ZkWitness,
    /// Binding that must be represented in the circuit public inputs.
    pub session_binding: ZkSessionBinding,
}

/// Request passed directly to a linked backend for one common-credential-root raw source
/// circuit.
#[derive(Clone, Copy)]
pub struct BbCommonCredentialRootRawProveRequest<'a> {
    /// Exact source circuit and raw public-input ABI for the proof slot.
    pub circuit_ref: ZkCircuitRef,
    /// Exact transcript and witness-masking suite requested by the caller.
    pub proof_suite: ZkProofSuite,
    /// Reviewed artifact-set identity to retain in evidence records.
    pub artifact_identity: ZkArtifactIdentity,
    /// Hash-verified proving material for the exact source circuit.
    pub artifacts: &'a BbExactCircuitArtifacts,
    /// Provider-encoded witness material for the exact source circuit.
    pub witness: &'a ZkWitness,
}

/// Request for one exact persona-credential-evidence proof stage. Its output is checked
/// against the prepared public-input ABI and verified before admission.
#[derive(Clone, Copy)]
pub struct BbPersonaCredentialEvidenceStageProveRequest<'a> {
    /// Persona mode that the circuit must implement.
    pub mode: ZkPersonaCredentialEvidenceMode,
    /// Exact prepared source circuit, including its hash lane.
    pub circuit_ref: ZkCircuitRef,
    /// Production zero-knowledge transcript and masking suite.
    pub proof_suite: ZkProofSuite,
    /// Reviewed artifact identity committed into the proof package.
    pub artifact_identity: ZkArtifactIdentity,
    /// Hash-verified compiled program and verification key.
    pub artifacts: &'a BbExactCircuitArtifacts,
    /// Short-lived, native-owned serialized witness.
    pub witness: &'a ZkWitness,
}

/// Request passed directly to a linked backend for one common-credential-root raw
/// verification.
#[derive(Debug, Clone, Copy)]
pub struct BbCommonCredentialRootRawVerifyRequest<'a> {
    /// Exact source circuit and raw public-input ABI for the proof slot.
    pub circuit_ref: ZkCircuitRef,
    /// Exact transcript and witness-masking suite claimed by the proof.
    pub proof_suite: ZkProofSuite,
    /// Reviewed artifact-set identity expected by the caller.
    pub artifact_identity: ZkArtifactIdentity,
    /// Hash-verified verification material for the exact source circuit.
    pub artifacts: &'a BbExactCircuitArtifacts,
    /// Raw proof bytes returned by or admitted to the linked backend.
    pub proof_bytes: &'a ZkProofBytes,
    /// Exact raw public-input owner consumed by join verification.
    pub public_inputs: &'a ZkCommonCredentialRootRawPublicInputs,
}

/// Request passed directly to a linked backend to verify one exact imported
/// source circuit.
#[derive(Debug, Clone, Copy)]
pub struct BbExactCircuitVerifyRequest<'a> {
    /// Exact source circuit and ABI for the proof.
    pub circuit_ref: ZkCircuitRef,
    /// Exact transcript and witness-masking suite claimed by the proof.
    pub proof_suite: ZkProofSuite,
    /// Reviewed artifact-set identity expected for the proof envelope.
    pub artifact_identity: ZkArtifactIdentity,
    /// Hash-verified verification material for the exact source circuit.
    pub artifacts: &'a BbExactCircuitArtifacts,
    /// Exact source-circuit proof package.
    pub proof: &'a ZkProof,
    /// Binding expected for the active verifier session.
    pub expected_binding: ZkSessionBinding,
}

/// Linked Barretenberg backend implemented by a platform binding.
///
/// Implementations receive hash-verified artifacts, invoke only a linked
/// Barretenberg library, and map backend failures to privacy-safe `ZkError`
/// values. This trait deliberately does not define an ambient provider or CLI
/// fallback.
pub trait LinkedBarretenbergBackend: Send + Sync {
    /// Reports whether this backend can execute the exact requested suite.
    ///
    /// Implementations must not satisfy a request by changing transcript hash,
    /// disabling ZK masking, or otherwise selecting a different suite.
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool;

    /// Proves one production stage.
    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError>;

    /// Verifies one production stage.
    ///
    /// The implementation MUST pass `request.proof.proof_bytes()` and the
    /// exact `request.proof.public_inputs()` owner to one cryptographic verify
    /// call. It must not reconstruct, substitute, or independently parse a
    /// parallel public-input source. The provider's policy checks and the
    /// backend verifier therefore share one canonical input owner.
    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError>;

    /// Verifies one common-credential-root raw source circuit.
    ///
    /// Common-credential-root presentations use the exact Barretenberg public-input field
    /// stream because their join checks consume circuit-native roots and
    /// commitments. Implementations must verify the supplied proof bytes and
    /// public inputs as one backend request and must not substitute compact
    /// production-stage public inputs.
    fn verify_common_credential_root_raw(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError>;
}

impl<T> LinkedBarretenbergBackend for &T
where
    T: LinkedBarretenbergBackend + ?Sized,
{
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        (**self).supports_proof_suite(proof_suite)
    }

    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        (**self).prove_stage(request)
    }

    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        (**self).verify_stage(request)
    }

    fn verify_common_credential_root_raw(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        (**self).verify_common_credential_root_raw(request)
    }
}

#[cfg(test)]
mod tests;
