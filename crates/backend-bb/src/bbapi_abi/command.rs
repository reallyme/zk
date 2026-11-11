// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProofSuite, ZkWitnessEncoding, MAX_WITNESS_BYTES},
};
use reallyme_zk_artifacts::{ArtifactKind, VerifiedArtifactBytes};
use zeroize::Zeroizing;

use crate::{
    bbapi_abi::{
        compiled_program_json::{decode_compiled_program_bytecode, decode_gzip_with_limit},
        message::{
            BbapiLimits, BbapiMessage, FULL_PROVER_CRS_G1_POINTS, FULL_PROVER_CRS_G1_PREFIX_BYTES,
            VERIFIER_CRS_G1_POINTS, VERIFIER_CRS_G1_PREFIX_BYTES, VERIFIER_CRS_G2_BYTES,
        },
        pack::{
            pack_array_header, pack_array_header_with_limits, pack_bin, pack_bin_with_limits,
            pack_field_vector, pack_map_header, pack_map_header_with_limits, pack_str,
            pack_str_with_limits, pack_uint_with_limits, pack_verify_settings,
        },
    },
    public_input_codec::BarretenbergPublicInputCodec,
    BbExactCircuitArtifacts, BbStageArtifacts, BbStageProveRequest,
};

/// Wrapper-constructed BBAPI `CircuitProve` command.
#[derive(PartialEq, Eq)]
pub(crate) struct BbapiCircuitProveCommand {
    encoded: Zeroizing<Vec<u8>>,
}

impl BbapiCircuitProveCommand {
    /// Builds the exact upstream prove command from typed, bounded owners.
    pub(crate) fn try_new(request: BbStageProveRequest<'_>) -> Result<Self, ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION
            || request.artifacts.manifest().proof_suite() != ZkProofSuite::PRODUCTION
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.artifacts.manifest().bundle_kind() != request.bundle_kind
            || request.artifacts.manifest().stage() != request.stage
            || request.artifacts.manifest().circuit_ref() != request.circuit_ref
            || request.witness.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.witness.encoding() != ZkWitnessEncoding::NoirWitnessStackV1 {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }

        Self::try_from_artifacts(request.artifacts, request.witness.expose_bytes())
    }

    /// Builds a prove command for one exact imported source circuit.
    pub(crate) fn try_new_exact(
        artifacts: &BbExactCircuitArtifacts,
        witness: &reallyme_zk_api::proofs::ZkWitness,
        proof_suite: ZkProofSuite,
    ) -> Result<Self, ZkError> {
        if proof_suite != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if artifacts.circuit_ref() != witness.circuit_ref() {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if witness.encoding() != ZkWitnessEncoding::NoirWitnessStackV1 {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }

        Self::try_from_exact_artifacts(artifacts, witness.expose_bytes())
    }

    fn try_from_artifacts(artifacts: &BbStageArtifacts, witness: &[u8]) -> Result<Self, ZkError> {
        if artifacts.bytecode().kind() != ArtifactKind::AcirBytecode
            || artifacts.verification_key().kind() != ArtifactKind::VerificationKey
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let limits = BbapiLimits::prove();
        let acir_bytecode = decode_compiled_program_bytecode(artifacts.bytecode().as_bytes())?;
        let witness_stack = decode_witness_stack(witness)?;
        Self::encode_prove_command(
            acir_bytecode.as_slice(),
            artifacts.verification_key().as_bytes(),
            witness_stack.as_slice(),
            limits,
        )
    }

    fn try_from_exact_artifacts(
        artifacts: &BbExactCircuitArtifacts,
        witness: &[u8],
    ) -> Result<Self, ZkError> {
        if artifacts.bytecode().kind() != ArtifactKind::AcirBytecode
            || artifacts.verification_key().kind() != ArtifactKind::VerificationKey
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let limits = BbapiLimits::prove();
        let acir_bytecode = decode_compiled_program_bytecode(artifacts.bytecode().as_bytes())?;
        let witness_stack = decode_witness_stack(witness)?;
        Self::encode_prove_command(
            acir_bytecode.as_slice(),
            artifacts.verification_key().as_bytes(),
            witness_stack.as_slice(),
            limits,
        )
    }

    fn encode_prove_command(
        acir_bytecode: &[u8],
        verification_key: &[u8],
        witness_stack: &[u8],
        limits: BbapiLimits,
    ) -> Result<Self, ZkError> {
        let mut encoded = Zeroizing::new(Vec::new());
        reserve_prove_command_capacity(
            &mut encoded,
            acir_bytecode.len(),
            verification_key.len(),
            witness_stack.len(),
            limits,
        )?;
        pack_array_header_with_limits(&mut encoded, 1, limits)?;
        pack_array_header_with_limits(&mut encoded, 2, limits)?;
        pack_str_with_limits(&mut encoded, "CircuitProve", limits)?;
        pack_map_header_with_limits(&mut encoded, 3, limits)?;

        pack_str_with_limits(&mut encoded, "circuit", limits)?;
        pack_map_header_with_limits(&mut encoded, 3, limits)?;
        pack_str_with_limits(&mut encoded, "name", limits)?;
        pack_str_with_limits(&mut encoded, "circuit", limits)?;
        pack_str_with_limits(&mut encoded, "bytecode", limits)?;
        pack_bin_with_limits(&mut encoded, acir_bytecode, limits)?;
        pack_str_with_limits(&mut encoded, "verification_key", limits)?;
        pack_bin_with_limits(&mut encoded, verification_key, limits)?;

        pack_str_with_limits(&mut encoded, "witness", limits)?;
        pack_bin_with_limits(&mut encoded, witness_stack, limits)?;
        pack_str_with_limits(&mut encoded, "settings", limits)?;
        pack_verify_settings(&mut encoded, limits)?;

        let message = BbapiMessage::try_from_slice_with_limits(encoded.as_slice(), limits)?;
        if message.as_bytes().len() != encoded.len() {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(Self { encoded })
    }

    /// Borrows the exact encoded command bytes to pass to the linked C ABI.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.encoded.as_slice()
    }

    /// Transfers the sole command owner to evidence tooling without making a
    /// second full copy of private witness bytes.
    #[cfg(feature = "dev-cli")]
    pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<Vec<u8>> {
        self.encoded
    }
}

const PROVE_COMMAND_STRUCTURAL_OVERHEAD_BYTES: usize = 1024;

fn reserve_prove_command_capacity(
    encoded: &mut Vec<u8>,
    acir_bytecode_len: usize,
    verification_key_len: usize,
    witness_stack_len: usize,
    limits: BbapiLimits,
) -> Result<(), ZkError> {
    let payload_capacity = acir_bytecode_len
        .checked_add(verification_key_len)
        .and_then(|value| value.checked_add(witness_stack_len))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    if payload_capacity > limits.message_bytes {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }
    let capacity = PROVE_COMMAND_STRUCTURAL_OVERHEAD_BYTES
        .checked_add(payload_capacity)
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?
        .min(limits.message_bytes);
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))
}

fn decode_witness_stack(witness: &[u8]) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    decode_gzip_with_limit(
        witness,
        MAX_WITNESS_BYTES,
        ZkErrorReason::WitnessTooLarge,
        ZkErrorReason::InvalidProofEncoding,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BbapiSrsInitProfile {
    pub(super) g1_prefix_bytes: usize,
    pub(super) g2_bytes: usize,
    pub(super) num_points: u64,
}

impl BbapiSrsInitProfile {
    pub(crate) const fn verifier_only() -> Self {
        Self {
            g1_prefix_bytes: VERIFIER_CRS_G1_PREFIX_BYTES,
            g2_bytes: VERIFIER_CRS_G2_BYTES,
            num_points: VERIFIER_CRS_G1_POINTS,
        }
    }

    pub(crate) const fn full_prover() -> Self {
        Self {
            g1_prefix_bytes: FULL_PROVER_CRS_G1_PREFIX_BYTES,
            g2_bytes: VERIFIER_CRS_G2_BYTES,
            num_points: FULL_PROVER_CRS_G1_POINTS,
        }
    }
}

/// Wrapper-constructed BBAPI `CircuitVerify` command.
#[derive(PartialEq, Eq)]
pub(crate) struct BbapiCircuitVerifyCommand {
    encoded: Zeroizing<Vec<u8>>,
}

impl BbapiCircuitVerifyCommand {
    /// Builds the exact upstream verify command from typed, bounded owners.
    pub(crate) fn try_new(
        verification_key: &VerifiedArtifactBytes,
        proof: &ZkProof,
    ) -> Result<Self, ZkError> {
        if verification_key.kind() != ArtifactKind::VerificationKey {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if proof.proof_suite() != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        validate_expected_proof_len(proof.circuit_ref(), proof.proof_bytes().len())?;
        let mut encoded = Zeroizing::new(Vec::new());
        pack_array_header(&mut encoded, 1)?;
        pack_array_header(&mut encoded, 2)?;
        pack_str(&mut encoded, "CircuitVerify")?;
        pack_map_header(&mut encoded, 4)?;
        pack_str(&mut encoded, "verification_key")?;
        pack_bin(&mut encoded, verification_key.as_bytes())?;
        pack_str(&mut encoded, "public_inputs")?;
        let public_inputs = Zeroizing::new(BarretenbergPublicInputCodec::encode(
            proof.circuit_ref(),
            proof.public_inputs(),
        )?);
        pack_field_vector(&mut encoded, public_inputs.as_slice())?;
        pack_str(&mut encoded, "proof")?;
        pack_field_vector(&mut encoded, proof.proof_bytes())?;
        pack_str(&mut encoded, "settings")?;
        pack_verify_settings(&mut encoded, BbapiLimits::standard())?;

        let message = BbapiMessage::try_from_slice(encoded.as_slice())?;
        if message.as_bytes().len() != encoded.len() {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(Self { encoded })
    }

    /// Borrows the exact encoded command bytes to pass to the linked C ABI.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.encoded.as_slice()
    }
}

mod raw_verify;

#[cfg(test)]
mod proof_len_tests;

fn validate_expected_proof_len(
    circuit_ref: ZkCircuitRef,
    actual_len: usize,
) -> Result<(), ZkError> {
    let expected_len = expected_production_proof_len(circuit_ref)?;
    if actual_len != expected_len {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    Ok(())
}

fn expected_production_proof_len(circuit_ref: ZkCircuitRef) -> Result<usize, ZkError> {
    if circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION {
        return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
    }
    let len = match (
        circuit_ref.credential_hash_algorithm,
        circuit_ref.family,
        circuit_ref.stage,
    ) {
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::Session,
        ) => 9_152,
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::CredentialEnvelope,
        ) => 8_768,
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::CredentialRoot,
        ) => 9_152,
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::Claim,
        ) => 9_536,
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => 9_920,
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => 10_304,
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::Session
            | ZkCircuitStage::CredentialEnvelope
            | ZkCircuitStage::CredentialRoot,
        ) => 8_768,
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CredentialSubjectClaimV1,
            ZkCircuitStage::Claim,
        ) => 9_152,
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::Claim,
        ) => 9_536,
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CredentialSubjectClaimV1 | ZkCircuitFamily::PrivatePersonaClaimV1,
            ZkCircuitStage::ClaimBundle4,
        ) => 9_920,
        (
            ZkCredentialHashAlgorithm::Sha256,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::PublicSession,
        ) => 9_152,
        (
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::PublicSession,
        ) => 8_768,
        (
            ZkCredentialHashAlgorithm::Sha256 | ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::RootAttestation,
        ) => 9_152,
        (
            ZkCredentialHashAlgorithm::Sha256 | ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::CommonCredentialRootV1,
            ZkCircuitStage::RootStatus
            | ZkCircuitStage::Lineage
            | ZkCircuitStage::IssuerCredentialStatus
            | ZkCircuitStage::PrivatePersonaClaim
            | ZkCircuitStage::PublicPersonaClaim,
        ) => 9_536,
        (
            ZkCredentialHashAlgorithm::Sha256 | ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidenceIssuerEnvelope
            | ZkCircuitStage::EvidenceClaimRoot
            | ZkCircuitStage::EvidenceSignedValidity,
        ) => 9_152,
        (
            ZkCredentialHashAlgorithm::Sha256 | ZkCredentialHashAlgorithm::Poseidon2,
            ZkCircuitFamily::PersonaCredentialEvidenceV1,
            ZkCircuitStage::EvidencePublicClaim
            | ZkCircuitStage::EvidencePrivateClaim
            | ZkCircuitStage::EvidenceCurrentState,
        ) => 9_536,
        (_, _, _) => return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit)),
    };
    Ok(len)
}

/// Wrapper-constructed BBAPI `SrsInitSrs` command for pinned CRS profiles.
#[derive(PartialEq, Eq)]
pub(crate) struct BbapiSrsInitCommand {
    encoded: Zeroizing<Vec<u8>>,
}

impl BbapiSrsInitCommand {
    /// Builds the exact upstream SRS initializer for one verifier G1 point.
    pub(crate) fn try_new_verifier(g1_prefix: &[u8], g2_point: &[u8]) -> Result<Self, ZkError> {
        Self::try_new(g1_prefix, g2_point, BbapiSrsInitProfile::verifier_only())
    }

    /// Builds the exact upstream SRS initializer for the full prover CRS.
    pub(crate) fn try_new_prover(g1_prefix: &[u8], g2_point: &[u8]) -> Result<Self, ZkError> {
        Self::try_new(g1_prefix, g2_point, BbapiSrsInitProfile::full_prover())
    }

    pub(super) fn try_new(
        g1_prefix: &[u8],
        g2_point: &[u8],
        profile: BbapiSrsInitProfile,
    ) -> Result<Self, ZkError> {
        if g1_prefix.len() != profile.g1_prefix_bytes || g2_point.len() != profile.g2_bytes {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let encoded_points = profile
            .num_points
            .checked_mul(
                u64::try_from(VERIFIER_CRS_G1_PREFIX_BYTES)
                    .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
            )
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if encoded_points
            != u64::try_from(g1_prefix.len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let mut encoded = Vec::new();
        let limits = BbapiLimits::srs();
        pack_array_header_with_limits(&mut encoded, 1, limits)?;
        pack_array_header_with_limits(&mut encoded, 2, limits)?;
        pack_str_with_limits(&mut encoded, "SrsInitSrs", limits)?;
        pack_map_header_with_limits(&mut encoded, 3, limits)?;
        pack_str_with_limits(&mut encoded, "points_buf", limits)?;
        pack_bin_with_limits(&mut encoded, g1_prefix, limits)?;
        pack_str_with_limits(&mut encoded, "num_points", limits)?;
        pack_uint_with_limits(&mut encoded, profile.num_points, limits)?;
        pack_str_with_limits(&mut encoded, "g2_point", limits)?;
        pack_bin_with_limits(&mut encoded, g2_point, limits)?;

        let message = BbapiMessage::try_from_slice_with_limits(encoded.as_slice(), limits)?;
        if message.as_bytes().len() != encoded.len() {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(Self {
            encoded: Zeroizing::new(encoded),
        })
    }

    /// Borrows the exact encoded command bytes to pass to the linked C ABI.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.encoded.as_slice()
    }
}

impl core::fmt::Debug for BbapiCircuitVerifyCommand {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BbapiCircuitVerifyCommand")
            .field("len", &self.encoded.len())
            .field("encoded", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for BbapiCircuitProveCommand {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BbapiCircuitProveCommand")
            .field("len", &self.encoded.len())
            .field("encoded", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for BbapiSrsInitCommand {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BbapiSrsInitCommand")
            .field("len", &self.encoded.len())
            .field("encoded", &"<redacted>")
            .finish()
    }
}
