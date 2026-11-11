// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared BBAPI raw-field framing after each profile validates its own ABI.

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    common_root::ZkCommonCredentialRootRawPublicInputs,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::ZkPersonaCredentialEvidenceRawPublicInputs,
    proofs::{ZkProofBytes, ZkProofSuite},
};
use reallyme_zk_artifacts::{ArtifactKind, VerifiedArtifactBytes};
use zeroize::Zeroizing;

use super::{validate_expected_proof_len, BbapiCircuitVerifyCommand};
use crate::bbapi_abi::{
    message::{BbapiLimits, BbapiMessage},
    pack::{
        pack_array_header, pack_bin, pack_field_vector, pack_map_header, pack_str,
        pack_verify_settings,
    },
};

impl BbapiCircuitVerifyCommand {
    /// Builds a verify command for common-credential-root raw public inputs.
    pub(crate) fn try_new_raw_common_credential_root(
        verification_key: &VerifiedArtifactBytes,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        proof_bytes: &ZkProofBytes,
        public_inputs: &ZkCommonCredentialRootRawPublicInputs,
    ) -> Result<Self, ZkError> {
        if public_inputs.circuit_ref() != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Self::try_new_raw_fields(
            verification_key,
            circuit_ref,
            proof_suite,
            proof_bytes,
            public_inputs.as_bytes(),
        )
    }

    /// Builds a verify command from the separately validated prepared ABI.
    pub(crate) fn try_new_raw_prepared(
        verification_key: &VerifiedArtifactBytes,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        proof_bytes: &ZkProofBytes,
        public_inputs: &ZkPersonaCredentialEvidenceRawPublicInputs,
    ) -> Result<Self, ZkError> {
        if public_inputs.circuit_ref() != circuit_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Self::try_new_raw_fields(
            verification_key,
            circuit_ref,
            proof_suite,
            proof_bytes,
            public_inputs.as_bytes(),
        )
    }

    fn try_new_raw_fields(
        verification_key: &VerifiedArtifactBytes,
        circuit_ref: ZkCircuitRef,
        proof_suite: ZkProofSuite,
        proof_bytes: &ZkProofBytes,
        public_inputs: &[u8],
    ) -> Result<Self, ZkError> {
        if verification_key.kind() != ArtifactKind::VerificationKey {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if proof_suite != ZkProofSuite::PRODUCTION {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        // Raw lanes pin the exact production proof length per circuit, as the
        // staged lane does, before any bytes reach the backend.
        validate_expected_proof_len(circuit_ref, proof_bytes.as_bytes().len())?;

        let mut encoded = Zeroizing::new(Vec::new());
        pack_array_header(&mut encoded, 1)?;
        pack_array_header(&mut encoded, 2)?;
        pack_str(&mut encoded, "CircuitVerify")?;
        pack_map_header(&mut encoded, 4)?;
        pack_str(&mut encoded, "verification_key")?;
        pack_bin(&mut encoded, verification_key.as_bytes())?;
        pack_str(&mut encoded, "public_inputs")?;
        pack_field_vector(&mut encoded, public_inputs)?;
        pack_str(&mut encoded, "proof")?;
        pack_field_vector(&mut encoded, proof_bytes.as_bytes())?;
        pack_str(&mut encoded, "settings")?;
        pack_verify_settings(&mut encoded, BbapiLimits::standard())?;

        let message = BbapiMessage::try_from_slice(encoded.as_slice())?;
        if message.as_bytes().len() != encoded.len() {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(Self { encoded })
    }
}
