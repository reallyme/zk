// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Backend-neutral verification boundary for common-credential-root presentations.
//
// The common-credential-root persona_mode is intentionally not modeled as a production
// `ZkClaimProofBundle`: it has nine ordered proof slots, two selected credentials,
// and verifier-owned attestation/status policy. This module gives SDKs and
// OpenID4VP adapters one typed request that concrete providers can verify
// without importing platform FFI or Barretenberg-specific crates.

use crate::{common_root::{check_common_credential_root_v1_joins, ZkCommonCredentialRootJoinPolicy, ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootPublicInputs, ZkCommonCredentialRootRawPublicInputs, COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT}, artifacts::{ZkArtifactIdentity}, circuits::{ZkCredentialHashAlgorithm}, errors::{ZkError, ZkErrorReason}, proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding}};

const PUBLIC_INPUT_FIELD_BYTES: usize = 32;
const PRIVATE_SESSION_EXPIRY_FIELD: usize = 96;
const PUBLIC_SESSION_EXPIRY_FIELD: usize = 160;
const UNIX_TIME_BYTES: usize = 8;

/// One raw proof package in a complete common-credential-root presentation.
pub struct ZkCommonCredentialRootProof {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    proof_suite: ZkProofSuite,
    artifact_identity: ZkArtifactIdentity,
    proof_bytes: ZkProofBytes,
    public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

impl ZkCommonCredentialRootProof {
    /// Builds a bounded proof package for one canonical common-credential-root slot.
    pub fn try_from_parts(
        persona_mode: ZkCommonCredentialRootPersonaMode,
        slot: ZkCommonCredentialRootProofSlot,
        proof_suite: ZkProofSuite,
        artifact_identity: impl Into<ZkArtifactIdentity>,
        proof_bytes: ZkProofBytes,
        public_inputs: ZkCommonCredentialRootRawPublicInputs,
    ) -> Result<Self, ZkError> {
        let artifact_identity = artifact_identity.into();
        let expected_ref =
            persona_mode.source_ref(public_inputs.circuit_ref().credential_hash_algorithm, slot);
        if public_inputs.circuit_ref() != expected_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if artifact_identity.is_zero() {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            persona_mode,
            slot,
            proof_suite,
            artifact_identity,
            proof_bytes,
            public_inputs,
        })
    }

    /// Persona mode shared by the complete presentation.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Ordered proof slot.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Proof-system suite claimed by this proof.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Artifact-manifest identity claimed by this proof.
    #[must_use]
    pub const fn artifact_identity(&self) -> ZkArtifactIdentity {
        self.artifact_identity
    }

    /// Bounded proof bytes for the injected backend.
    #[must_use]
    pub const fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    /// Raw public-input stream for this exact slot ABI.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        &self.public_inputs
    }
}

impl core::fmt::Debug for ZkCommonCredentialRootProof {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootProof")
            .field("persona_mode", &self.persona_mode)
            .field("slot", &self.slot)
            .field("proof_suite", &self.proof_suite)
            .field("artifact_identity", &self.artifact_identity)
            .field("proof_len", &self.proof_bytes.as_bytes().len())
            .field("public_inputs", &self.public_inputs)
            .finish()
    }
}

/// Complete verifier request for a common-credential-root v1 presentation.
#[derive(Clone, Copy)]
pub struct ZkCommonCredentialRootVerifyRequest<'a> {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
    expected_proof_suite: ZkProofSuite,
    session_binding: ZkSessionBinding,
    proofs: &'a [ZkCommonCredentialRootProof],
    join_policy: ZkCommonCredentialRootJoinPolicy<'a>,
}

impl core::fmt::Debug for ZkCommonCredentialRootVerifyRequest<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootVerifyRequest")
            .field("persona_mode", &self.persona_mode)
            .field(
                "expected_credential_hash_algorithm",
                &self.expected_credential_hash_algorithm,
            )
            .field("expected_proof_suite", &self.expected_proof_suite)
            .field("proof_count", &self.proofs.len())
            .field("session_binding", &"<redacted>")
            .field("join_policy", &"<redacted>")
            .finish()
    }
}

impl<'a> ZkCommonCredentialRootVerifyRequest<'a> {
    /// Builds a fail-closed common-credential-root verification request.
    pub fn try_new(
        persona_mode: ZkCommonCredentialRootPersonaMode,
        expected_credential_hash_algorithm: ZkCredentialHashAlgorithm,
        expected_proof_suite: ZkProofSuite,
        session_binding: ZkSessionBinding,
        proofs: &'a [ZkCommonCredentialRootProof],
        join_policy: ZkCommonCredentialRootJoinPolicy<'a>,
    ) -> Result<Self, ZkError> {
        expected_proof_suite.require_production()?;
        if proofs.len() != COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT {
            return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
        }
        validate_persona_mode_policy(persona_mode, join_policy.persona_mode)?;
        if session_binding.nonce_hash != join_policy.challenge
            || session_binding.audience_hash != join_policy.audience_hash
            || session_binding.transaction_data_public_input() != join_policy.transaction_data_hash
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        for (index, proof) in proofs.iter().enumerate() {
            let expected_slot = *ZkCommonCredentialRootProofSlot::ALL
                .get(index)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let expected_ref =
                persona_mode.source_ref(expected_credential_hash_algorithm, expected_slot);
            if proof.persona_mode() != persona_mode
                || proof.slot() != expected_slot
                || proof.proof_suite() != expected_proof_suite
                || proof.public_inputs().circuit_ref() != expected_ref
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
        }
        Ok(Self {
            persona_mode,
            expected_credential_hash_algorithm,
            expected_proof_suite,
            session_binding,
            proofs,
            join_policy,
        })
    }

    /// Persona mode being verified.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Hash lane selected by verifier policy for the whole presentation.
    #[must_use]
    pub const fn expected_credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.expected_credential_hash_algorithm
    }

    /// Exact suite selected by verifier policy.
    #[must_use]
    pub const fn expected_proof_suite(&self) -> ZkProofSuite {
        self.expected_proof_suite
    }

    /// Active OpenID4VP/session binding expected by policy.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }

    /// Canonically ordered proof packages.
    #[must_use]
    pub const fn proofs(&self) -> &'a [ZkCommonCredentialRootProof] {
        self.proofs
    }

    /// Verifier-owned join and attestation/status policy.
    #[must_use]
    pub const fn join_policy(&self) -> ZkCommonCredentialRootJoinPolicy<'a> {
        self.join_policy
    }

    /// Decode the exact session-expiry field before accepting a presentation.
    ///
    /// This parser is a fail-closed policy precheck. The result becomes
    /// authenticated only after every proof and the ordered joins verify.
    pub fn session_expiry_unix(&self) -> Result<u64, ZkError> {
        let session = self
            .proofs
            .get(usize::from(
                ZkCommonCredentialRootProofSlot::Session.index(),
            ))
            .filter(|proof| proof.slot() == ZkCommonCredentialRootProofSlot::Session)
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
        let field_index = match self.persona_mode {
            ZkCommonCredentialRootPersonaMode::PrivatePersona => PRIVATE_SESSION_EXPIRY_FIELD,
            ZkCommonCredentialRootPersonaMode::PublicPersona => PUBLIC_SESSION_EXPIRY_FIELD,
        };
        let start = field_index
            .checked_mul(PUBLIC_INPUT_FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let end = start
            .checked_add(PUBLIC_INPUT_FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let field = session
            .public_inputs()
            .as_bytes()
            .get(start..end)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        let prefix_bytes = PUBLIC_INPUT_FIELD_BYTES
            .checked_sub(UNIX_TIME_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        if field
            .get(..prefix_bytes)
            .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        let tail = <[u8; UNIX_TIME_BYTES]>::try_from(
            field
                .get(prefix_bytes..)
                .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
        )
        .map_err(|_| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        Ok(u64::from_be_bytes(tail))
    }

    /// Borrows the raw public-input streams consumed by join verification.
    pub fn public_inputs(&self) -> Result<ZkCommonCredentialRootPublicInputs<'_>, ZkError> {
        let proof = |slot: ZkCommonCredentialRootProofSlot| -> Result<&ZkCommonCredentialRootProof, ZkError> {
            self.proofs
                .get(usize::from(slot.index()))
                .filter(|proof| proof.slot() == slot)
                .ok_or(ZkError::new(ZkErrorReason::MissingStage))
        };
        Ok(ZkCommonCredentialRootPublicInputs {
            attestation: proof(ZkCommonCredentialRootProofSlot::RootAttestation)?
                .public_inputs()
                .as_bytes(),
            status: proof(ZkCommonCredentialRootProofSlot::RootStatus)?
                .public_inputs()
                .as_bytes(),
            lineage: [
                proof(ZkCommonCredentialRootProofSlot::Lineage0)?
                    .public_inputs()
                    .as_bytes(),
                proof(ZkCommonCredentialRootProofSlot::Lineage1)?
                    .public_inputs()
                    .as_bytes(),
            ],
            selected_claim: [
                proof(ZkCommonCredentialRootProofSlot::SelectedClaim0)?
                    .public_inputs()
                    .as_bytes(),
                proof(ZkCommonCredentialRootProofSlot::SelectedClaim1)?
                    .public_inputs()
                    .as_bytes(),
            ],
            session: proof(ZkCommonCredentialRootProofSlot::Session)?
                .public_inputs()
                .as_bytes(),
            issuer_credential_status: [
                proof(ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0)?
                    .public_inputs()
                    .as_bytes(),
                proof(ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1)?
                    .public_inputs()
                    .as_bytes(),
            ],
        })
    }
}
