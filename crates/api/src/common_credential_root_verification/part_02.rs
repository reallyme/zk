// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Successful common-credential-root verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootVerification {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    verified_proof_count: u8,
    proof_suite: ZkProofSuite,
}

impl ZkCommonCredentialRootVerification {
    /// Minted only after proof evidence and join policy both verify.
    #[must_use]
    const fn from_verified(
        persona_mode: ZkCommonCredentialRootPersonaMode,
        verified_proof_count: u8,
        proof_suite: ZkProofSuite,
    ) -> Self {
        Self {
            persona_mode,
            verified_proof_count,
            proof_suite,
        }
    }

    /// Verified common-credential-root persona_mode.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Number of proofs checked by the injected backend.
    #[must_use]
    pub const fn verified_proof_count(&self) -> u8 {
        self.verified_proof_count
    }

    /// Verified proof suite.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }
}

fn validate_persona_mode_policy(
    presentation_mode: ZkCommonCredentialRootPersonaMode,
    policy_mode: ZkCommonCredentialRootPersonaMode,
) -> Result<(), ZkError> {
    if presentation_mode == policy_mode {
        Ok(())
    } else {
        Err(ZkError::new(ZkErrorReason::BindingMismatch))
    }
}

/// Verifier boundary for complete common-credential-root presentations.
pub trait ZkCommonCredentialRootVerifier: Send + Sync {
    /// Verifies all nine proofs against exact artifacts and verification keys.
    fn verify_common_credential_root_evidence(
        &self,
        request: &ZkCommonCredentialRootVerifyRequest<'_>,
    ) -> Result<(), ZkError>;
}

/// Verifies proof evidence, checks joins, and mints the verified result.
pub fn verify_common_credential_root_with(
    verifier: &dyn ZkCommonCredentialRootVerifier,
    request: ZkCommonCredentialRootVerifyRequest<'_>,
) -> Result<ZkCommonCredentialRootVerification, ZkError> {
    verifier.verify_common_credential_root_evidence(&request)?;
    check_common_credential_root_v1_joins(request.public_inputs()?, request.join_policy())?;
    let verified_proof_count = u8::try_from(request.proofs().len())
        .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
    Ok(ZkCommonCredentialRootVerification::from_verified(
        request.persona_mode(),
        verified_proof_count,
        request.expected_proof_suite(),
    ))
}
