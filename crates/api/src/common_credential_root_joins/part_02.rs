// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Typed composer for request-bound common-credential-root stage inputs.
///
/// This is the production boundary between wallet policy and platform/protobuf
/// encoding. A caller should create exactly one composer for an authenticated
/// OpenID4VP request, combine its output with issuer-signed credential witness
/// material, and then pass the encoded operation to the concrete prover.
pub struct ZkCommonCredentialRootStageInputComposer {
    request: ZkCommonCredentialRootRequestJoinContext,
    joins: ZkCommonCredentialRootPresentationJoins,
    salt_owner: ZkCommonCredentialRootStageSaltOwner,
}

impl ZkCommonCredentialRootStageInputComposer {
    /// Composes one slot's request binding, public joins, and private salt handle.
    pub fn compose_stage(
        &mut self,
        slot: ZkCommonCredentialRootProofSlot,
    ) -> Result<ZkCommonCredentialRootStageInputMaterial, ZkCommonCredentialRootStageInputError>
    {
        match slot {
            ZkCommonCredentialRootProofSlot::RootAttestation => {
                Ok(ZkCommonCredentialRootStageInputMaterial::RootAttestation(
                    ZkCommonCredentialRootRootStageInput {
                        request: self.request,
                        root_join: self.joins.root_join,
                        attestation_join: self.joins.attestation_join,
                        join_salt: self.stage_salt(slot)?,
                    },
                ))
            }
            ZkCommonCredentialRootProofSlot::RootStatus => {
                Ok(ZkCommonCredentialRootStageInputMaterial::RootStatus(
                    ZkCommonCredentialRootRootStageInput {
                        request: self.request,
                        root_join: self.joins.root_join,
                        attestation_join: self.joins.attestation_join,
                        join_salt: self.stage_salt(slot)?,
                    },
                ))
            }
            ZkCommonCredentialRootProofSlot::Lineage0
            | ZkCommonCredentialRootProofSlot::Lineage1 => {
                let credential_index = credential_slot_index(slot)?;
                Ok(ZkCommonCredentialRootStageInputMaterial::Lineage(
                    ZkCommonCredentialRootLineageStageInput {
                        slot,
                        credential_index,
                        request: self.request,
                        root_join: self.joins.root_join,
                        subject_join: self.joins.subject_joins[credential_index],
                        join_salt: self.stage_salt(slot)?,
                    },
                ))
            }
            ZkCommonCredentialRootProofSlot::SelectedClaim0
            | ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
                let credential_index = credential_slot_index(slot)?;
                Ok(ZkCommonCredentialRootStageInputMaterial::SelectedClaim(
                    ZkCommonCredentialRootSelectedClaimStageInput {
                        slot,
                        credential_index,
                        request: self.request,
                        subject_join: self.joins.subject_joins[credential_index],
                        join_salt: self.stage_salt(slot)?,
                    },
                ))
            }
            ZkCommonCredentialRootProofSlot::Session => {
                Ok(ZkCommonCredentialRootStageInputMaterial::Session(
                    ZkCommonCredentialRootSessionStageInput {
                        request: self.request,
                    },
                ))
            }
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0
            | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => Ok(
                ZkCommonCredentialRootStageInputMaterial::IssuerCredentialStatus(
                    ZkCommonCredentialRootIssuerCredentialStatusStageInput {
                        slot,
                        credential_index: credential_slot_index(slot)?,
                        request: self.request,
                    },
                ),
            ),
        }
    }

    /// Finishes the composer after all salt-bearing stages have been composed.
    pub fn finish(self) -> Result<(), ZkCommonCredentialRootStageInputError> {
        self.salt_owner.finish()?;
        Ok(())
    }

    fn stage_salt(
        &mut self,
        slot: ZkCommonCredentialRootProofSlot,
    ) -> Result<ZkCommonCredentialRootStageJoinSalt, ZkCommonCredentialRootStageInputError> {
        let mut bytes = Zeroizing::new([0_u8; JOIN_SALT_BYTES]);
        self.salt_owner
            .copy_for_stage_witness(slot, self.request, &mut bytes)?;
        Ok(ZkCommonCredentialRootStageJoinSalt { bytes: Some(bytes) })
    }
}

/// Request-bound common-credential-root material for one proof slot.
pub enum ZkCommonCredentialRootStageInputMaterial {
    /// Root-attestation stage binding.
    RootAttestation(ZkCommonCredentialRootRootStageInput),
    /// Active-status stage binding.
    RootStatus(ZkCommonCredentialRootRootStageInput),
    /// Credential lineage stage binding.
    Lineage(ZkCommonCredentialRootLineageStageInput),
    /// Selected-claim stage binding.
    SelectedClaim(ZkCommonCredentialRootSelectedClaimStageInput),
    /// Persona session stage binding.
    Session(ZkCommonCredentialRootSessionStageInput),
    /// Issuer-signed credential validity and current status stage binding.
    IssuerCredentialStatus(ZkCommonCredentialRootIssuerCredentialStatusStageInput),
}

impl ZkCommonCredentialRootStageInputMaterial {
    /// Returns this material's canonical proof slot.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        match self {
            Self::RootAttestation(_) => ZkCommonCredentialRootProofSlot::RootAttestation,
            Self::RootStatus(_) => ZkCommonCredentialRootProofSlot::RootStatus,
            Self::Lineage(input) => input.slot,
            Self::SelectedClaim(input) => input.slot,
            Self::Session(_) => ZkCommonCredentialRootProofSlot::Session,
            Self::IssuerCredentialStatus(input) => input.slot,
        }
    }

    /// Returns the active request binding carried by this stage material.
    #[must_use]
    pub const fn request(&self) -> ZkCommonCredentialRootRequestJoinContext {
        match self {
            Self::RootAttestation(input) | Self::RootStatus(input) => input.request,
            Self::Lineage(input) => input.request,
            Self::SelectedClaim(input) => input.request,
            Self::Session(input) => input.request,
            Self::IssuerCredentialStatus(input) => input.request,
        }
    }
}

/// One-shot private join salt for a composed stage.
pub struct ZkCommonCredentialRootStageJoinSalt {
    bytes: Option<Zeroizing<[u8; JOIN_SALT_BYTES]>>,
}

impl ZkCommonCredentialRootStageJoinSalt {
    /// Copies the stage salt into a platform witness field once.
    pub fn copy_once(
        &mut self,
        destination: &mut [u8; JOIN_SALT_BYTES],
    ) -> Result<(), ZkCommonCredentialRootStageSaltError> {
        let Some(bytes) = self.bytes.take() else {
            return Err(ZkCommonCredentialRootStageSaltError::ReusedSlot);
        };
        destination.copy_from_slice(bytes.as_ref());
        Ok(())
    }
}

/// Root-attestation or active-status stage request binding.
pub struct ZkCommonCredentialRootRootStageInput {
    /// Active request binding context.
    request: ZkCommonCredentialRootRequestJoinContext,
    /// Public join shared by root assurance, status, and lineage stages.
    root_join: [u8; 32],
    /// Public join shared by root attestation and status stages.
    attestation_join: [u8; 32],
    /// Private one-shot salt for this stage witness.
    join_salt: ZkCommonCredentialRootStageJoinSalt,
}

impl ZkCommonCredentialRootRootStageInput {
    /// Returns the active request binding context.
    #[must_use]
    pub const fn request(&self) -> ZkCommonCredentialRootRequestJoinContext {
        self.request
    }

    /// Returns the public root join.
    #[must_use]
    pub const fn root_join(&self) -> [u8; 32] {
        self.root_join
    }

    /// Returns the public attestation join.
    #[must_use]
    pub const fn attestation_join(&self) -> [u8; 32] {
        self.attestation_join
    }

    /// Copies this stage's private salt into a platform witness field once.
    pub fn copy_join_salt_once(
        &mut self,
        destination: &mut [u8; 32],
    ) -> Result<(), ZkCommonCredentialRootStageSaltError> {
        self.join_salt.copy_once(destination)
    }
}

/// Credential-lineage stage request binding.
pub struct ZkCommonCredentialRootLineageStageInput {
    /// Slot being composed.
    slot: ZkCommonCredentialRootProofSlot,
    /// Credential-role index selected by the verifier.
    credential_index: usize,
    /// Active request binding context.
    request: ZkCommonCredentialRootRequestJoinContext,
    /// Public join shared by root assurance, status, and lineage stages.
    root_join: [u8; 32],
    /// Public join binding this lineage proof to its selected-claim proof.
    subject_join: [u8; 32],
    /// Private one-shot salt for this stage witness.
    join_salt: ZkCommonCredentialRootStageJoinSalt,
}

impl ZkCommonCredentialRootLineageStageInput {
    /// Returns this lineage proof slot.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Returns the verifier-selected credential role index.
    #[must_use]
    pub const fn credential_index(&self) -> usize {
        self.credential_index
    }

    /// Returns the active request binding context.
    #[must_use]
    pub const fn request(&self) -> ZkCommonCredentialRootRequestJoinContext {
        self.request
    }

    /// Returns the public root join.
    #[must_use]
    pub const fn root_join(&self) -> [u8; 32] {
        self.root_join
    }

    /// Returns the public subject join for this credential role.
    #[must_use]
    pub const fn subject_join(&self) -> [u8; 32] {
        self.subject_join
    }

    /// Copies this stage's private salt into a platform witness field once.
    pub fn copy_join_salt_once(
        &mut self,
        destination: &mut [u8; 32],
    ) -> Result<(), ZkCommonCredentialRootStageSaltError> {
        self.join_salt.copy_once(destination)
    }
}

/// Selected-claim stage request binding.
pub struct ZkCommonCredentialRootSelectedClaimStageInput {
    /// Slot being composed.
    slot: ZkCommonCredentialRootProofSlot,
    /// Credential-role index selected by the verifier.
    credential_index: usize,
    /// Active request binding context.
    request: ZkCommonCredentialRootRequestJoinContext,
    /// Public join binding this selected claim to its lineage proof.
    subject_join: [u8; 32],
    /// Private one-shot salt for this stage witness.
    join_salt: ZkCommonCredentialRootStageJoinSalt,
}

impl ZkCommonCredentialRootSelectedClaimStageInput {
    /// Returns this selected-claim proof slot.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Returns the verifier-selected credential role index.
    #[must_use]
    pub const fn credential_index(&self) -> usize {
        self.credential_index
    }

    /// Returns the active request binding context.
    #[must_use]
    pub const fn request(&self) -> ZkCommonCredentialRootRequestJoinContext {
        self.request
    }

    /// Returns the public subject join for this credential role.
    #[must_use]
    pub const fn subject_join(&self) -> [u8; 32] {
        self.subject_join
    }

    /// Copies this stage's private salt into a platform witness field once.
    pub fn copy_join_salt_once(
        &mut self,
        destination: &mut [u8; 32],
    ) -> Result<(), ZkCommonCredentialRootStageSaltError> {
        self.join_salt.copy_once(destination)
    }
}

/// Persona-session stage request binding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootSessionStageInput {
    /// Active request binding context.
    request: ZkCommonCredentialRootRequestJoinContext,
}

/// Request and credential-role binding for an issuer credential-status proof.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootIssuerCredentialStatusStageInput {
    slot: ZkCommonCredentialRootProofSlot,
    credential_index: usize,
    request: ZkCommonCredentialRootRequestJoinContext,
}

impl ZkCommonCredentialRootIssuerCredentialStatusStageInput {
    /// Canonical proof slot.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Verifier-selected credential role.
    #[must_use]
    pub const fn credential_index(&self) -> usize {
        self.credential_index
    }

    /// Authenticated presentation request binding.
    #[must_use]
    pub const fn request(&self) -> ZkCommonCredentialRootRequestJoinContext {
        self.request
    }
}

impl ZkCommonCredentialRootSessionStageInput {
    /// Returns the active request binding context.
    #[must_use]
    pub const fn request(&self) -> ZkCommonCredentialRootRequestJoinContext {
        self.request
    }
}
