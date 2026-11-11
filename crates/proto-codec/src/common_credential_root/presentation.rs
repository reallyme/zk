// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};

mod join_policy;
pub(crate) use join_policy::{
    common_credential_root_join_policy_from_proto, zeroize_common_credential_root_join_policy_proto,
};
pub use join_policy::{
    ZkCommonCredentialRootClaimExpectationOwner, ZkCommonCredentialRootJoinPolicyOwner,
};
use reallyme_zk_api::{
    artifacts::ZkArtifactIdentity,
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootPublicInputs, ZkCommonCredentialRootRawPublicInputs,
        COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::artifact::{
    circuit_ref_to_proto, credential_hash_algorithm_to_proto, proof_suite_to_proto,
};
use crate::binding::session_binding_from_proto_message;
use crate::domain::{
    circuit_ref_from_proto_message, credential_hash_algorithm_from_proto, proof_suite_from_proto,
};

use super::{
    common_credential_root_persona_mode_from_proto, common_credential_root_persona_mode_to_proto,
    common_credential_root_raw_public_inputs_from_proto,
    common_credential_root_raw_public_inputs_to_proto, common_credential_root_slot_from_proto,
    common_credential_root_slot_to_proto,
};

/// Decoded raw proof package for one common-credential-root slot.
pub struct ZkCommonCredentialRootRawProofPackage {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    slot: ZkCommonCredentialRootProofSlot,
    proof_suite: ZkProofSuite,
    artifact_identity: ZkArtifactIdentity,
    proof_bytes: ZkProofBytes,
    public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

impl ZkCommonCredentialRootRawProofPackage {
    /// Builds a strict raw proof package from provider-owned proof output.
    pub fn try_from_parts(
        persona_mode: ZkCommonCredentialRootPersonaMode,
        slot: ZkCommonCredentialRootProofSlot,
        proof_suite: ZkProofSuite,
        artifact_identity: impl Into<ZkArtifactIdentity>,
        proof_bytes: ZkProofBytes,
        public_inputs: ZkCommonCredentialRootRawPublicInputs,
    ) -> Result<Self, ZkError> {
        let expected_ref =
            persona_mode.source_ref(public_inputs.circuit_ref().credential_hash_algorithm, slot);
        if public_inputs.circuit_ref() != expected_ref {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        Ok(Self {
            persona_mode,
            slot,
            proof_suite,
            artifact_identity: artifact_identity.into(),
            proof_bytes,
            public_inputs,
        })
    }

    /// Persona mode selected by the complete common-credential-root persona_mode.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Ordered slot occupied by this proof.
    #[must_use]
    pub const fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    /// Exact proof suite claimed by this proof.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Manifest digest pinned by the proof package.
    #[must_use]
    pub const fn artifact_identity(&self) -> ZkArtifactIdentity {
        self.artifact_identity
    }

    /// Bounded proof bytes.
    #[must_use]
    pub const fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    /// Exact raw public inputs for this slot.
    #[must_use]
    pub const fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        &self.public_inputs
    }

    /// Consumes the package without copying proof or public-input owners.
    #[must_use]
    pub fn into_parts(self) -> (ZkProofBytes, ZkCommonCredentialRootRawPublicInputs) {
        (self.proof_bytes, self.public_inputs)
    }
}

impl core::fmt::Debug for ZkCommonCredentialRootRawProofPackage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootRawProofPackage")
            .field("persona_mode", &self.persona_mode)
            .field("slot", &self.slot)
            .field("proof_suite", &self.proof_suite)
            .field("artifact_identity", &self.artifact_identity)
            .field("proof_len", &self.proof_bytes.as_bytes().len())
            .field("public_inputs", &self.public_inputs)
            .finish()
    }
}

/// Decoded nine-proof common-credential-root presentation in canonical slot order.
pub struct ZkCommonCredentialRootPresentation {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    session_binding: ZkSessionBinding,
    proofs: Vec<ZkCommonCredentialRootRawProofPackage>,
}

impl ZkCommonCredentialRootPresentation {
    /// Builds a complete presentation from provider-owned raw proof packages.
    ///
    /// Providers receive each package from the protobuf operation boundary.
    /// This constructor keeps assembly in the typed owner after that decode
    /// while enforcing the same canonical slot, persona_mode, suite, and binding
    /// checks as the wire decoder.
    pub fn try_from_raw_packages(
        persona_mode: ZkCommonCredentialRootPersonaMode,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proof_suite: ZkProofSuite,
        session_binding: ZkSessionBinding,
        proofs: Vec<ZkCommonCredentialRootRawProofPackage>,
    ) -> Result<Self, ZkError> {
        session_binding.validate_for_circuit(persona_mode.source_ref(
            credential_hash_algorithm,
            ZkCommonCredentialRootProofSlot::Session,
        ))?;
        if proofs.len() < COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT {
            return Err(ZkError::new(ZkErrorReason::MissingStage));
        }
        if proofs.len() > COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT {
            return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
        }
        for (index, proof) in proofs.iter().enumerate() {
            let expected_slot = *ZkCommonCredentialRootProofSlot::ALL
                .get(index)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            if proof.persona_mode() != persona_mode
                || proof.slot() != expected_slot
                || proof
                    .public_inputs()
                    .circuit_ref()
                    .credential_hash_algorithm
                    != credential_hash_algorithm
                || proof.proof_suite() != proof_suite
            {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
        }
        Ok(Self {
            persona_mode,
            credential_hash_algorithm,
            proof_suite,
            session_binding,
            proofs,
        })
    }

    /// Persona mode selected by this presentation.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Exact hash lane shared by every proof package.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Exact proof suite shared by every proof package.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Binding claimed by the presentation envelope.
    #[must_use]
    pub const fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }

    /// Proof packages in canonical common-credential-root slot order.
    #[must_use]
    pub fn proofs(&self) -> &[ZkCommonCredentialRootRawProofPackage] {
        self.proofs.as_slice()
    }

    /// Consume a validated package so the OpenID4VP adapter can retain the
    /// exact proof owners without copying private or proof-bearing buffers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ZkCommonCredentialRootPersonaMode,
        ZkCredentialHashAlgorithm,
        ZkProofSuite,
        ZkSessionBinding,
        Vec<ZkCommonCredentialRootRawProofPackage>,
    ) {
        (
            self.persona_mode,
            self.credential_hash_algorithm,
            self.proof_suite,
            self.session_binding,
            self.proofs,
        )
    }

    /// Borrows the raw public-input streams needed by join validation.
    pub fn public_inputs(&self) -> Result<ZkCommonCredentialRootPublicInputs<'_>, ZkError> {
        let proof = |slot: ZkCommonCredentialRootProofSlot| -> Result<&ZkCommonCredentialRootRawProofPackage, ZkError> {
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

/// Converts a generated common-credential-root presentation into the strict owner.
pub(crate) fn common_credential_root_presentation_from_proto(
    mut presentation: pb::ZkCommonCredentialRootPresentation,
) -> Result<ZkCommonCredentialRootPresentation, ZkError> {
    let persona_mode = common_credential_root_persona_mode_from_proto(presentation.persona_mode)?;
    let credential_hash_algorithm =
        credential_hash_algorithm_from_proto(presentation.credential_hash_algorithm)?;
    let proof_suite = proof_suite_from_proto(presentation.proof_suite)?;
    let session_binding = session_binding_from_proto_message(presentation.session_binding)?;
    session_binding.validate_for_circuit(persona_mode.source_ref(
        credential_hash_algorithm,
        ZkCommonCredentialRootProofSlot::Session,
    ))?;

    if presentation.proofs.len() < COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT {
        return Err(ZkError::new(ZkErrorReason::MissingStage));
    }
    if presentation.proofs.len() > COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT {
        return Err(ZkError::new(ZkErrorReason::InvalidClaimProofBundle));
    }

    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for (index, proof) in presentation.proofs.drain(..).enumerate() {
        let expected_slot = *ZkCommonCredentialRootProofSlot::ALL
            .get(index)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let proof = common_credential_root_raw_proof_package_from_proto(proof)?;
        if proof.persona_mode() != persona_mode
            || proof.slot() != expected_slot
            || proof
                .public_inputs()
                .circuit_ref()
                .credential_hash_algorithm
                != credential_hash_algorithm
            || proof.proof_suite() != proof_suite
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        proofs.push(proof);
    }

    Ok(ZkCommonCredentialRootPresentation {
        persona_mode,
        credential_hash_algorithm,
        proof_suite,
        session_binding,
        proofs,
    })
}

/// Converts one generated raw common-credential-root proof package into the strict owner.
pub(crate) fn common_credential_root_raw_proof_package_from_proto(
    mut package: pb::ZkCommonCredentialRootRawProofPackage,
) -> Result<ZkCommonCredentialRootRawProofPackage, ZkError> {
    let persona_mode = common_credential_root_persona_mode_from_proto(package.persona_mode)?;
    let slot = common_credential_root_slot_from_proto(package.slot)?;
    let circuit_ref = circuit_ref_from_proto_message(core::mem::take(&mut package.circuit_ref))?;
    if persona_mode.source_ref(circuit_ref.credential_hash_algorithm, slot) != circuit_ref {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let proof_suite = proof_suite_from_proto(package.proof_suite)?;
    let artifact_identity = crate::artifact_identity::common_root_identity_from_proto(
        package.artifact_identity.take(),
    )?;
    let public_inputs = package
        .public_inputs
        .take()
        .ok_or(ZkError::new(ZkErrorReason::EmptyInput))?;
    let public_inputs = common_credential_root_raw_public_inputs_from_proto(public_inputs)?;
    if public_inputs.persona_mode() != persona_mode
        || public_inputs.slot() != slot
        || public_inputs.public_inputs().circuit_ref() != circuit_ref
    {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }
    let proof_bytes = ZkProofBytes::try_from_bytes(core::mem::take(&mut package.proof))?;
    Ok(ZkCommonCredentialRootRawProofPackage {
        persona_mode,
        slot,
        proof_suite,
        artifact_identity,
        proof_bytes,
        public_inputs: public_inputs.into_public_inputs(),
    })
}

/// Converts one strict raw proof package to generated protobuf.
pub fn common_credential_root_raw_proof_package_to_proto(
    package: &ZkCommonCredentialRootRawProofPackage,
) -> Result<pb::ZkCommonCredentialRootRawProofPackage, ZkError> {
    Ok(pb::ZkCommonCredentialRootRawProofPackage {
        persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto(
            package.persona_mode(),
        )),
        slot: EnumValue::from(common_credential_root_slot_to_proto(package.slot())),
        circuit_ref: MessageField::some(circuit_ref_to_proto(
            package.public_inputs().circuit_ref(),
        )),
        proof: package.proof_bytes().as_bytes().to_vec(),
        public_inputs: MessageField::some(common_credential_root_raw_public_inputs_to_proto(
            package.persona_mode(),
            package.slot(),
            package.public_inputs(),
        )?),
        artifact_identity: Some(crate::artifact_identity::common_root_identity_to_proto(
            package.artifact_identity(),
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(package.proof_suite())),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Converts a strict common-credential-root presentation to generated protobuf.
pub fn common_credential_root_presentation_to_proto(
    presentation: &ZkCommonCredentialRootPresentation,
) -> Result<pb::ZkCommonCredentialRootPresentation, ZkError> {
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(presentation.proofs().len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for proof in presentation.proofs() {
        proofs.push(common_credential_root_raw_proof_package_to_proto(proof)?);
    }
    Ok(pb::ZkCommonCredentialRootPresentation {
        persona_mode: EnumValue::from(common_credential_root_persona_mode_to_proto(
            presentation.persona_mode(),
        )),
        credential_hash_algorithm: EnumValue::from(credential_hash_algorithm_to_proto(
            presentation.credential_hash_algorithm(),
        )),
        proof_suite: EnumValue::from(proof_suite_to_proto(presentation.proof_suite())),
        session_binding: MessageField::some(crate::binding::session_binding_to_proto_message(
            presentation.session_binding(),
        )),
        proofs,
        __buffa_unknown_fields: Default::default(),
    })
}

/// Converts a strict common-credential-root persona_mode to generated protobuf.
#[must_use]
pub fn common_credential_root_persona_mode_to_proto_public(
    persona_mode: ZkCommonCredentialRootPersonaMode,
) -> pb::ZkCommonCredentialRootPersonaMode {
    common_credential_root_persona_mode_to_proto(persona_mode)
}
