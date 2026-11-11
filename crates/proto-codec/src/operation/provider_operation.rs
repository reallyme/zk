// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleWitness,
        ZkStatusQualifiedClaimProofBundle,
    },
    issuer_status::ZkIssuerStatusFeed,
    keys::ZkIssuerPublicKey,
    persona_evidence::ZkPersonaCredentialEvidenceStageProof,
    proofs::{ZkProof, ZkProofSuite, ZkPublicInputs, ZkSessionBinding, ZkWitness},
};

use super::persona_credential_evidence::{
    ZkPersonaCredentialEvidenceCurrentStateProveRequest,
    ZkPersonaCredentialEvidencePresentationInput,
    ZkPersonaCredentialEvidenceSelectedClaimProveRequest,
};
use crate::common_credential_root::{
    ZkCommonCredentialRootJoinPolicyOwner, ZkCommonCredentialRootPresentation,
    ZkCommonCredentialRootWitnessPlan,
};

use super::{
    ZkCommonCredentialRootStageInputOwner, ZkCommonCredentialRootStageProveRequest,
    ZkNativeStageWitnessHandle, ZkStageWitnessInputOwner, ZkStageWitnessSource,
};

/// A validated provider operation ready for dispatch to an injected backend.
///
/// This enum intentionally does not implement `Debug` or `Clone`: proving
/// variants own a zeroizing witness and must not acquire accidental copies or
/// log representations.
pub enum ZkProviderOperation {
    /// Prove all required production stages for one profile.
    ProveClaimProofBundle {
        /// Stable production profile.
        bundle_kind: ZkClaimProofBundleKind,
        /// Exact circuit hash family.
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
        /// Secret witness owner.
        witness_bundle: ZkClaimProofBundleWitness,
        /// Active presentation binding.
        session_binding: ZkSessionBinding,
    },
    /// Prove all required production stages from native-owned witnesses.
    ProveRetainedClaimProofBundle {
        /// Stable production profile.
        bundle_kind: ZkClaimProofBundleKind,
        /// Exact circuit hash family.
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
        /// Native-owned secret witness handles in canonical stage order.
        witness_handles: Vec<ZkNativeStageWitnessHandle>,
        /// Active presentation binding.
        session_binding: ZkSessionBinding,
    },
    /// Verify a complete production proof bundle.
    VerifyClaimProofBundle {
        /// Validated proof bundle.
        claim_proof_bundle: ZkClaimProofBundle,
        /// Exact suite selected by verifier policy.
        expected_proof_suite: ZkProofSuite,
        /// Binding supplied by the active verifier session.
        expected_binding: ZkSessionBinding,
        /// Bounded exact issuer trust policy.
        trusted_issuers: Vec<ZkIssuerPublicKey>,
        /// Trusted verifier clock as a Unix timestamp.
        verification_time_unix: u64,
    },
    /// Verify four claim proofs, the issuer validity and current-status
    /// proof, and the verifier's authenticated current issuer status list.
    VerifyStatusQualifiedClaimProofBundle {
        /// Joined claim bundle and issuer-credential-status proof.
        status_qualified_claim_proof_bundle: Box<ZkStatusQualifiedClaimProofBundle>,
        /// Exact suite selected by verifier policy.
        expected_proof_suite: ZkProofSuite,
        /// Binding supplied by the active verifier session.
        expected_binding: ZkSessionBinding,
        /// Bounded exact issuer trust policy.
        trusted_issuers: Vec<ZkIssuerPublicKey>,
        /// Trusted verifier clock as a Unix timestamp.
        verification_time_unix: u64,
        /// Current issuer status list authenticated by the verifier.
        current_issuer_status: ZkIssuerStatusFeed,
        /// Credential issuer for which the current status feed was authenticated.
        expected_issuer: ZkIssuerPublicKey,
    },
    /// Prove one exact stage for diagnostics and circuit iteration.
    ProveStage {
        /// Exact imported source circuit.
        circuit_ref: ZkCircuitRef,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
        /// Secret witness source.
        witness_source: ZkStageWitnessSource,
        /// Canonical compact public inputs.
        public_inputs: ZkPublicInputs,
        /// Active presentation binding.
        session_binding: ZkSessionBinding,
    },
    /// Verify one exact stage.
    VerifyStage {
        /// Validated exact proof package.
        proof: ZkProof,
        /// Exact suite selected by verifier policy.
        expected_proof_suite: ZkProofSuite,
        /// Binding supplied by the active verifier session.
        expected_binding: ZkSessionBinding,
    },
    /// Resolve one exact artifact manifest.
    GetArtifactManifest {
        /// Exact imported source circuit.
        circuit_ref: ZkCircuitRef,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
    },
    /// Generate and retain one native-owned stage witness.
    WitnessStage {
        /// Exact imported source circuit.
        circuit_ref: ZkCircuitRef,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
        /// Fixed-schema generated stage input message.
        input: ZkStageWitnessInputOwner,
    },
    /// Release one native-owned witness without proving it.
    ReleaseStageWitness {
        /// Opaque native context handle.
        witness_handle: ZkNativeStageWitnessHandle,
    },
    /// Verify a complete nine-proof common-credential-root v1 presentation.
    VerifyCommonCredentialRoot {
        /// Validated raw common-credential-root proof presentation.
        presentation: Box<ZkCommonCredentialRootPresentation>,
        /// Verifier-owned active request and trust policy.
        join_policy: Box<ZkCommonCredentialRootJoinPolicyOwner>,
        /// Exact suite selected by verifier policy.
        expected_proof_suite: ZkProofSuite,
    },
    /// Prove one exact common-credential-root source stage from typed private inputs.
    ProveCommonCredentialRootStage {
        /// Canonical common-credential-root source-circuit plan.
        plan: ZkCommonCredentialRootWitnessPlan,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
        /// Secret generated input owner.
        input: ZkCommonCredentialRootStageInputOwner,
        /// Active presentation binding supplied by the SDK request.
        expected_binding: ZkSessionBinding,
    },
    /// Prove every common-credential-root v1 source stage and assemble a presentation.
    ProveCommonCredentialRootPresentation {
        /// Persona profile shared by all nine stages.
        persona_mode: reallyme_zk_api::common_root::ZkCommonCredentialRootPersonaMode,
        /// Exact hash lane shared by all nine source circuits.
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        /// Exact transcript and witness-masking suite.
        proof_suite: ZkProofSuite,
        /// Active presentation binding supplied by the SDK request.
        expected_binding: ZkSessionBinding,
        /// Secret fixed-slot stage requests in canonical proof-slot order.
        stages: Vec<ZkCommonCredentialRootStageProveRequest>,
    },
    /// Verify one prepared stage under its sealed exact-circuit VK. A caller
    /// must still verify the complete prepared presentation composition.
    VerifyPersonaCredentialEvidenceStage {
        /// Structurally admitted proof and compiler-ordered public inputs.
        proof: ZkPersonaCredentialEvidenceStageProof,
    },
    /// Prove one exact prepared source circuit with a secret witness owner.
    ProvePersonaCredentialEvidenceStage {
        /// Selected public or one-time private persona contract.
        mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
        /// Exact source circuit and hash lane.
        circuit_ref: ZkCircuitRef,
        /// Production proving suite.
        proof_suite: ZkProofSuite,
        /// Short-lived, zeroizing Noir witness stack.
        witness: ZkWitness,
    },
    /// Prove the separately refreshable prepared current-state proof from
    /// typed credential and issuer-status material.
    ProvePersonaCredentialEvidenceCurrentState {
        /// Selected public or one-time private persona contract.
        mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
        /// Exact current-state source circuit and hash lane.
        circuit_ref: ZkCircuitRef,
        /// Production proving suite.
        proof_suite: ZkProofSuite,
        /// Typed current-state witness source.
        input: Box<ZkPersonaCredentialEvidenceCurrentStateProveRequest>,
    },
    /// Prove the issuer envelope and exact subject edge from typed, private
    /// credential fields without exposing a raw Noir witness to the caller.
    ProvePersonaCredentialEvidenceIssuerEnvelope {
        /// Public or one-time private persona token contract.
        mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
        /// Exact issuer-envelope circuit and hash lane.
        circuit_ref: ZkCircuitRef,
        /// Production proving suite.
        proof_suite: ZkProofSuite,
        /// Owned typed issuer credential and token inputs.
        input: Box<super::ZkPersonaCredentialEvidenceIssuerEnvelopeProveRequest>,
    },
    /// Prove the issuer-signed envelope-to-claim-root edge for one token.
    ProvePersonaCredentialEvidenceClaimRoot {
        /// Public or one-time private persona token contract.
        mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
        /// Exact claim-root circuit and hash lane.
        circuit_ref: ZkCircuitRef,
        /// Production proving suite.
        proof_suite: ZkProofSuite,
        /// Owned credential and token inputs.
        input: Box<super::ZkPersonaCredentialEvidenceClaimRootProveRequest>,
    },
    /// Prove the issuer-signed validity interval and status-list pointer.
    ProvePersonaCredentialEvidenceSignedValidity {
        /// Public or one-time private persona token contract.
        mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
        /// Exact signed-validity circuit and hash lane.
        circuit_ref: ZkCircuitRef,
        /// Production proving suite.
        proof_suite: ZkProofSuite,
        /// Owned issuer credential and status-pointer fields.
        input: Box<super::ZkPersonaCredentialEvidenceSignedValidityProveRequest>,
    },
    /// Prove one selected credential claim and persona authorization.
    ProvePersonaCredentialEvidenceSelectedClaim {
        /// Public or one-time private persona token contract.
        mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
        /// Exact selected-claim circuit and hash lane.
        circuit_ref: ZkCircuitRef,
        /// Production proving suite.
        proof_suite: ZkProofSuite,
        /// Owned selected opening and signatures.
        input: Box<ZkPersonaCredentialEvidenceSelectedClaimProveRequest>,
    },
    /// Compute the canonical challenge for a platform protected holder key.
    PreparePersonaCredentialEvidencePresentationSigning {
        /// Exact joined packages and authenticated verifier request.
        input: Box<ZkPersonaCredentialEvidencePresentationInput>,
    },
    /// Assemble a holder-signed prepared presentation after recomputing its challenge.
    AssemblePersonaCredentialEvidencePresentation {
        /// Exact joined packages and authenticated verifier request.
        input: Box<ZkPersonaCredentialEvidencePresentationInput>,
        /// Raw low-S P-256 signature returned by the protected key.
        signature: zeroize::Zeroizing<[u8; 64]>,
    },
}
