// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Barretenberg bundle provider adapter.

// The BBAPI command builder/parser is only compiled for native linked
// Barretenberg bindings, plus tests that pin the exact upstream envelope.
#[cfg(feature = "native")]
mod bbapi_abi;
mod exact_artifacts;
#[cfg(feature = "native")]
mod filesystem_store;
mod linked;
#[cfg(feature = "native")]
mod native_backend;
#[cfg(feature = "native")]
mod persona_credential_evidence_provider;
mod provider;
mod public_input_codec;
#[cfg(all(feature = "native", feature = "dev-cli"))]
pub mod retained_command;
mod stage_provider;
#[cfg(test)]
mod tests;

pub use exact_artifacts::BbExactCircuitArtifacts;
#[cfg(feature = "native")]
pub use filesystem_store::NativeFilesystemArtifactStore;
pub use linked::{
    BbCommonCredentialRootRawProveRequest, BbCommonCredentialRootRawProveResponse,
    BbCommonCredentialRootRawVerifyRequest, BbExactCircuitProveRequest,
    BbExactCircuitVerifyRequest, BbPersonaCredentialEvidenceStageProveRequest, BbStageProveRequest,
    BbStageProveResponse, BbStageVerifyRequest, LinkedBarretenbergBackend,
};
#[cfg(feature = "native")]
pub use native_backend::{
    BarretenbergProverCrs, BarretenbergProverCrsIdentity, BarretenbergVerifierCrs,
    BarretenbergVerifierCrsIdentity, NativeBarretenbergBackend,
};
#[cfg(feature = "native")]
pub use persona_credential_evidence_provider::{
    BarretenbergPersonaCredentialEvidenceArtifactResolver,
    BarretenbergPersonaCredentialEvidenceProvider,
};
pub use provider::{
    BarretenbergArtifactResolver, BarretenbergArtifactStore, BarretenbergBundleProvider,
    BarretenbergCommonCredentialRootArtifactResolver, BbStageArtifacts,
    BbStageVerificationArtifacts, ManifestBackedArtifactResolver,
};
pub use public_input_codec::{BarretenbergPublicInputCodec, BARRETENBERG_FIELD_BYTES};
pub use stage_provider::BarretenbergStageProvider;
