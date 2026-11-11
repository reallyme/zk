// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use crate::modern_all30::MatrixError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HarnessPhase {
    PrivatePersonaResolver,
    CommonCredentialRootResolver,
    FirstBundleProof,
    SecondBundleProof,
    WrongPersonaBundleProof,
    FirstDirectPostBundleProof,
    SecondDirectPostBundleProof,
    CommonCredentialRootSelectedVpResponse,
    CommonCredentialRootInitialDirectVerification,
    CommonCredentialRootFreshDirectVerification,
    CommonCredentialRootSelectedSessionExpiryDecode,
    CommonCredentialRootSelectedDirectVerification,
    CommonCredentialRootSelectedVpValue,
    CommonCredentialRootSelectedVerifiedExtraction,
    CommonCredentialRootSelectedWrongSession,
    CommonCredentialRootSelectedSwappedSlots,
    CommonCredentialRootSelectedProfileMatrixDirectVerification,
    CommonCredentialRootSelectedProfileMatrixVpValue,
    CommonCredentialRootSelectedProfileMatrixVpResponse,
    CommonCredentialRootSelectedProfileMatrixWrongProfile,
    CommonCredentialRootSelectedProfileMatrixWrongHash,
    CommonCredentialRootMixedSaltRejection,
    CommonCredentialRootFreshVpResponse,
    CommonCredentialRootFreshVerifiedExtraction,
    CommonCredentialRootWrongStatusPolicy,
    CommonCredentialRootWrongSignerPolicy,
    CommonCredentialRootWrongAssurancePolicy,
    CommonCredentialRootStaleStatusPolicy,
    CommonCredentialRootWrongPersonaPolicy,
    CommonCredentialRootSecondPresentationProof,
    CommonCredentialRootSecondSessionExpiryDecode,
    CommonCredentialRootSecondVpValue,
    CommonCredentialRootSecondDirectVerification,
    CommonCredentialRootSecondVpResponse,
    CommonCredentialRootSecondVerifiedExtraction,
    CommonCredentialRootBodyEncoding,
    CommonCredentialRootSecondRuntimeStore,
    CommonCredentialRootFirstInSecondSession,
    CommonCredentialRootSecondInFirstSession,
    CommonCredentialRootSecondRuntimeSetup,
    CommonCredentialRootSecondRuntimeAccept,
    CommonCredentialRootSecondRuntimeReplay,
    CommonCredentialRootRuntimeTamperedProof,
    CommonCredentialRootRuntimeWrongSession,
    CommonCredentialRootWrongQuery,
    CommonCredentialRootRuntimeSetup,
    CommonCredentialRootRuntimeAccept,
    DirectPostRuntime,
    DcApiBoundPresentationRejection,
}

#[derive(Debug, Error)]
pub(crate) enum HarnessError {
    #[error("required fixture field is missing")]
    MissingField,
    #[error("fixture field is ambiguous")]
    AmbiguousField,
    #[error("fixture length is invalid")]
    InvalidLength,
    #[error("linked proof composition was accepted unexpectedly")]
    WrongPersonaAccepted,
    #[error("verifier accepted an invalid presentation unexpectedly")]
    InvalidPresentationAccepted,
    #[error("verified disclosure is not a ZK claim")]
    MissingZkClaim,
    #[error("runtime did not commit the expected verified response")]
    RuntimeCommitMissing,
    #[error("runtime returned an unexpected direct-post status")]
    RuntimeStatus(u16),
    #[error("harness phase failed: {0:?}")]
    Phase(HarnessPhase),
    #[error("i/o failure")]
    Io(#[from] std::io::Error),
    #[error("json failure")]
    Json(#[from] serde_json::Error),
    #[error("matrix failure")]
    Matrix(#[from] MatrixError),
    #[error("zk failure")]
    Zk(#[from] reallyme_zk_api::errors::ZkError),
    #[error("common-credential-root presentation material generation failed")]
    CommonCredentialRootJoinGeneration(
        #[from] reallyme_zk_api::common_root::ZkCommonCredentialRootJoinGenerationError,
    ),
    #[error("issuer-approved common-credential-root claims do not match the commitment")]
    CommonCredentialRootClaimCommitment(
        #[from] reallyme_zk_api::common_root::ZkCommonCredentialRootClaimCommitmentError,
    ),
    #[error("common-credential-root stage salt ownership failed")]
    CommonCredentialRootStageSalt(
        #[from] reallyme_zk_api::common_root::ZkCommonCredentialRootStageSaltError,
    ),
    #[error("root status snapshot failure")]
    RootStatusSnapshot(#[from] reallyme_zk_api::common_root::ZkRootStatusSnapshotError),
    #[error("root status verification failure")]
    RootStatusVerification(#[from] reallyme_zk_api::common_root::ZkRootStatusVerificationError),
    #[error("wallet failure")]
    Wallet(#[from] reallyme_openid4vp_wallet::WalletError),
    #[error("verifier failure")]
    Verifier(#[from] reallyme_openid4vp_verifier::VerifierError),
    #[error("runtime failure")]
    Runtime(#[from] reallyme_openid4vp_runtime::RuntimeError),
    #[error("identity product runtime failure")]
    IdentityProduct(#[from] reallyme_identity_openid4vp_product::OpenId4VpProductError),
    #[error("identity product store failure")]
    IdentityProductStore(#[from] reallyme_identity_openid4vp_product_store::VerifierStoreError),
    #[error("identity product response key failure")]
    IdentityProductResponseKey(#[from] reallyme_identity_openid4vp_product_store::ResponseKeyError),
    #[error("openid4vp type failure")]
    Type(#[from] reallyme_openid4vp_types::OpenId4vpTypeError),
    #[error("dcql failure")]
    Dcql(#[from] reallyme_openid4vp_dcql::DcqlError),
    #[error("witness failure")]
    Witness(#[from] reallyme_zk_noir_witness_core::WitnessError),
    #[error("ssi credential failure")]
    Credential(#[from] reallyme_credential::CredentialError),
    #[error("ssi credential status failure")]
    CredentialStatus(#[from] reallyme_credential_status::CredentialStatusError),
    #[error("ssi proof-binding issuance failure")]
    CredentialProofBinding(#[from] reallyme_credential::committed::error::VcError),
    #[error("openid4vci issuer failure")]
    VciIssuer(#[from] openid4vci_issuer::IssuerError),
    #[error("openid4vci response failure")]
    VciType(#[from] openid4vci_types::OpenId4VciError),
    #[error("identity issuance assurance failure")]
    IssuanceAssurance(#[from] reallyme_identity::zk::ZkIssuanceAssuranceError),
    #[error("common-credential-root holder assurance failure")]
    HolderAssurance(
        #[from] reallyme_zk_api::common_root::ZkCommonCredentialRootHolderAssuranceError,
    ),
    #[error("SD-JWT issuance and presentation roundtrip failed")]
    SdJwtRoundtrip,
    #[error("cryptographic signing failure")]
    Crypto(#[from] reallyme_crypto::CryptoError),
}
