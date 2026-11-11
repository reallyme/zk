// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Mutex;

use reallyme_credential_status::StatusList;
use reallyme_identity_openid4vp_product::{TrustedRequestObjectResolver, VerifierProductStore};
use reallyme_identity_openid4vp_product_store::{
    EncryptedVerifierFileStore, ZkPersonaCredentialEvidenceSignedStatusAuthority,
};
use reallyme_openid4vp_runtime::{
    HostedRequestObject, RequestObjectStore, ResponseCode, RuntimeClock, RuntimeError,
    RuntimeErrorReason, SessionReservation, VerifiedAuthorizationResponse,
    VerifiedAuthorizationResult, VerifierSessionStore, SESSION_RESERVATION_ID_BYTES,
};
use reallyme_openid4vp_verifier::{
    BrowserSessionBinding, HolderBindingVerificationContext, HolderBindingVerifier, SessionRecord,
    VerifiedHolderBinding, VerifierError, VerifierErrorReason, ZkHolderBindingVerifier,
    ZkVerificationRequirements,
};
use reallyme_zk_api::{issuer_status::ZkIssuerStatusPurpose, keys::ZkIssuerPublicKey};
use reallyme_zk_backend_bb::{BarretenbergBundleProvider, NativeBarretenbergBackend};

use crate::artifacts::StageResolver;
use crate::common_credential_root_direct_post::CommonCredentialRootFixture;
use crate::error::HarnessError;
use crate::status_qualified::{status_source, FixtureStatusSignatureVerifier};

pub(crate) const SESSION_KEY: &str = "linked-session-0123456789";

pub(crate) struct OwnedZkHolderBindingVerifier {
    pub(crate) provider:
        std::sync::Arc<BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>>,
    pub(crate) trusted_issuers: Vec<ZkIssuerPublicKey>,
    pub(crate) requirements: ZkVerificationRequirements,
    pub(crate) status_store: std::sync::Arc<EncryptedVerifierFileStore>,
    pub(crate) status_lists: [StatusList; 2],
    pub(crate) status_issuer_keys: [ZkIssuerPublicKey; 2],
    pub(crate) status_signer: FixtureStatusSignatureVerifier,
}

impl HolderBindingVerifier for OwnedZkHolderBindingVerifier {
    fn verify_holder_binding(
        &self,
        presentation: &reallyme_openid4vp_types::PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        let sources = [
            status_source(
                &self.status_lists[0],
                &self.status_signer,
                self.status_issuer_keys[0],
            ),
            status_source(
                &self.status_lists[1],
                &self.status_signer,
                self.status_issuer_keys[1],
            ),
        ];
        let authority = ZkPersonaCredentialEvidenceSignedStatusAuthority::new(
            self.status_store.as_ref(),
            &sources,
        );
        ZkHolderBindingVerifier::new(
            self.provider.as_ref(),
            self.trusted_issuers.as_slice(),
            self.requirements,
        )
        .with_issuer_credential_status(
            self.provider.as_ref(),
            &authority,
            ZkIssuerStatusPurpose::Revocation,
        )
        .verify_holder_binding(presentation, context)
    }
}

pub(crate) struct OwnedCommonCredentialRootZkHolderBindingVerifier {
    pub(crate) provider:
        std::sync::Arc<BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>>,
    pub(crate) trusted_issuers: Vec<ZkIssuerPublicKey>,
    pub(crate) requirements: ZkVerificationRequirements,
    pub(crate) fixture: std::sync::Arc<CommonCredentialRootFixture>,
    pub(crate) issuer_status_lists: [StatusList; 2],
    pub(crate) policy_build_time_unix: u64,
}

impl HolderBindingVerifier for OwnedCommonCredentialRootZkHolderBindingVerifier {
    fn verify_holder_binding(
        &self,
        presentation: &reallyme_openid4vp_types::PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        // The verification policy borrows durable floors. Construct it for
        // each request while this owner keeps the floor and authenticated
        // issuer lists alive; never retain a policy borrowing local inputs.
        let policy = self
            .fixture
            .verification_policy(&self.issuer_status_lists, self.policy_build_time_unix)
            .map_err(|error| match error {
                HarnessError::Verifier(error) => error,
                _ => VerifierError::new(VerifierErrorReason::InvalidCredentialStatus),
            })?;
        ZkHolderBindingVerifier::new_with_common_credential_root(
            self.provider.as_ref(),
            self.trusted_issuers.as_slice(),
            self.requirements,
            self.provider.as_ref(),
            policy,
        )
        .verify_holder_binding(presentation, context)
    }
}

pub(crate) struct InMemorySessionStore {
    state: Mutex<InMemorySessionState>,
}

enum InMemorySessionState {
    Live(SessionRecord),
    Reserved {
        session: SessionRecord,
        reservation_id: [u8; SESSION_RESERVATION_ID_BYTES],
    },
    Committed {
        result: VerifiedAuthorizationResult,
    },
}

impl InMemorySessionStore {
    pub(crate) fn new(session: SessionRecord) -> Self {
        Self {
            state: Mutex::new(InMemorySessionState::Live(session)),
        }
    }

    pub(crate) fn committed_result(&self) -> Result<VerifiedAuthorizationResult, HarnessError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::VerifiedResponseStoreFailed))?;
        match &*state {
            InMemorySessionState::Committed { result } => Ok(result.clone()),
            InMemorySessionState::Live(_) | InMemorySessionState::Reserved { .. } => {
                Err(HarnessError::RuntimeCommitMissing)
            }
        }
    }
}

impl VerifierSessionStore for InMemorySessionStore {
    fn load_session(&self, key: &str) -> Result<SessionRecord, RuntimeError> {
        require_session_key(key)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionConsumeFailed))?;
        match &*state {
            InMemorySessionState::Live(session)
            | InMemorySessionState::Reserved { session, .. } => Ok(session.clone()),
            InMemorySessionState::Committed { .. } => Err(RuntimeError::new(
                RuntimeErrorReason::SessionAlreadyConsumed,
            )),
        }
    }

    fn reserve_session(&self, key: &str) -> Result<SessionReservation, RuntimeError> {
        require_session_key(key)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionConsumeFailed))?;
        let session = match &*state {
            InMemorySessionState::Live(session) => session.clone(),
            InMemorySessionState::Reserved { .. } => {
                return Err(RuntimeError::new(
                    RuntimeErrorReason::SessionReservationConflict,
                ));
            }
            InMemorySessionState::Committed { .. } => {
                return Err(RuntimeError::new(
                    RuntimeErrorReason::SessionAlreadyConsumed,
                ));
            }
        };
        let reservation_id = [7_u8; SESSION_RESERVATION_ID_BYTES];
        *state = InMemorySessionState::Reserved {
            session: session.clone(),
            reservation_id,
        };
        Ok(SessionReservation::new(session, reservation_id))
    }

    fn release_session(
        &self,
        key: &str,
        reservation: &SessionReservation,
    ) -> Result<(), RuntimeError> {
        require_session_key(key)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed))?;
        let session = match &*state {
            InMemorySessionState::Reserved {
                session,
                reservation_id,
            } if reservation_id == reservation.reservation_id()
                && session == reservation.session() =>
            {
                session.clone()
            }
            InMemorySessionState::Live(_) | InMemorySessionState::Reserved { .. } => {
                return Err(RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed));
            }
            InMemorySessionState::Committed { .. } => {
                return Err(RuntimeError::new(
                    RuntimeErrorReason::SessionAlreadyConsumed,
                ));
            }
        };
        *state = InMemorySessionState::Live(session);
        Ok(())
    }

    fn commit_verified_authorization_response(
        &self,
        key: &str,
        reservation: &SessionReservation,
        _response_code: &ResponseCode,
        result: VerifiedAuthorizationResponse<'_>,
    ) -> Result<(), RuntimeError> {
        require_session_key(key)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionCommitFailed))?;
        match &*state {
            InMemorySessionState::Reserved {
                session,
                reservation_id,
            } if reservation_id == reservation.reservation_id()
                && session == reservation.session()
                && session == result.session() =>
            {
                *state = InMemorySessionState::Committed {
                    result: result.into_result(),
                };
                Ok(())
            }
            InMemorySessionState::Live(_) | InMemorySessionState::Reserved { .. } => {
                Err(RuntimeError::new(RuntimeErrorReason::SessionCommitFailed))
            }
            InMemorySessionState::Committed { .. } => Err(RuntimeError::new(
                RuntimeErrorReason::SessionAlreadyConsumed,
            )),
        }
    }

    fn redeem_follow_back(
        &self,
        _response_code: &ResponseCode,
        _browser_session: &BrowserSessionBinding,
        _now_unix: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::UnsupportedFeature))
    }
}

impl RequestObjectStore for InMemorySessionStore {
    fn load_request_object(&self, _key: &str) -> Result<HostedRequestObject, RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::RequestObjectNotFound))
    }
}

impl TrustedRequestObjectResolver for InMemorySessionStore {}

impl VerifierProductStore for InMemorySessionStore {}

fn require_session_key(key: &str) -> Result<(), RuntimeError> {
    if key == SESSION_KEY {
        Ok(())
    } else {
        Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound))
    }
}

pub(crate) struct MissingRequestObjectStore;

impl RequestObjectStore for MissingRequestObjectStore {
    fn load_request_object(&self, _key: &str) -> Result<HostedRequestObject, RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::RequestObjectNotFound))
    }
}

pub(crate) struct FixedClock {
    pub(crate) now_unix: u64,
}

impl RuntimeClock for FixedClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(self.now_unix)
    }
}
