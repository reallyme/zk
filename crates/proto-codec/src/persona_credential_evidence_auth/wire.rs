// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact protobuf enum and fixed-digest conversion for prepared authentication.

use buffa::EnumValue;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use super::{
    error, ZkPersonaCredentialEvidenceAuthError, ZkPersonaCredentialEvidenceAuthReason,
    ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRequestProtocol,
    ZkPersonaCredentialEvidenceResponseMode, DIGEST_BYTES,
};

pub(super) fn exact_digest(
    bytes: &[u8],
) -> Result<[u8; DIGEST_BYTES], ZkPersonaCredentialEvidenceAuthError> {
    <[u8; DIGEST_BYTES]>::try_from(bytes)
        .map_err(|_| error(ZkPersonaCredentialEvidenceAuthReason::InvalidField))
}

pub(super) fn profile_to_proto(
    mode: ZkPersonaCredentialEvidenceMode,
) -> pb::ZkPersonaCredentialEvidenceMode {
    match mode {
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1
        }
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1 => {
            pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1
        }
    }
}

pub(super) fn profile_from_proto(
    value: &EnumValue<pb::ZkPersonaCredentialEvidenceMode>,
) -> Result<ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceAuthError> {
    match value.as_known() {
        Some(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PUBLIC_PERSONA_V1) => {
            Ok(ZkPersonaCredentialEvidenceMode::PublicPersonaV1)
        }
        Some(pb::ZkPersonaCredentialEvidenceMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_MODE_PRIVATE_PERSONA_ONE_TIME_V1) => {
            Ok(ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1)
        }
        _ => Err(error(ZkPersonaCredentialEvidenceAuthReason::InvalidField)),
    }
}

pub(super) fn protocol_to_proto(
    protocol: ZkPersonaCredentialEvidenceRequestProtocol,
) -> pb::ZkPersonaCredentialEvidenceRequestProtocol {
    match protocol {
        ZkPersonaCredentialEvidenceRequestProtocol::ReallyMeDirect => {
            pb::ZkPersonaCredentialEvidenceRequestProtocol::ZK_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_PROTOCOL_REALLYME_DIRECT_V1
        }
        ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp => {
            pb::ZkPersonaCredentialEvidenceRequestProtocol::ZK_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_PROTOCOL_OPENID4VP_V1
        }
    }
}

pub(super) fn protocol_from_proto(
    value: &EnumValue<pb::ZkPersonaCredentialEvidenceRequestProtocol>,
) -> Result<ZkPersonaCredentialEvidenceRequestProtocol, ZkPersonaCredentialEvidenceAuthError> {
    match value.as_known() {
        Some(pb::ZkPersonaCredentialEvidenceRequestProtocol::ZK_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_PROTOCOL_REALLYME_DIRECT_V1) => {
            Ok(ZkPersonaCredentialEvidenceRequestProtocol::ReallyMeDirect)
        }
        Some(pb::ZkPersonaCredentialEvidenceRequestProtocol::ZK_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_PROTOCOL_OPENID4VP_V1) => {
            Ok(ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp)
        }
        _ => Err(error(ZkPersonaCredentialEvidenceAuthReason::InvalidField)),
    }
}

pub(super) fn response_mode_to_proto(
    mode: ZkPersonaCredentialEvidenceResponseMode,
) -> pb::ZkPersonaCredentialEvidenceResponseMode {
    match mode {
        ZkPersonaCredentialEvidenceResponseMode::Direct => {
            pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT
        }
        ZkPersonaCredentialEvidenceResponseMode::DirectPost => {
            pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT_POST
        }
        ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt => {
            pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT_POST_JWT
        }
        ZkPersonaCredentialEvidenceResponseMode::Fragment => {
            pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_FRAGMENT
        }
        ZkPersonaCredentialEvidenceResponseMode::FormPost => {
            pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_FORM_POST
        }
        ZkPersonaCredentialEvidenceResponseMode::DcApi => pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DC_API,
        ZkPersonaCredentialEvidenceResponseMode::DcApiJwt => {
            pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DC_API_JWT
        }
    }
}

pub(super) fn response_mode_from_proto(
    value: &EnumValue<pb::ZkPersonaCredentialEvidenceResponseMode>,
) -> Result<ZkPersonaCredentialEvidenceResponseMode, ZkPersonaCredentialEvidenceAuthError> {
    match value.as_known() {
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::Direct)
        }
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT_POST) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::DirectPost)
        }
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT_POST_JWT) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt)
        }
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_FRAGMENT) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::Fragment)
        }
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_FORM_POST) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::FormPost)
        }
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DC_API) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::DcApi)
        }
        Some(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DC_API_JWT) => {
            Ok(ZkPersonaCredentialEvidenceResponseMode::DcApiJwt)
        }
        _ => Err(error(ZkPersonaCredentialEvidenceAuthReason::InvalidField)),
    }
}
