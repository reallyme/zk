// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(
    clippy::unwrap_used,
    reason = "focused tests fail directly on unexpected Result and Option values"
)]

use super::{
    decode_persona_credential_evidence_presentation_auth,
    decode_persona_credential_evidence_verifier_request, ZkPersonaCredentialEvidenceAuthReason,
    ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidencePresentationAuth,
    ZkPersonaCredentialEvidenceRequestProtocol, ZkPersonaCredentialEvidenceResponseMode,
    ZkPersonaCredentialEvidenceVerifierRequest,
};
use buffa::{EnumValue, Message};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
#[cfg(any(feature = "native", feature = "wasm"))]
use zeroize::Zeroizing;

fn request() -> ZkPersonaCredentialEvidenceVerifierRequest {
    ZkPersonaCredentialEvidenceVerifierRequest {
        protocol: ZkPersonaCredentialEvidenceRequestProtocol::OpenId4Vp,
        response_mode: ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt,
        nonce: [1; 32],
        audience_sha256: [2; 32],
        transaction_data_sha256: [3; 32],
        requested_claims_sha256: [4; 32],
        verifier_policy_sha256: [5; 32],
        transport_context_sha256: [6; 32],
        issued_at_unix: 100,
        expires_at_unix: 200,
    }
}

#[test]
fn canonical_request_roundtrip_and_exclusive_expiry() {
    let request = request();
    let wire = request.encode().unwrap();
    let decoded = decode_persona_credential_evidence_verifier_request(&wire).unwrap();
    assert_eq!(decoded.digest().unwrap(), request.digest().unwrap());
    assert!(decoded.validate_at(100).is_ok());
    assert!(decoded.validate_at(199).is_ok());
    assert_eq!(
        decoded.validate_at(200).unwrap_err().reason(),
        ZkPersonaCredentialEvidenceAuthReason::NotCurrent
    );
    assert_eq!(
        decoded.validate_at(99).unwrap_err().reason(),
        ZkPersonaCredentialEvidenceAuthReason::NotCurrent
    );
}

#[test]
fn every_openid4vp_response_mode_has_a_distinct_authenticated_transcript() {
    let mut digests = std::collections::BTreeSet::new();
    for mode in [
        ZkPersonaCredentialEvidenceResponseMode::DirectPost,
        ZkPersonaCredentialEvidenceResponseMode::DirectPostJwt,
        ZkPersonaCredentialEvidenceResponseMode::Fragment,
        ZkPersonaCredentialEvidenceResponseMode::FormPost,
        ZkPersonaCredentialEvidenceResponseMode::DcApi,
        ZkPersonaCredentialEvidenceResponseMode::DcApiJwt,
    ] {
        let mut candidate = request();
        candidate.response_mode = mode;
        let wire = candidate.encode().unwrap();
        let decoded = decode_persona_credential_evidence_verifier_request(&wire).unwrap();
        assert_eq!(decoded.response_mode, mode);
        assert!(digests.insert(*decoded.digest().unwrap().as_bytes()));
    }
    let mut invalid = request();
    invalid.protocol = ZkPersonaCredentialEvidenceRequestProtocol::ReallyMeDirect;
    invalid.response_mode = ZkPersonaCredentialEvidenceResponseMode::DcApi;
    assert_eq!(
        invalid.encode().unwrap_err().reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidField
    );
}

#[test]
fn request_rejects_malformed_fields_and_protocol_confusion() {
    let mut changed = request();
    changed.nonce = [0; 32];
    assert_eq!(
        changed.encode().unwrap_err().reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidField
    );
    let mut changed = request();
    changed.expires_at_unix = changed.issued_at_unix;
    assert_eq!(
        changed.encode().unwrap_err().reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidInterval
    );
    let mut changed = request();
    changed.protocol = ZkPersonaCredentialEvidenceRequestProtocol::ReallyMeDirect;
    assert_eq!(
        changed.encode().unwrap_err().reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidField
    );
    let mut wire = request().encode().unwrap().to_vec();
    wire.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert_eq!(
        decode_persona_credential_evidence_verifier_request(&wire)
            .err()
            .unwrap()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidEncoding
    );
    let mut protobuf = pb::ZkPersonaCredentialEvidenceVerifierRequestV1::default();
    protobuf.nonce = vec![1; 31];
    protobuf.protocol =
        EnumValue::from(pb::ZkPersonaCredentialEvidenceRequestProtocol::ZK_PERSONA_CREDENTIAL_EVIDENCE_REQUEST_PROTOCOL_OPENID4VP_V1);
    protobuf.response_mode =
        EnumValue::from(pb::ZkPersonaCredentialEvidenceResponseMode::ZK_PERSONA_CREDENTIAL_EVIDENCE_RESPONSE_MODE_DIRECT_POST);
    assert_eq!(
        decode_persona_credential_evidence_verifier_request(&protobuf.encode_to_vec())
            .err()
            .unwrap()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidField
    );
}

#[test]
fn every_request_component_changes_the_digest() {
    let original = request();
    let digest = original.digest().unwrap();
    let mut variants = Vec::new();
    let mut changed = request();
    changed.nonce[0] ^= 1;
    variants.push(changed);
    let mut changed = request();
    changed.audience_sha256[0] ^= 1;
    variants.push(changed);
    let mut changed = request();
    changed.transaction_data_sha256[0] ^= 1;
    variants.push(changed);
    let mut changed = request();
    changed.requested_claims_sha256[0] ^= 1;
    variants.push(changed);
    let mut changed = request();
    changed.verifier_policy_sha256[0] ^= 1;
    variants.push(changed);
    let mut changed = request();
    changed.transport_context_sha256[0] ^= 1;
    variants.push(changed);
    let mut changed = request();
    changed.issued_at_unix += 1;
    variants.push(changed);
    let mut changed = request();
    changed.expires_at_unix += 1;
    variants.push(changed);
    let mut changed = request();
    changed.response_mode = ZkPersonaCredentialEvidenceResponseMode::DirectPost;
    variants.push(changed);
    for changed in variants {
        assert_ne!(changed.digest().unwrap(), digest);
    }
    let mut direct = request();
    direct.protocol = ZkPersonaCredentialEvidenceRequestProtocol::ReallyMeDirect;
    direct.response_mode = ZkPersonaCredentialEvidenceResponseMode::Direct;
    assert_ne!(direct.digest().unwrap(), digest);
}

#[test]
fn authentication_binds_both_packages_request_and_profile() {
    let request = request();
    let auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        b"prepared proof",
        b"signed current status",
        &request,
    )
    .unwrap();
    let wire = auth.encode().unwrap();
    let decoded = decode_persona_credential_evidence_presentation_auth(&wire).unwrap();
    assert_eq!(
        decoded.signing_digest().unwrap(),
        auth.signing_digest().unwrap()
    );
    assert!(decoded
        .validate_verified_packages(
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            b"prepared proof",
            b"signed current status",
            &request,
        )
        .is_ok());
    for (mode, prepared, status) in [
        (
            ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
            b"prepared proof".as_slice(),
            b"signed current status".as_slice(),
        ),
        (
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            b"changed proof".as_slice(),
            b"signed current status".as_slice(),
        ),
        (
            ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
            b"prepared proof".as_slice(),
            b"stale current status".as_slice(),
        ),
    ] {
        assert_eq!(
            decoded
                .validate_verified_packages(mode, prepared, status, &request)
                .unwrap_err()
                .reason(),
            ZkPersonaCredentialEvidenceAuthReason::BindingMismatch
        );
    }
    let mut different_request = request;
    different_request.nonce[0] ^= 1;
    assert_eq!(
        decoded
            .validate_verified_packages(
                ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
                b"prepared proof",
                b"signed current status",
                &different_request,
            )
            .unwrap_err()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::BindingMismatch
    );
    let mut protobuf = pb::ZkPersonaCredentialEvidencePresentationAuthV1::default();
    protobuf.mode_id = EnumValue::from(99);
    protobuf.evidence_proof_set_sha256 = vec![1; 32];
    protobuf.current_state_sha256 = vec![2; 32];
    protobuf.verifier_request_sha256 = vec![3; 32];
    assert_eq!(
        decode_persona_credential_evidence_presentation_auth(&protobuf.encode_to_vec())
            .err()
            .unwrap()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidField
    );
}

#[cfg(any(feature = "native", feature = "wasm"))]
#[test]
fn holder_signature_accepts_only_exact_authenticated_packages_and_key() {
    let secret = Zeroizing::new([7_u8; 32]);
    let (compressed, _) = crypto_p256::generate_p256_keypair_from_secret_key(&secret).unwrap();
    let public_key = crypto_p256::decompress_public_key(&compressed).unwrap();
    let holder_x: [u8; 32] = public_key[1..33].try_into().unwrap();
    let holder_y: [u8; 32] = public_key[33..65].try_into().unwrap();
    let request = request();
    let auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        b"prepared proof",
        b"current status",
        &request,
    )
    .unwrap();
    let digest = auth.signing_digest().unwrap();
    let digest = crypto_p256::P256Sha256Digest::new(*digest.as_bytes());
    let der = crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest).unwrap();
    let raw = crypto_p256::p256_ecdsa_der_to_jose_signature(&der).unwrap();
    assert!(auth
        .verify_holder_signature(&holder_x, &holder_y, &raw)
        .is_ok());

    let changed_auth = ZkPersonaCredentialEvidencePresentationAuth::from_canonical_packages(
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
        b"prepared proof",
        b"new current status",
        &request,
    )
    .unwrap();
    assert_eq!(
        changed_auth
            .verify_holder_signature(&holder_x, &holder_y, &raw)
            .unwrap_err()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidSignature
    );
    let mut wrong_key = holder_x;
    wrong_key[0] ^= 1;
    assert_eq!(
        auth.verify_holder_signature(&wrong_key, &holder_y, &raw)
            .unwrap_err()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidSignature
    );
    let mut wrong_sig = raw;
    wrong_sig[0] ^= 1;
    assert_eq!(
        auth.verify_holder_signature(&holder_x, &holder_y, &wrong_sig)
            .unwrap_err()
            .reason(),
        ZkPersonaCredentialEvidenceAuthReason::InvalidSignature
    );
}
