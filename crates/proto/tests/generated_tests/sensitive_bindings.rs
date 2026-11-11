// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    ZkInputBytes32, ZkInputMerkleClaimProof, ZkInputMerklePath, ZkPublicInputs, ZkPublicInputsView,
};

// These test-only includes inspect the complete generated secret-handling code.
// The generator emits files larger than Clippy's default include size limit.
#[allow(clippy::large_include_file)]
const GENERATED_MESSAGE_SOURCE: &str = concat!(
    include_str!("../../src/generated/buffa/reallyme.zk.v1.manifest.rs"),
    include_str!("../../src/generated/buffa/reallyme.zk.v1.capabilities.rs"),
);
#[allow(clippy::large_include_file)]
const GENERATED_VIEW_SOURCE: &str = concat!(
    include_str!("../../src/generated/buffa/reallyme.zk.v1.manifest.__view.rs"),
    include_str!("../../src/generated/buffa/reallyme.zk.v1.capabilities.__view.rs"),
);
const GENERATED_MODULE_SOURCE: &str =
    include_str!("../../src/generated/buffa/reallyme.zk.v1.mod.rs");

#[test]
fn sensitive_protojson_bytes_use_zeroizing_base64_staging() {
    const SENSITIVE_BYTES_FIELD_COUNT: usize = 67;
    const PROTOJSON_BYTES_FIELD_COUNT: usize = 66;
    const BINARY_ONLY_BYTES_FIELD_COUNT: usize = 1;

    assert!(GENERATED_MESSAGE_SOURCE.contains("fn __reallyme_serialize_zeroizing_bytes"));
    assert!(GENERATED_MESSAGE_SOURCE.contains("fn __reallyme_deserialize_zeroizing_bytes"));
    assert!(GENERATED_MESSAGE_SOURCE.contains("::reallyme_codec::base64::bytes_to_base64"));
    assert!(GENERATED_MESSAGE_SOURCE.contains("::zeroize::Zeroizing::new("));
    assert!(GENERATED_MESSAGE_SOURCE.contains("decoded.as_mut_slice().zeroize()"));
    assert_eq!(
        GENERATED_MESSAGE_SOURCE
            .matches("serialize_with = \"__reallyme_serialize_zeroizing_bytes\"")
            .count(),
        PROTOJSON_BYTES_FIELD_COUNT
    );
    assert_eq!(
        GENERATED_MESSAGE_SOURCE
            .matches("serialize_with = \"__reallyme_reject_binary_only_bytes\"")
            .count(),
        BINARY_ONLY_BYTES_FIELD_COUNT
    );
    assert_eq!(
        PROTOJSON_BYTES_FIELD_COUNT + BINARY_ONLY_BYTES_FIELD_COUNT,
        SENSITIVE_BYTES_FIELD_COUNT
    );
}

#[test]
fn sensitive_generated_fields_are_redacted_and_zeroized_on_drop() {
    const GENERATED_MESSAGE_COUNT: usize = 126;
    const SENSITIVE_FIELD_COUNT: usize = 71;
    const DROP_MARKERS: [&str; 33] = [
        "impl ::core::ops::Drop for Digest",
        "impl ::core::ops::Drop for ZkPublicInputs",
        "impl ::core::ops::Drop for ZkCommonCredentialRootRawPublicInputs",
        "impl ::core::ops::Drop for NamedPublicInput",
        "impl ::core::ops::Drop for ZkProofPackage",
        "impl ::core::ops::Drop for ZkCommonCredentialRootRawProofPackage",
        "impl ::core::ops::Drop for ZkCommonCredentialRootPrivateClaimOpening",
        "impl ::core::ops::Drop for ZkCommonCredentialRootPreparedClaims",
        "impl ::core::ops::Drop for ZkCommonCredentialRootPrivateLineageMaterial",
        "impl ::core::ops::Drop for ZkWalletStoredCredential",
        "impl ::core::ops::Drop for ZkSessionBinding",
        "impl ::core::ops::Drop for ZkWitness",
        "impl ::core::ops::Drop for ZkPresentationBoundClaimStatement",
        "impl ::core::ops::Drop for ZkStatusQualifiedClaimStatement",
        "impl ::core::ops::Drop for ZkCommonCredentialRootClaimExpectation",
        "impl ::core::ops::Drop for ZkCommonCredentialRootJoinPolicy",
        "impl ::core::ops::Drop for ZkInputBytes32",
        "impl ::core::ops::Drop for ZkInputBytes16",
        "impl ::core::ops::Drop for ZkInputBytes64",
        "impl ::core::ops::Drop for ZkInputMerklePath",
        "impl ::core::ops::Drop for ZkInputMerkleClaimProof",
        "impl ::core::ops::Drop for ZkProviderOperationResponse",
        "impl ::core::ops::Drop for ZkCommonCredentialRootIssuerStatusExpectation",
        "impl ::core::ops::Drop for ZkRootStatusSnapshot",
        "impl ::core::ops::Drop for ZkRootAssuranceAttestation",
        "impl ::core::ops::Drop for ZkRootActiveSetPublication",
        "impl ::core::ops::Drop for ZkRootStatusPublicationIntent",
        "impl ::core::ops::Drop for ZkRootActiveSetPathAssignment",
        "impl ::core::ops::Drop for ZkPersonaCredentialEvidenceVerifierRequestV1",
        "impl ::core::ops::Drop for ZkPersonaCredentialEvidencePresentationAuthV1",
        "impl ::core::ops::Drop for ZkPersonaCredentialEvidenceRawPublicInputs",
        "impl ::core::ops::Drop for ZkPersonaCredentialEvidenceStageProof",
        "impl ::core::ops::Drop for ZkPersonaCredentialEvidencePresentation",
    ];
    const ZEROIZE_MARKERS: [(&str, usize); 40] = [
        ("Zeroize::zeroize(&mut self.value);", 15),
        ("Zeroize::zeroize(&mut self.encoded);", 6),
        ("Zeroize::zeroize(&mut self.proof);", 12),
        ("Zeroize::zeroize(&mut self.nonce_hash);", 3),
        ("Zeroize::zeroize(&mut self.audience_hash);", 6),
        ("Zeroize::zeroize(&mut self.transaction_data_hash);", 6),
        ("Zeroize::zeroize(&mut self.claim_name_hash);", 12),
        ("Zeroize::zeroize(&mut self.claim_value);", 12),
        ("Zeroize::zeroize(&mut self.claim_salt);", 3),
        ("Zeroize::zeroize(&mut self.credential_binding);", 6),
        ("Zeroize::zeroize(&mut self.request_sha256);", 3),
        ("Zeroize::zeroize(&mut self.path_length);", 2),
        ("Zeroize::zeroize(&mut self.leaf_index);", 4),
        ("Zeroize::zeroize(&mut self.raw_fields);", 6),
        ("Zeroize::zeroize(&mut self.challenge);", 3),
        ("Zeroize::zeroize(&mut self.assurance_policy_id);", 6),
        ("Zeroize::zeroize(&mut self.status_root);", 6),
        ("Zeroize::zeroize(&mut self.claim_root);", 3),
        ("Zeroize::zeroize(&mut self.issuance_binding);", 3),
        ("Zeroize::zeroize(&mut self.credential_pb);", 3),
        ("Zeroize::zeroize(&mut self.prepared_claims_pb);", 3),
        ("Zeroize::zeroize(&mut self.root);", 6),
        ("Zeroize::zeroize(&mut self.relationship_did);", 2),
        ("Zeroize::zeroize(&mut self.nonce);", 6),
        ("Zeroize::zeroize(&mut self.list_id);", 3),
        ("Zeroize::zeroize(&mut self.root_commitment);", 3),
        ("Zeroize::zeroize(&mut self.session_link_commitment);", 6),
        ("Zeroize::zeroize(&mut self.signature);", 6),
        ("Zeroize::zeroize(&mut self.sorted_attestation_ids);", 6),
        ("Zeroize::zeroize(&mut self.url_hash);", 3),
        ("Zeroize::zeroize(&mut self.audience_sha256);", 3),
        ("Zeroize::zeroize(&mut self.transaction_data_sha256);", 3),
        ("Zeroize::zeroize(&mut self.requested_claims_sha256);", 3),
        ("Zeroize::zeroize(&mut self.verifier_policy_sha256);", 3),
        ("Zeroize::zeroize(&mut self.transport_context_sha256);", 3),
        ("Zeroize::zeroize(&mut self.evidence_proof_set_sha256);", 3),
        ("Zeroize::zeroize(&mut self.current_state_sha256);", 3),
        ("Zeroize::zeroize(&mut self.verifier_request_sha256);", 3),
        ("Zeroize::zeroize(&mut self.holder_signature_p256_raw);", 6),
        ("Zeroize::zeroize(&mut self.feed_id);", 6),
    ];
    const SENSITIVE_VIEWS: [&str; 108] = [
        "Digest",
        "ZkArtifactManifest",
        "ZkPublicInputs",
        "ZkCommonCredentialRootRawPublicInputs",
        "NamedPublicInput",
        "ZkProofPackage",
        "ZkCommonCredentialRootRawProofPackage",
        "ZkCommonCredentialRootPresentation",
        "ZkCommonCredentialRootPrivateClaimOpening",
        "ZkCommonCredentialRootPreparedClaims",
        "ZkCommonCredentialRootPrivateLineageMaterial",
        "ZkWalletStoredCredential",
        "ZkClaimProofBundleStageProofPackage",
        "ZkClaimProofBundle",
        "ZkSessionBinding",
        "ZkExpectedStageProofShape",
        "ZkExpectedClaimProofBundleProofShape",
        "ZkWitness",
        "ZkClaimProofBundleWitness",
        "ZkClaimProofBundleProveOperation",
        "ZkRetainedClaimProofBundleProveOperation",
        "ZkClaimProofBundleVerifyOperation",
        "ZkPresentationBoundClaimStatement",
        "ZkStatusQualifiedClaimStatement",
        "ZkStatusQualifiedClaimProofBundleVerifyOperation",
        "ZkStatusQualifiedClaimProofBundleVerification",
        "ZkCommonCredentialRootClaimExpectation",
        "ZkCommonCredentialRootJoinPolicy",
        "ZkCommonCredentialRootVerifyOperation",
        "ZkInputBytes32",
        "ZkInputBytes16",
        "ZkInputBytes64",
        "ZkInputP256PublicKey",
        "ZkInputSessionContext",
        "ZkInputIssuerContext",
        "ZkInputClaimDisclosure",
        "ZkInputMerklePath",
        "ZkInputMerkleClaimProof",
        "ZkInputEnvelopeSignatureProof",
        "ZkInputCredentialRootProof",
        "ZkInputSubjectSessionAuthorization",
        "ZkInputPersonaSessionAuthorization",
        "ZkInputPublicPersonaSessionAuthorization",
        "ZkInputSubjectClaimLink",
        "ZkInputPersonaClaimLink",
        "ZkInputPublicPersonaClaimLink",
        "ZkCredentialSubjectClaimSessionInput",
        "ZkPrivatePersonaSessionInput",
        "ZkPublicPersonaSessionInput",
        "ZkCredentialEnvelopeInput",
        "ZkCredentialRootInput",
        "ZkCredentialSubjectClaimInput",
        "ZkPrivatePersonaClaimInput",
        "ZkInputPresentationContext",
        "ZkCommonCredentialRootAttestationInput",
        "ZkInputCommonCredentialRootStatusPath",
        "ZkCommonCredentialRootStatusInput",
        "ZkInputCommonCredentialRootLineageSlot",
        "ZkInputCommonCredentialRootLineageWitness",
        "ZkCommonCredentialRootLineageInput",
        "ZkCommonCredentialRootPrivatePersonaClaimInput",
        "ZkCommonCredentialRootPublicPersonaClaimInput",
        "ZkCommonCredentialRootStageProveOperation",
        "ZkCommonCredentialRootIssuerCredentialStatusInput",
        "ZkCommonCredentialRootIssuerStatusExpectation",
        "ZkCommonCredentialRootPresentationProveOperation",
        "ZkRootActiveSetPublication",
        "ZkRootStatusPublicationIntent",
        "ZkRootAssuranceAttestation",
        "ZkRootStatusSnapshot",
        "ZkRootActiveSetPathAssignment",
        "ZkPersonaCredentialEvidenceVerifierRequestV1",
        "ZkPersonaCredentialEvidencePresentationAuthV1",
        "ZkPersonaCredentialEvidenceRawPublicInputs",
        "ZkPersonaCredentialEvidenceStageProof",
        "ZkPersonaCredentialEvidencePresentationAssembleOperation",
        "ZkPersonaCredentialEvidenceClaimRootProveOperation",
        "ZkPersonaCredentialEvidenceCurrentStateCredentialInput",
        "ZkPersonaCredentialEvidenceCurrentStateProveOperation",
        "ZkPersonaCredentialEvidenceCurrentStatusInput",
        "ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation",
        "ZkPersonaCredentialEvidenceSelectedClaimProveOperation",
        "ZkPersonaCredentialEvidenceSignedValidityProveOperation",
        "ZkPersonaCredentialEvidencePresentationSigningChallenge",
        "ZkPersonaCredentialEvidencePresentationSigningOperation",
        "ZkCredentialStatusProofPackage",
        "ZkStatusQualifiedClaimProofBundle",
        "ZkPersonaCredentialEvidenceProofSet",
        "ZkPersonaCredentialEvidenceStageVerifyOperation",
        "ZkPersonaCredentialEvidenceStageProveOperation",
        "ZkPersonaCredentialEvidencePresentation",
        "ZkStageWitnessInput",
        "ZkStageWitnessOperation",
        "ZkStageWitness",
        "ZkPresentationBoundClaimBundleVerification",
        "ZkStageProveOperation",
        "ZkStageVerifyOperation",
        "ZkProviderOperationRequest",
        "ZkProviderOperationResult",
        "ZkProviderOperationResponse",
        "ZkProvingVector",
        "ZkProvingVectorSet",
        "ZkReleaseCommonCredentialRootArtifactPin",
        "ZkReleasePersonaCredentialEvidenceArtifactPin",
        "ZkVerificationVector",
        "ZkVerificationVectorSet",
        "ZkReleaseVerificationVectorPin",
        "ZkReleaseIndex",
    ];

    for marker in DROP_MARKERS {
        assert!(GENERATED_MESSAGE_SOURCE.contains(marker));
    }
    assert!(GENERATED_MESSAGE_SOURCE
        .contains("impl ::core::ops::Drop for ReallyMeZeroizingUnknownFields"));
    assert_eq!(
        GENERATED_MESSAGE_SOURCE
            .matches("pub __buffa_unknown_fields: ReallyMeZeroizingUnknownFields,")
            .count(),
        GENERATED_MESSAGE_COUNT
    );
    assert!(
        !GENERATED_MESSAGE_SOURCE.contains("pub __buffa_unknown_fields: ::buffa::UnknownFields,")
    );
    for (marker, expected_count) in ZEROIZE_MARKERS {
        assert_eq!(
            GENERATED_MESSAGE_SOURCE.matches(marker).count(),
            expected_count
        );
    }
    assert_eq!(
        GENERATED_MESSAGE_SOURCE.matches("&\"<redacted>\"").count(),
        SENSITIVE_FIELD_COUNT
    );
    for message in SENSITIVE_VIEWS {
        let redaction = format!("{message}View(<redacted>)");
        let omitted = format!("{message}OwnedView");
        assert!(GENERATED_VIEW_SOURCE.contains(&redaction));
        assert!(!GENERATED_VIEW_SOURCE.contains(&omitted));
        assert!(!GENERATED_MODULE_SOURCE.contains(&omitted));
    }
    assert!(!GENERATED_VIEW_SOURCE.contains("OwnedView"));
    assert!(!GENERATED_MODULE_SOURCE.contains("OwnedView"));
}

#[test]
fn generated_merkle_witness_position_debug_is_redacted() {
    let path = ZkInputMerklePath {
        path_length: 4,
        siblings: vec![ZkInputBytes32 {
            value: vec![31; 32],
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };
    let mut proof = ZkInputMerkleClaimProof::default();
    proof.leaf_index = 37;
    proof.path = MessageField::some(path);
    let debug = format!("{proof:?}");

    assert!(debug.contains("leaf_index"));
    assert!(debug.contains("path_length"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("leaf_index: 37"));
    assert!(!debug.contains("path_length: 4"));
}

#[test]
fn sensitive_repeated_wire_occurrences_zeroize_prior_allocations_before_merge() {
    const SENSITIVE_BYTE_MERGES: [(&str, usize); 39] = [
        ("value", 5),
        ("encoded", 2),
        ("proof", 4),
        ("nonce_hash", 1),
        ("audience_hash", 2),
        ("transaction_data_hash", 2),
        ("claim_name_hash", 4),
        ("claim_value", 4),
        ("claim_salt", 1),
        ("request_sha256", 1),
        ("raw_fields", 2),
        ("challenge", 1),
        ("assurance_policy_id", 2),
        ("status_root", 2),
        ("claim_root", 1),
        ("issuance_binding", 1),
        ("credential_pb", 1),
        ("prepared_claims_pb", 1),
        ("credential_binding", 2),
        ("list_id", 1),
        ("nonce", 2),
        ("root", 2),
        ("root_commitment", 1),
        ("session_link_commitment", 2),
        ("signature", 2),
        ("sorted_attestation_ids", 2),
        ("url_hash", 1),
        ("audience_sha256", 1),
        ("transaction_data_sha256", 1),
        ("requested_claims_sha256", 1),
        ("verifier_policy_sha256", 1),
        ("transport_context_sha256", 1),
        ("evidence_proof_set_sha256", 1),
        ("current_state_sha256", 1),
        ("verifier_request_sha256", 1),
        ("holder_signature_p256_raw", 2),
        ("feed_id", 2),
        ("active_status_root", 1),
        ("attestation_id", 1),
    ];
    for (field, expected) in SENSITIVE_BYTE_MERGES {
        let marker = format!(
            "::zeroize::Zeroize::zeroize(&mut self.{field});\n                self.{field}.clear();\n                ::buffa::types::merge_bytes(&mut self.{field}, buf)?;"
        );
        assert_eq!(GENERATED_MESSAGE_SOURCE.matches(&marker).count(), expected);
    }
}

#[test]
fn sensitive_protojson_bytes_reject_malformed_base64() {
    let decoded = serde_json::from_str::<ZkPublicInputs>(r#"{"encoded":"AQID$"}"#);
    assert!(decoded.is_err());
}

#[test]
fn sensitive_protojson_bytes_preserve_protojson_base64_compatibility() {
    const EXPECTED: &[u8] = &[0xfb, 0xff];

    for json in [
        r#"{"encoded":"+/8="}"#,
        r#"{"encoded":"+/8"}"#,
        r#"{"encoded":"-_8="}"#,
        r#"{"encoded":"-_8"}"#,
    ] {
        let public_inputs = serde_json::from_str::<ZkPublicInputs>(json).unwrap();
        assert_eq!(public_inputs.encoded, EXPECTED);
    }

    let empty = serde_json::from_str::<ZkPublicInputs>(r#"{"encoded":null}"#).unwrap();
    assert!(empty.encoded.is_empty());

    let mut public_inputs = ZkPublicInputs::default();
    public_inputs.encoded.extend_from_slice(EXPECTED);
    let canonical = serde_json::to_string(&public_inputs).unwrap();
    assert_eq!(canonical, r#"{"encoded":"+/8="}"#);
}

#[test]
fn sensitive_borrowed_views_are_binary_only() {
    assert!(serde_json::to_string(&ZkPublicInputsView::default()).is_err());
    assert_eq!(
        GENERATED_VIEW_SOURCE
            .matches("JSON serialization is disabled for this binary-only view")
            .count(),
        108
    );
}
