// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    zeroize_prepared_current_state_credential_proto, zeroize_prepared_current_status_proto,
};
use buffa::MessageField;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use zeroize::ZeroizeOnDrop;

#[test]
fn moved_current_state_inputs_have_a_zeroizing_owner() {
    fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    require_zeroize_on_drop::<crate::operation::ZkPersonaCredentialEvidenceCurrentStateProveRequest>(
    );

    let mut envelope_hash = pb::ZkInputBytes32::default();
    envelope_hash.value = vec![1; 32];
    let mut signature = pb::ZkInputBytes64::default();
    signature.value = vec![2; 64];
    let mut status_chunk = pb::ZkInputBytes32::default();
    status_chunk.value = vec![3; 32];
    let mut sibling = pb::ZkInputBytes32::default();
    sibling.value = vec![4; 32];

    let mut credential = pb::ZkPersonaCredentialEvidenceCurrentStateCredentialInput {
        envelope_hash: MessageField::some(envelope_hash),
        issuer_validity_status_signature: MessageField::some(signature),
        status_index: 17,
        ..Default::default()
    };
    let mut status = pb::ZkPersonaCredentialEvidenceCurrentStatusInput {
        status_chunk: MessageField::some(status_chunk),
        path: vec![sibling],
        path_length: 1,
        ..Default::default()
    };
    zeroize_prepared_current_state_credential_proto(&mut credential);
    zeroize_prepared_current_status_proto(&mut status);
    assert!(credential
        .envelope_hash
        .as_option()
        .is_some_and(|v| v.value.is_empty()));
    assert!(credential
        .issuer_validity_status_signature
        .as_option()
        .is_some_and(|v| v.value.is_empty()));
    assert_eq!(credential.status_index, 0);
    assert!(status
        .status_chunk
        .as_option()
        .is_some_and(|v| v.value.is_empty()));
    assert!(status.path.iter().all(|sibling| sibling.value.is_empty()));
    assert_eq!(status.path_length, 0);
}
