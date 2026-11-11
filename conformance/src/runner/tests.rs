// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::has_complete_mutation_catalog;
use reallyme_zk_proto_codec::verification_vector::VerificationVectorMutation;

#[test]
fn complete_mutation_catalog_requires_exact_membership_and_order() {
    let complete = VerificationVectorMutation::BUNDLE_CONFORMANCE;
    assert!(has_complete_mutation_catalog(complete.iter().copied()));
    assert!(!has_complete_mutation_catalog(
        complete[..complete.len() - 1].iter().copied()
    ));

    let mut reordered = complete.to_vec();
    reordered.swap(0, 1);
    assert!(!has_complete_mutation_catalog(reordered));
}
