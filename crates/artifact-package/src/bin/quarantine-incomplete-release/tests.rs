// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_arguments, ArtifactPackageErrorReason, OsString};

#[test]
fn parser_requires_exact_argument_count() {
    let missing = [OsString::from("binary")];
    let extra = ["binary", "artifacts", "0.1.0", "extra"].map(OsString::from);

    assert_eq!(
        parse_arguments(missing).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::InvalidArguments)
    );
    assert_eq!(
        parse_arguments(extra).err().map(|error| error.reason()),
        Some(ArtifactPackageErrorReason::InvalidArguments)
    );
}
