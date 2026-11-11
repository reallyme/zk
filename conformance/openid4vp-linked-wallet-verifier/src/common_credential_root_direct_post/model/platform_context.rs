// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;

use reallyme_zk_platform_ffi::{
    reallyme_zk_platform_context_create, reallyme_zk_platform_context_destroy,
    ReallyMeZkPlatformContext, REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER,
};
use reallyme_zk_proto_codec::platform_abi::REALLYME_ZK_PLATFORM_STATUS_OK;

use crate::error::HarnessError;

use super::{
    super::{RELEASE_INDEX_SHA256_HEX, VERIFIER_CRS_G2_BYTES},
    fixture_io::{common_credential_root_release_root, hex_to_digest},
};

pub(in crate::common_credential_root_direct_post) struct PlatformContextGuard {
    context: *mut ReallyMeZkPlatformContext,
}

impl PlatformContextGuard {
    pub(in crate::common_credential_root_direct_post) fn create() -> Result<Self, HarnessError> {
        let root = common_credential_root_release_root()?;
        let artifact_root = root.join("artifacts");
        let artifact_root_bytes = artifact_root.as_os_str().as_encoded_bytes();
        let release_index = fs::read(root.join("release-index.pb"))?;
        let release_index_sha256 = hex_to_digest(RELEASE_INDEX_SHA256_HEX)?;
        let crs_g1 = fs::read(root.join("crs/bn254_g1.prover"))?;
        let crs_g2 = fs::read(root.join("crs/bn254_g2"))?;
        if crs_g2.len() != VERIFIER_CRS_G2_BYTES {
            return Err(HarnessError::InvalidLength);
        }
        let result = unsafe {
            reallyme_zk_platform_context_create(
                artifact_root_bytes.as_ptr(),
                artifact_root_bytes.len(),
                release_index.as_ptr(),
                release_index.len(),
                release_index_sha256.as_ptr(),
                release_index_sha256.len(),
                crs_g1.as_ptr(),
                crs_g1.len(),
                crs_g2.as_ptr(),
                crs_g2.len(),
                REALLYME_ZK_PLATFORM_CRS_MODE_FULL_PROVER,
            )
        };
        if result.status_code != REALLYME_ZK_PLATFORM_STATUS_OK || result.context.is_null() {
            return Err(HarnessError::InvalidPresentationAccepted);
        }
        Ok(Self {
            context: result.context,
        })
    }

    pub(in crate::common_credential_root_direct_post) const fn as_ptr(
        &self,
    ) -> *mut ReallyMeZkPlatformContext {
        self.context
    }
}

impl Drop for PlatformContextGuard {
    fn drop(&mut self) {
        let _status = unsafe { reallyme_zk_platform_context_destroy(self.context) };
    }
}
