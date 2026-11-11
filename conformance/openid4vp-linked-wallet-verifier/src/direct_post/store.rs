// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use reallyme_identity_openid4vp_product_store::{
    EncryptedVerifierFileStore, P256ResponseKeyRegistry,
};
use reallyme_openid4vp_runtime::{
    AuthorizationRequestLaunchStore, AuthorizationRequestLaunchStoreRecord, HostedRequestObject,
};
use reallyme_openid4vp_types::AuthorizationRequestObject;
use reallyme_openid4vp_verifier::SessionRecord;
use secrecy::SecretBox;
use zeroize::Zeroizing;

use crate::direct_post::{REQUEST_OBJECT_KEY, TEST_P256_SECRET};
use crate::error::HarnessError;
use crate::runtime::SESSION_KEY;

static NEXT_STORE_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ProductStoreDirectory {
    path: PathBuf,
}

impl ProductStoreDirectory {
    fn create() -> Result<Self, HarnessError> {
        let path = std::env::temp_dir().join(format!(
            "reallyme-zk-linked-openid4vp-store-{}-{}",
            std::process::id(),
            NEXT_STORE_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { path })
    }
}

impl Drop for ProductStoreDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn product_store(
    request: AuthorizationRequestObject,
    session: SessionRecord,
) -> Result<(Arc<EncryptedVerifierFileStore>, ProductStoreDirectory), HarnessError> {
    let directory = ProductStoreDirectory::create()?;
    let store = Arc::new(EncryptedVerifierFileStore::open(
        &directory.path,
        SecretBox::new(Box::new(Zeroizing::new([0x31_u8; 32]))),
    )?);
    store.register_response_key(
        SESSION_KEY.to_owned(),
        Zeroizing::new(TEST_P256_SECRET.to_vec()),
        session.binding.expiry_unix,
    )?;
    store.store_authorization_request_launch(AuthorizationRequestLaunchStoreRecord {
        session_key: SESSION_KEY,
        session,
        request_object_key: REQUEST_OBJECT_KEY,
        request_object: HostedRequestObject::deferred_post(request)?,
        evidence_context: None,
    })?;
    Ok((store, directory))
}

pub(crate) fn status_floor_store(
) -> Result<(Arc<EncryptedVerifierFileStore>, ProductStoreDirectory), HarnessError> {
    let directory = ProductStoreDirectory::create()?;
    let store = Arc::new(EncryptedVerifierFileStore::open(
        &directory.path,
        SecretBox::new(Box::new(Zeroizing::new([0x31_u8; 32]))),
    )?);
    Ok((store, directory))
}
