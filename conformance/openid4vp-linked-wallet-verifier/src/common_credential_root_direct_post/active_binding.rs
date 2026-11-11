// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fs, io::Write, path::Path};

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_wallet::WalletAuthorizationRequest;

use crate::{
    constants::COMMON_CREDENTIAL_ROOT_QUERY,
    direct_post::{verified_request, DIRECT_POST_CLIENT_ID},
    error::HarnessError,
    fixture::lower_hex,
};

use super::flow::request_for_common_credential_root_fixture_at;

pub(crate) const SECOND_REQUEST_NONCE: &str =
    "linked-common-credential-root-second-request-nonce-v1";

pub(crate) fn write_active_binding(
    path: &Path,
    verification_time_unix: u64,
    second_request: bool,
) -> Result<(), HarnessError> {
    let query_id = QueryId::parse(COMMON_CREDENTIAL_ROOT_QUERY)?;
    let mut request =
        request_for_common_credential_root_fixture_at(&query_id, None, verification_time_unix)?;
    if second_request {
        request.nonce = SECOND_REQUEST_NONCE.to_owned();
    }
    let verified = verified_request(request, verification_time_unix)?;
    let binding = reallyme_openid4vp_formats::build_zk_presentation_binding(
        &verified.request().nonce,
        DIRECT_POST_CLIENT_ID,
        None,
    );
    let mut file = fs::File::create(path)?;
    writeln!(file, "challenge_hex={}", lower_hex(&binding.nonce_hash)?)?;
    writeln!(file, "audience_hex={}", lower_hex(&binding.audience_hash)?)?;
    writeln!(
        file,
        "transaction_hex={}",
        lower_hex(&reallyme_zk_api::proofs::ABSENT_TRANSACTION_DATA_HASH)?
    )?;
    Ok(())
}
