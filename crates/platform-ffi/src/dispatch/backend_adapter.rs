// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{errors::ZkError, proofs::ZkProofSuite};
use reallyme_zk_backend_bb::{
    BbCommonCredentialRootRawVerifyRequest, BbStageProveRequest, BbStageProveResponse,
    BbStageVerifyRequest, LinkedBarretenbergBackend, NativeBarretenbergBackend,
};

pub(super) struct BorrowedPlatformBackend<'a> {
    backend: &'a NativeBarretenbergBackend,
}

impl<'a> BorrowedPlatformBackend<'a> {
    pub(super) const fn new(backend: &'a NativeBarretenbergBackend) -> Self {
        Self { backend }
    }
}

impl LinkedBarretenbergBackend for BorrowedPlatformBackend<'_> {
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        self.backend.supports_proof_suite(proof_suite)
    }

    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        self.backend.prove_stage(request)
    }

    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        self.backend.verify_stage(request)
    }

    fn verify_common_credential_root_raw(
        &self,
        request: BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        self.backend.verify_common_credential_root_raw(request)
    }
}
