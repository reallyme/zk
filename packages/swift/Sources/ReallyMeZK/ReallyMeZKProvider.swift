// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated

public protocol ReallyMeZKProvider: Sendable {
  associatedtype WitnessHandle: Sendable
  associatedtype ProofHandle: Sendable

  func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<WitnessHandle>

  func prove(
    request: ReallyMeZKStageProveRequest,
    witness: WitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<ProofHandle>

  /// Verifies one diagnostic stage proof against its typed public binding.
  /// Production native builds reject this operation with `.unsupportedTransport`.
  ///
  /// A successful return is stage-scoped. SDK demos, fixture validation, and
  /// backend diagnostics use this path for immediate feedback; production
  /// presentation acceptance must verify joined credential validity and current
  /// status as well as issuer, audience, nonce, transaction-data, and expiry policy. A standalone
  /// credential-envelope stage result must never grant claim admission by itself.
  func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: ProofHandle
  ) async throws(ReallyMeZKError) -> Bool

  func releaseWitness(
    _ witness: WitnessHandle
  ) async throws(ReallyMeZKError)
}

public protocol ReallyMeZKPresentationBoundClaimBundleVerifier: Sendable {
  associatedtype ClaimProofBundleHandle: Sendable

  /// Verifies presentation binding, trusted issuer, and presentation expiry only.
  /// Credential acceptance additionally requires joined signed validity/current
  /// status evidence and atomic single-use session enforcement by the verifier.
  func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: ClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification
}

public protocol ReallyMeZKStatusQualifiedClaimBundleVerifier: Sendable {
  associatedtype StatusQualifiedClaimProofBundleHandle: Sendable

  /// Verifies the four claim proofs, the issuer credential-status proof, and
  /// the verifier's current issuer status list. This is the only claim bundle
  /// verification that may be used for credential acceptance.
  ///
  /// The verifier application authenticates the issuer status list before
  /// building the request. Verification does not consume the session; the
  /// verifier must atomically accept the active session exactly once before
  /// granting access.
  func verifyStatusQualifiedClaimBundle(
    request: ReallyMeZKStatusQualifiedClaimBundleVerifyRequest,
    statusQualifiedClaimProofBundle: StatusQualifiedClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKStatusQualifiedClaimBundleVerification
}

public protocol ReallyMeZKClaimProofBundleProvider: ReallyMeZKProvider,
  ReallyMeZKPresentationBoundClaimBundleVerifier
{
  /// Proves a complete production bundle from four retained stage witnesses.
  ///
  /// A successful return consumes every supplied witness handle. If proving
  /// throws, callers perform best-effort release of the original handles and
  /// keep the proof error as primary; provider implementations must therefore
  /// make release single-use and stale-handle safe.
  func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [WitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<ClaimProofBundleHandle>
}

public struct UnsupportedReallyMeZKProvider: ReallyMeZKProvider {
  public struct UnsupportedWitnessHandle: Sendable {}
  public struct UnsupportedProofHandle: Sendable {}

  public init() {}

  public func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<UnsupportedWitnessHandle> {
    _ = request
    throw ReallyMeZKError.providerUnavailable
  }

  public func prove(
    request: ReallyMeZKStageProveRequest,
    witness: UnsupportedWitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<UnsupportedProofHandle> {
    _ = request
    _ = witness
    throw ReallyMeZKError.providerUnavailable
  }

  public func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: UnsupportedProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    _ = request
    _ = proof
    throw ReallyMeZKError.providerUnavailable
  }

  public func releaseWitness(
    _ witness: UnsupportedWitnessHandle
  ) async throws(ReallyMeZKError) {
    _ = witness
    throw ReallyMeZKError.providerUnavailable
  }
}

public struct UnsupportedReallyMeZKPresentationBoundClaimBundleVerifier:
  ReallyMeZKPresentationBoundClaimBundleVerifier
{
  public struct UnsupportedClaimProofBundleHandle: Sendable {}

  public init() {}

  public func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: UnsupportedClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    _ = request
    _ = claimProofBundle
    throw ReallyMeZKError.providerUnavailable
  }
}

public struct UnsupportedReallyMeZKStatusQualifiedClaimBundleVerifier:
  ReallyMeZKStatusQualifiedClaimBundleVerifier
{
  public struct UnsupportedStatusQualifiedClaimProofBundleHandle: Sendable {}

  public init() {}

  public func verifyStatusQualifiedClaimBundle(
    request: ReallyMeZKStatusQualifiedClaimBundleVerifyRequest,
    statusQualifiedClaimProofBundle: UnsupportedStatusQualifiedClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKStatusQualifiedClaimBundleVerification {
    _ = request
    _ = statusQualifiedClaimProofBundle
    throw ReallyMeZKError.providerUnavailable
  }
}

public struct UnsupportedReallyMeZKClaimProofBundleProvider: ReallyMeZKClaimProofBundleProvider,
  ReallyMeZKStatusQualifiedClaimBundleVerifier
{
  public struct UnsupportedWitnessHandle: Sendable {}
  public struct UnsupportedProofHandle: Sendable {}
  public struct UnsupportedClaimProofBundleHandle: Sendable {}
  public struct UnsupportedStatusQualifiedClaimProofBundleHandle: Sendable {}

  public init() {}

  public func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<UnsupportedWitnessHandle> {
    _ = request
    throw ReallyMeZKError.providerUnavailable
  }

  public func prove(
    request: ReallyMeZKStageProveRequest,
    witness: UnsupportedWitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<UnsupportedProofHandle> {
    _ = request
    _ = witness
    throw ReallyMeZKError.providerUnavailable
  }

  public func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: UnsupportedProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    _ = request
    _ = proof
    throw ReallyMeZKError.providerUnavailable
  }

  public func releaseWitness(
    _ witness: UnsupportedWitnessHandle
  ) async throws(ReallyMeZKError) {
    _ = witness
    throw ReallyMeZKError.providerUnavailable
  }

  public func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [UnsupportedWitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<
    UnsupportedClaimProofBundleHandle
  > {
    _ = request
    _ = witnesses
    throw ReallyMeZKError.providerUnavailable
  }

  public func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: UnsupportedClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    _ = request
    _ = claimProofBundle
    throw ReallyMeZKError.providerUnavailable
  }

  public func verifyStatusQualifiedClaimBundle(
    request: ReallyMeZKStatusQualifiedClaimBundleVerifyRequest,
    statusQualifiedClaimProofBundle: UnsupportedStatusQualifiedClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKStatusQualifiedClaimBundleVerification {
    _ = request
    _ = statusQualifiedClaimProofBundle
    throw ReallyMeZKError.providerUnavailable
  }
}
