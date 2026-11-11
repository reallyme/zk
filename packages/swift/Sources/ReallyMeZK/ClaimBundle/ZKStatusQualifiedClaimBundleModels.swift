// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated

/// Byte length of an issuer status list root, list identifier, and URL hash.
let reallyMeZKIssuerStatusDigestByteCount = 32

/// Largest issuer status list length a verifier may supply.
let reallyMeZKMaxIssuerStatusListLength: UInt64 = 1_000_000

/// Four claim proofs plus the issuer validity and current-status proof.
let reallyMeZKStatusQualifiedVerifiedProofCount: UInt32 = 5

/// Verifier-owned inputs for status-qualified claim bundle verification.
///
/// The provider has no network access and no trust store. Before building this
/// request the verifier application must authenticate the issuer status list:
/// its signature, its issuer, its freshness, and its rollback floor. The status
/// list must be authenticated for `expectedIssuer`, the credential issuer key
/// even when the status list uses a delegated signing key. The status
/// list values must never be taken from the holder's presentation.
public struct ReallyMeZKStatusQualifiedClaimBundleVerifyRequest: CustomStringConvertible,
  CustomDebugStringConvertible, Equatable, Sendable
{
  public let expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding
  /// Credential issuer for which the verifier authenticated the current status list.
  public let expectedIssuer: Reallyme_Zk_V1_ZkP256PublicKey
  public let trustedIssuers: [Reallyme_Zk_V1_ZkP256PublicKey]
  public let verificationTimeUnix: UInt64
  /// The authenticated, current issuer status list selected by the verifier.
  public let currentIssuerStatus: Reallyme_Zk_V1_ZkCommonCredentialRootIssuerStatusExpectation

  public var description: String {
    "ReallyMeZKStatusQualifiedClaimBundleVerifyRequest(expectedSessionBinding: <redacted>, expectedIssuer: <redacted>, trustedIssuers: <redacted>, verificationTimeUnix: \(verificationTimeUnix), currentIssuerStatus: <redacted>)"
  }

  public var debugDescription: String {
    description
  }

  public init(
    expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding,
    expectedIssuer: Reallyme_Zk_V1_ZkP256PublicKey,
    trustedIssuers: [Reallyme_Zk_V1_ZkP256PublicKey],
    verificationTimeUnix: UInt64,
    currentIssuerStatus: Reallyme_Zk_V1_ZkCommonCredentialRootIssuerStatusExpectation
  ) throws(ReallyMeZKError) {
    guard trustedIssuers.isEmpty == false else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    guard trustedIssuers.contains(expectedIssuer) else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    guard verificationTimeUnix > 0 else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    guard issuerStatusDigestIsWellFormed(currentIssuerStatus.root),
      issuerStatusDigestIsWellFormed(currentIssuerStatus.listID),
      issuerStatusDigestIsWellFormed(currentIssuerStatus.urlHash)
    else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    guard currentIssuerStatus.length > 0,
      currentIssuerStatus.length <= reallyMeZKMaxIssuerStatusListLength
    else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    switch currentIssuerStatus.purpose {
    case .revocation, .suspension:
      break
    case .unspecified, .UNRECOGNIZED:
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    self.expectedSessionBinding = expectedSessionBinding
    self.expectedIssuer = expectedIssuer
    self.trustedIssuers = trustedIssuers
    self.verificationTimeUnix = verificationTimeUnix
    self.currentIssuerStatus = currentIssuerStatus
  }
}

/// Five verified proofs checked against the verifier's current issuer status list.
///
/// This value establishes that the four claim proofs and the issuer
/// credential-status proof verified under the production proof suite, that the
/// claim is bound to the active request, that the issuer is one of the
/// verifier's trusted issuers, that the presentation has not expired, that the
/// credential is issuer-signed and valid, and that it is current under the
/// issuer status list the verifier supplied for the reported status purpose.
/// It is the only claim bundle result that may be used for credential
/// acceptance.
///
/// Verification does not consume the session. The verifier must atomically
/// accept the active session exactly once before granting access.
///
/// Only a provider can create this value. It is unrelated to
/// ``ReallyMeZKPresentationBoundClaimBundleVerification`` and cannot be
/// derived from it.
public struct ReallyMeZKStatusQualifiedClaimBundleVerification: CustomStringConvertible,
  CustomDebugStringConvertible,
  Sendable
{
  public let bundleKind: ZKClaimProofBundleKind
  public let verifiedProofCount: Int
  /// Meaning of the issuer status bit the credential was checked against.
  public let statusPurpose: Reallyme_Zk_V1_ZkIssuerStatusPurpose
  public let sessionBinding: Reallyme_Zk_V1_ZkSessionBinding
  public let issuer: Reallyme_Zk_V1_ZkP256PublicKey
  public let persona: Reallyme_Zk_V1_ZkP256PublicKey?
  /// Verified claim-name hash. Callers must treat this as privacy-sensitive
  /// linkage material and avoid logging or long-lived storage unless policy
  /// explicitly requires it.
  public let claimNameHash: ReallyMeZKSensitiveBytes
  /// Verified disclosed claim bytes. This may contain PII and is owned by a
  /// best-effort zeroizing container with independently owned storage. Swift
  /// runtimes may still create transient copies; callers should use scoped
  /// access and avoid creating unmanaged copies.
  public let claimValue: ReallyMeZKSensitiveBytes
  public let claimValueLength: UInt32
  /// Presentation-scoped credential/root commitment. Applications that need
  /// to pair multiple disclosed leaves from the same issued credential should
  /// compare this value after both bundles verify.
  public let credentialBinding: ReallyMeZKSensitiveBytes
  /// Presentation-scoped link commitment. Fresh verifier inputs make this
  /// presentation-scoped, but reuse can make it correlatable.
  public let sessionLinkCommitment: ReallyMeZKSensitiveBytes
  public let presentationExpiryUnix: UInt64

  public var description: String {
    "ReallyMeZKStatusQualifiedClaimBundleVerification(bundleKind: \(bundleKind.rawValue), verifiedProofCount: \(verifiedProofCount), statusPurpose: \(issuerStatusPurposeLabel(statusPurpose)), sessionBinding: <redacted>, issuer: <redacted>, persona: <redacted>, claimNameHash: <redacted>, claimValue: <redacted>, claimValueLength: \(claimValueLength), credentialBinding: <redacted>, sessionLinkCommitment: <redacted>, presentationExpiryUnix: \(presentationExpiryUnix))"
  }

  public var debugDescription: String {
    description
  }

  init(
    bundleKind: ZKClaimProofBundleKind,
    verifiedProofCount: Int,
    statusPurpose: Reallyme_Zk_V1_ZkIssuerStatusPurpose,
    sessionBinding: Reallyme_Zk_V1_ZkSessionBinding,
    issuer: Reallyme_Zk_V1_ZkP256PublicKey,
    persona: Reallyme_Zk_V1_ZkP256PublicKey?,
    claimNameHash: ReallyMeZKSensitiveBytes,
    claimValue: ReallyMeZKSensitiveBytes,
    claimValueLength: UInt32,
    credentialBinding: ReallyMeZKSensitiveBytes,
    sessionLinkCommitment: ReallyMeZKSensitiveBytes,
    presentationExpiryUnix: UInt64
  ) {
    self.bundleKind = bundleKind
    self.verifiedProofCount = verifiedProofCount
    self.statusPurpose = statusPurpose
    self.sessionBinding = sessionBinding
    self.issuer = issuer
    self.persona = persona
    self.claimNameHash = claimNameHash
    self.claimValue = claimValue
    self.claimValueLength = claimValueLength
    self.credentialBinding = credentialBinding
    self.sessionLinkCommitment = sessionLinkCommitment
    self.presentationExpiryUnix = presentationExpiryUnix
  }
}

private func issuerStatusDigestIsWellFormed(_ digest: Data) -> Bool {
  digest.count == reallyMeZKIssuerStatusDigestByteCount && digest.contains(where: { $0 != 0 })
}

private func issuerStatusPurposeLabel(
  _ purpose: Reallyme_Zk_V1_ZkIssuerStatusPurpose
) -> String {
  switch purpose {
  case .revocation:
    return "revocation"
  case .suspension:
    return "suspension"
  case .unspecified, .UNRECOGNIZED:
    return "unspecified"
  }
}
