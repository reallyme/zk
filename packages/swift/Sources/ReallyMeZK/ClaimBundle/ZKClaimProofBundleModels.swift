// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated
import Synchronization

public struct ReallyMeZKClaimProofBundleProveRequest: CustomStringConvertible,
  CustomDebugStringConvertible,
  Equatable, Sendable
{
  public let bundleKind: ZKClaimProofBundleKind
  public let credentialHashAlgorithm: ZKCredentialHashAlgorithm
  public let sessionBinding: Reallyme_Zk_V1_ZkSessionBinding

  public var description: String {
    "ReallyMeZKClaimProofBundleProveRequest(bundleKind: \(bundleKind.rawValue), credentialHashAlgorithm: \(credentialHashAlgorithm.rawValue), sessionBinding: <redacted>)"
  }

  public var debugDescription: String {
    description
  }

  public init(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm = .sha256,
    sessionBinding: Reallyme_Zk_V1_ZkSessionBinding
  ) {
    self.bundleKind = bundleKind
    self.credentialHashAlgorithm = credentialHashAlgorithm
    self.sessionBinding = sessionBinding
  }
}

public struct ReallyMeZKPresentationBoundClaimBundleVerifyRequest: CustomStringConvertible,
  CustomDebugStringConvertible, Equatable, Sendable
{
  public let expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding
  public let trustedIssuers: [Reallyme_Zk_V1_ZkP256PublicKey]
  public let verificationTimeUnix: UInt64

  public var description: String {
    "ReallyMeZKPresentationBoundClaimBundleVerifyRequest(expectedSessionBinding: <redacted>, trustedIssuers: <redacted>, verificationTimeUnix: \(verificationTimeUnix))"
  }

  public var debugDescription: String {
    description
  }

  public init(
    expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding,
    trustedIssuers: [Reallyme_Zk_V1_ZkP256PublicKey],
    verificationTimeUnix: UInt64
  ) throws(ReallyMeZKError) {
    guard trustedIssuers.isEmpty == false else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    guard verificationTimeUnix > 0 else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    self.expectedSessionBinding = expectedSessionBinding
    self.trustedIssuers = trustedIssuers
    self.verificationTimeUnix = verificationTimeUnix
  }
}

let reallyMeZKMaxPresentationLifetimeSeconds: UInt64 = 300

public final class ReallyMeZKSensitiveBytes: CustomStringConvertible,
  CustomDebugStringConvertible, Sendable
{
  private let storage: Mutex<ContiguousArray<UInt8>>

  public var count: Int {
    storage.withLock { bytes in
      bytes.count
    }
  }

  public var description: String {
    "ReallyMeZKSensitiveBytes(count: \(count), bytes: <redacted>)"
  }

  public var debugDescription: String {
    description
  }

  init(_ bytes: Data) throws(ReallyMeZKError) {
    guard bytes.isEmpty == false else {
      throw ReallyMeZKError.invalidProviderResponse(.emptyBuffer)
    }
    self.storage = Mutex(ContiguousArray(bytes))
  }

  deinit {
    storage.withLock { bytes in
      bytes.withUnsafeMutableBufferPointer { buffer in
        for index in buffer.indices {
          buffer[index] = 0
        }
      }
    }
  }

  public func withUnsafeBytes<Result: Sendable>(
    _ body: @Sendable (UnsafeRawBufferPointer) -> Result
  ) -> Result {
    storage.withLock { bytes in
      bytes.withUnsafeBufferPointer { buffer in
        body(UnsafeRawBufferPointer(buffer))
      }
    }
  }
}

/// Four verified claim proofs bound to the active request.
/// Issuer-signed credential validity and current status are not established.
/// This value must not authorize credential acceptance or consume a session.
public struct ReallyMeZKPresentationBoundClaimBundleVerification: CustomStringConvertible,
  CustomDebugStringConvertible,
  Sendable
{
  public let bundleKind: ZKClaimProofBundleKind
  public let verifiedStageCount: Int
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
    "ReallyMeZKPresentationBoundClaimBundleVerification(bundleKind: \(bundleKind.rawValue), verifiedStageCount: \(verifiedStageCount), sessionBinding: <redacted>, issuer: <redacted>, persona: <redacted>, claimNameHash: <redacted>, claimValue: <redacted>, claimValueLength: \(claimValueLength), credentialBinding: <redacted>, sessionLinkCommitment: <redacted>, presentationExpiryUnix: \(presentationExpiryUnix))"
  }

  public var debugDescription: String {
    description
  }

  init(
    bundleKind: ZKClaimProofBundleKind,
    verifiedStageCount: Int,
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
    self.verifiedStageCount = verifiedStageCount
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

// The composition envelope evolves independently of exact circuit revisions.
let reallyMeZKClaimProofBundleFormatVersion: UInt32 = 1
