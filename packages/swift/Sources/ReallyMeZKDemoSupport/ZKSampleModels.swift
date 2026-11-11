// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZKKit

public struct ZKStageTiming: Equatable, Sendable {
  public let witnessMilliseconds: Double
  public let proveMilliseconds: Double
  public let verifyMilliseconds: Double

  public init(
    witnessMilliseconds: Double,
    proveMilliseconds: Double,
    verifyMilliseconds: Double
  ) throws(ReallyMeZKError) {
    guard witnessMilliseconds.isFinite, witnessMilliseconds >= 0.0 else {
      throw ReallyMeZKError.invalidProviderResponse(.invalidTiming)
    }
    guard proveMilliseconds.isFinite, proveMilliseconds >= 0.0 else {
      throw ReallyMeZKError.invalidProviderResponse(.invalidTiming)
    }
    guard verifyMilliseconds.isFinite, verifyMilliseconds >= 0.0 else {
      throw ReallyMeZKError.invalidProviderResponse(.invalidTiming)
    }
    self.witnessMilliseconds = witnessMilliseconds
    self.proveMilliseconds = proveMilliseconds
    self.verifyMilliseconds = verifyMilliseconds
  }
}

public struct ZKSampleResult: Equatable, Sendable {
  public let bundleKind: ZKClaimProofBundleKind
  public let verificationKeySize: Int
  public let publicInputsSize: Int
  public let proofSize: Int
  public let witnessMilliseconds: Double
  public let proveMilliseconds: Double
  public let verifyMilliseconds: Double
  public let fixtureBundleVerified: Bool
}
