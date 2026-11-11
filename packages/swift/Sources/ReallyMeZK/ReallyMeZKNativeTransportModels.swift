// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated

public protocol ReallyMeZKNativeTransport: Sendable {
  /// Dispatches one canonical operation request.
  ///
  /// Implementations must treat `request` as borrowed for the duration of this
  /// call, must not retain it, and must not log it. The native provider clears
  /// its serialized request owner after dispatch returns, but Swift `Data`
  /// copies retained by a custom transport are outside that owner.
  func dispatch(
    contextHandle: UInt64,
    request: Data
  ) async throws(ReallyMeZKError) -> Data
}

public struct ReallyMeZKNativeClaimProofBundleHandle: Sendable {
  public let claimProofBundle: Reallyme_Zk_V1_ZkClaimProofBundle

  public init(claimProofBundle: Reallyme_Zk_V1_ZkClaimProofBundle) {
    self.claimProofBundle = claimProofBundle
  }
}

public struct ReallyMeZKNativeStatusQualifiedClaimProofBundleHandle: Sendable {
  public let statusQualifiedClaimProofBundle: Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundle

  public init(statusQualifiedClaimProofBundle: Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundle) {
    self.statusQualifiedClaimProofBundle = statusQualifiedClaimProofBundle
  }
}
