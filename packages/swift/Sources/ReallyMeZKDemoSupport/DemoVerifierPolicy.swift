// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKKit
import ReallyMeZkProtoGenerated

/// Independent verifier policy for the reviewed synthetic demo fixtures.
///
/// The sample fixtures are public test material, so the policy is intentionally
/// pinned in code instead of derived from the prover-owned witness input.
public enum ReallyMeZKDemoVerifierPolicy {
  public static let verificationTimeUnix: UInt64 = 1_749_999_999

  public static func sessionBinding() -> Reallyme_Zk_V1_ZkSessionBinding {
    var binding = Reallyme_Zk_V1_ZkSessionBinding()
    binding.nonceHash = Data(verifierNonceHash)
    binding.audienceHash = Data(verifierAudienceHash)
    binding.transactionDataHash = Data(verifierTransactionDataHash)
    return binding
  }

  public static func trustedIssuer() -> Reallyme_Zk_V1_ZkP256PublicKey {
    var issuer = Reallyme_Zk_V1_ZkP256PublicKey()
    issuer.x = Data(verifierIssuerX)
    issuer.y = Data(verifierIssuerY)
    return issuer
  }

  public static func bundleVerifyRequest() throws(ReallyMeZKError)
    -> ReallyMeZKPresentationBoundClaimBundleVerifyRequest
  {
    try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
      expectedSessionBinding: sessionBinding(),
      trustedIssuers: [trustedIssuer()],
      verificationTimeUnix: verificationTimeUnix
    )
  }

  public static func validateReviewedFixtureSession(
    _ binding: Reallyme_Zk_V1_ZkSessionBinding
  ) throws(ReallyMeZKError) {
    guard binding == sessionBinding() else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
  }

  public static func validateReviewedFixtureIssuer(
    _ issuer: Reallyme_Zk_V1_ZkP256PublicKey
  ) throws(ReallyMeZKError) {
    guard issuer == trustedIssuer() else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
  }
}

private let verifierNonceHash: [UInt8] = [
  49, 50, 51, 52, 53, 54, 55, 56,
  57, 48, 49, 50, 51, 52, 53, 54,
  55, 56, 57, 48, 49, 50, 51, 52,
  53, 54, 55, 56, 57, 48, 49, 50,
]

private let verifierAudienceHash: [UInt8] = [
  209, 184, 121, 5, 4, 149, 28, 47,
  60, 116, 198, 18, 153, 185, 207, 184,
  99, 76, 161, 176, 220, 142, 59, 106,
  229, 116, 117, 188, 55, 121, 10, 37,
]

private let verifierTransactionDataHash: [UInt8] = [
  3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3,
]

private let verifierIssuerX: [UInt8] = [
  62, 209, 19, 183, 136, 59, 76, 89,
  6, 56, 55, 157, 176, 194, 28, 218,
  22, 116, 46, 208, 37, 80, 72, 191,
  67, 51, 145, 211, 116, 188, 33, 209,
]

private let verifierIssuerY: [UInt8] = [
  144, 153, 32, 154, 204, 196, 200, 162,
  36, 200, 67, 175, 164, 244, 198, 138,
  9, 13, 4, 218, 94, 152, 137, 218,
  226, 248, 238, 252, 232, 42, 55, 64,
]
