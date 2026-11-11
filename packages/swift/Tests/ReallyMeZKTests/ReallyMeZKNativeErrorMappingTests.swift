// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKNativeErrorMappingTests {
  @Test
  func unsupportedReasonsRemainDistinct() {
    #expect(providerFailureReason(from: .unsupportedProofSuite) == .unsupportedSuite)
    #expect(providerFailureReason(from: .unsupportedTransport) == .unsupportedTransport)
    #expect(providerFailureReason(from: .unsupportedCircuit) == .unsupportedCircuit)
    #expect(providerFailureReason(from: .unknownCircuit) == .unsupportedCircuit)
  }

  @Test
  func policyProofRejectionReasonsStayTyped() {
    let cases: [Reallyme_Zk_V1_ZkErrorReason] = [
      .untrustedIssuer,
      .presentationExpired,
      .presentationExpiryTooFar,
    ]

    for reason in cases {
      #expect(providerFailureReason(from: reason) == .proofRejected)
    }
  }

  @Test
  func witnessMetricsAdmitLargestExactCircuitTransportBudget() throws {
    let byteCount = try ZKWitnessByteCount(claimProofBundleWitnessTransportBudgetBytes)

    #expect(byteCount.value == claimProofBundleWitnessTransportBudgetBytes)
  }

  @Test
  func witnessMetricsRejectAboveExactCircuitTransportBudget() {
    #expect(throws: ReallyMeZKError.invalidProviderResponse(.oversizedBuffer)) {
      _ = try ZKWitnessByteCount(claimProofBundleWitnessTransportBudgetBytes + 1)
    }
  }
}

private let claimProofBundleWitnessTransportBudgetBytes = 4 * 1_024 * 1_024
