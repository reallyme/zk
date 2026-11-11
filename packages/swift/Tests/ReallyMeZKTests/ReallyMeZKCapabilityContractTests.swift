// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import Testing

struct ReallyMeZKCapabilityContractTests {
  @Test func disclosureAndPredicatesRoundTripSeparately() throws {
    var capabilities = validCapabilities()
    capabilities.predicateTypes = [.range]
    let decoded = try Reallyme_Zk_V1_ZkCircuitCapabilities(
      serializedBytes: capabilities.serializedData()
    )
    try ReallyMeZKCapabilityContract.validate(decoded)
    #expect(decoded.disclosureModes == [.reveal])
    #expect(decoded.predicateTypes == [.range])
  }

  @Test func unknownCodesFailClosed() {
    for value in [3, 4, 5, 99] {
      var capabilities = validCapabilities()
      capabilities.disclosureModes = [.UNRECOGNIZED(value)]
      #expect(throws: ReallyMeZKProtoCodecError.invalidCapabilities) {
        try ReallyMeZKCapabilityContract.validate(capabilities)
      }
    }
    for value in [0, 99] {
      var capabilities = validCapabilities()
      capabilities.semanticGuarantees = value == 0 ? [.unspecified] : [.UNRECOGNIZED(value)]
      #expect(throws: ReallyMeZKProtoCodecError.invalidCapabilities) {
        try ReallyMeZKCapabilityContract.validate(capabilities)
      }
    }
    var capabilities = validCapabilities()
    capabilities.predicateTypes = [.UNRECOGNIZED(99)]
    #expect(throws: ReallyMeZKProtoCodecError.invalidCapabilities) {
      try ReallyMeZKCapabilityContract.validate(capabilities)
    }
  }

  private func validCapabilities() -> Reallyme_Zk_V1_ZkCircuitCapabilities {
    var capabilities = Reallyme_Zk_V1_ZkCircuitCapabilities()
    capabilities.subjectBinding = .required
    capabilities.personaBinding = .forbidden
    capabilities.mayBeCorrelated = true
    capabilities.disclosureModes = [.reveal]
    capabilities.semanticGuarantees = [.sessionBound]
    return capabilities
  }
}
