// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKDemoSupport
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKDemoFixtureTests {
  @Test
  func demoFixtureProtobufsMapEveryProfileStageToGeneratedWitnessInput() throws {
    for bundleKind in ZKClaimProofBundleKind.allCases {
      for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
        for stage in ZKClaimProofBundleStage.allCases {
          let data = try fixtureData(
            bundleKind: bundleKind, credentialHashAlgorithm: credentialHashAlgorithm, stage: stage)
          let input: Reallyme_Zk_V1_ZkStageWitnessInput
          do {
            input = try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
              bundleKind: bundleKind,
              stage: stage,
              protobufData: data
            )
          } catch {
            Issue.record(
              "Fixture rejected for \(bundleKind.rawValue) \(credentialHashAlgorithm.rawValue) \(stage.rawValue): \(error)"
            )
            continue
          }

          switch (bundleKind, stage, input.input) {
          case (.credentialSubjectClaim, .session, .credentialSubjectClaimSession?),
            (.privatePersona, .session, .privatePersonaSession?),
            (_, .credentialEnvelope, .credentialEnvelope?),
            (_, .credentialRoot, .credentialRoot?),
            (.credentialSubjectClaim, .claim, .credentialSubjectClaim?),
            (.privatePersona, .claim, .privatePersonaClaim?):
            break
          default:
            Issue.record("Fixture mapped to the wrong generated witness input.")
          }
        }
      }
    }
  }

  @Test
  func demoFixtureRejectsMalformedProtobufBytes() throws {
    #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
        bundleKind: .credentialSubjectClaim,
        stage: .session,
        protobufData: Data([0x08, 0x80])
      )
    }
  }

  @Test
  func demoFixtureRejectsWrongProfileStageBinding() throws {
    let data = try fixtureData(
      bundleKind: .privatePersona, credentialHashAlgorithm: .sha256, stage: .session)

    #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
        bundleKind: .credentialSubjectClaim,
        stage: .session,
        protobufData: data
      )
    }
  }

  @Test
  func demoFixtureSessionBindingIncludesTransactionDataHash() throws {
    for bundleKind in ZKClaimProofBundleKind.allCases {
      for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
        let data = try fixtureData(
          bundleKind: bundleKind, credentialHashAlgorithm: credentialHashAlgorithm, stage: .session)
        let input = try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
          bundleKind: bundleKind,
          stage: .session,
          protobufData: data
        )
        let binding = try ReallyMeZKDemoFixtureWitnessInputs.sessionBinding(input: input)

        #expect(binding.nonceHash.count == 32)
        #expect(binding.audienceHash.count == 32)
        #expect(binding.transactionDataHash.count == 32)
      }
    }
  }

  @Test
  func demoFixtureRejectsOversizedProtobufBeforeParsing() {
    let oversized = Data(repeating: 0, count: 16_385)

    #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
        bundleKind: .credentialSubjectClaim,
        stage: .session,
        protobufData: oversized
      )
    }
  }

  private func fixtureData(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    stage: ZKClaimProofBundleStage
  ) throws -> Data {
    let resourceName = try ReallyMeZKDemoFixtureWitnessInputs.fixtureResourceName(
      bundleKind: bundleKind,
      credentialHashAlgorithm: credentialHashAlgorithm,
      stage: stage
    )
    let url = fixtureDirectory()
      .appendingPathComponent("\(resourceName).pb")
    return try Data(contentsOf: url)
  }

  private func fixtureDirectory() -> URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("vectors")
      .appendingPathComponent("demo-flow-inputs")
      .appendingPathComponent("v1")
  }
}
