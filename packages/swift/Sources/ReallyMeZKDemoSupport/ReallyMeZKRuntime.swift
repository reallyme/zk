// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKKit
import ReallyMeZkProtoGenerated

public enum ReallyMeZKRuntime {
  public static let bundleKinds = ZKClaimProofBundleKind.allCases
  public static let stages = ZKClaimProofBundleStage.allCases

  public static func makeSampleRunner<Provider: ReallyMeZKClaimProofBundleProvider>(
    provider: Provider,
    bundleVerifyRequestProvider:
      @escaping ReallyMeZKSampleRunner<Provider>.BundleVerifyRequestProvider,
    witnessInputProvider: @escaping ReallyMeZKSampleRunner<Provider>.WitnessInputProvider = {
      _, _, _ in
      Reallyme_Zk_V1_ZkStageWitnessInput()
    }
  ) -> ReallyMeZKSampleRunner<Provider> {
    ReallyMeZKSampleRunner(
      provider: provider,
      bundleVerifyRequestProvider: bundleVerifyRequestProvider,
      witnessInputProvider: witnessInputProvider
    )
  }
}
