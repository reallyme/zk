// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZkProtoGenerated

/// Validates capability vocabulary at the protobuf boundary.
/// Circuit support and trusted guarantees require canonical Rust manifest admission.
public enum ReallyMeZKCapabilityContract {
  public static func validate(
    _ capabilities: Reallyme_Zk_V1_ZkCircuitCapabilities
  ) throws(ReallyMeZKProtoCodecError) {
    switch capabilities.subjectBinding {
    case .required, .forbidden, .optional: break
    case .unspecified, .UNRECOGNIZED: throw .invalidCapabilities
    }
    switch capabilities.personaBinding {
    case .required, .forbidden, .optional: break
    case .unspecified, .UNRECOGNIZED: throw .invalidCapabilities
    }
    for mode in capabilities.disclosureModes {
      switch mode {
      case .hidden, .reveal: break
      case .unspecified, .UNRECOGNIZED: throw .invalidCapabilities
      }
    }
    for predicate in capabilities.predicateTypes {
      switch predicate {
      case .greaterThanOrEqual, .lessThanOrEqual, .range: break
      case .unspecified, .UNRECOGNIZED: throw .invalidCapabilities
      }
    }
    for guarantee in capabilities.semanticGuarantees {
      switch guarantee {
      case .sessionBound, .audienceBound, .transactionDataBound,
        .credentialAuthenticity, .claimIntegrity, .linkablePersonaBinding,
        .privatePersonaBinding:
        break
      case .unspecified, .UNRECOGNIZED: throw .invalidCapabilities
      }
    }
  }
}
