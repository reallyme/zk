// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    common_root::{
        common_credential_root_poseidon2_persona_session_authorization,
        common_credential_root_poseidon2_persona_session_binding,
        common_credential_root_poseidon2_subject_persona_link,
        common_credential_root_sha256_compressed_persona_key,
        common_credential_root_sha256_persona_session_authorization,
        common_credential_root_sha256_persona_session_binding,
        common_credential_root_sha256_subject_persona_link, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootRequestJoinContext, ZkCommonCredentialRootSubjectPublicKey,
    },
    errors::ZkError,
};

const PERSONA: ZkCommonCredentialRootSubjectPublicKey = ZkCommonCredentialRootSubjectPublicKey {
    x: [
        214, 211, 58, 222, 250, 25, 91, 7, 167, 195, 109, 160, 144, 133, 59, 140, 253, 140, 209,
        198, 136, 181, 138, 65, 222, 221, 105, 61, 28, 120, 77, 239,
    ],
    y: [
        132, 170, 186, 22, 238, 25, 93, 126, 63, 120, 36, 95, 85, 138, 93, 203, 9, 161, 102, 171,
        75, 149, 237, 237, 85, 12, 18, 69, 147, 209, 188, 166,
    ],
};
const REQUEST: ZkCommonCredentialRootRequestJoinContext =
    ZkCommonCredentialRootRequestJoinContext {
        challenge: [
            7, 146, 24, 250, 136, 252, 119, 147, 126, 171, 210, 42, 80, 63, 203, 195, 136, 33, 78,
            138, 87, 177, 93, 112, 148, 209, 57, 195, 115, 95, 8, 95,
        ],
        audience_hash: [
            64, 20, 0, 141, 176, 3, 137, 182, 205, 27, 144, 21, 90, 176, 160, 79, 61, 125, 232, 73,
            157, 120, 113, 26, 209, 108, 89, 10, 182, 12, 103, 51,
        ],
        transaction_data_hash: [
            84, 15, 118, 184, 232, 227, 82, 228, 159, 224, 228, 227, 170, 10, 230, 66, 197, 98,
            102, 204, 195, 4, 63, 234, 186, 124, 107, 190, 210, 130, 172, 194,
        ],
    };
const EXPIRY_UNIX: u64 = 1_900_000_240;

#[test]
fn compressed_persona_key_matches_circuit_fixture() {
    assert_eq!(
        common_credential_root_sha256_compressed_persona_key(PERSONA),
        [
            2, 214, 211, 58, 222, 250, 25, 91, 7, 167, 195, 109, 160, 144, 133, 59, 140, 253, 140,
            209, 198, 136, 181, 138, 65, 222, 221, 105, 61, 28, 120, 77, 239,
        ]
    );
}

#[test]
fn persona_transcripts_match_sha256_common_credential_root_fixtures() {
    assert_eq!(
        common_credential_root_sha256_subject_persona_link(PERSONA),
        [
            116, 199, 147, 109, 229, 190, 8, 43, 14, 41, 110, 184, 173, 208, 136, 8, 184, 178, 31,
            16, 22, 169, 29, 13, 2, 235, 29, 208, 66, 42, 131, 190,
        ]
    );
    assert_eq!(
        common_credential_root_sha256_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            REQUEST,
            EXPIRY_UNIX,
        ),
        [
            123, 141, 107, 246, 171, 200, 134, 42, 83, 48, 50, 138, 39, 210, 172, 16, 0, 239, 63,
            175, 135, 59, 77, 135, 148, 226, 149, 236, 150, 230, 247, 130,
        ]
    );
    assert_eq!(
        common_credential_root_sha256_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            REQUEST,
            EXPIRY_UNIX,
        ),
        [
            62, 50, 101, 186, 139, 181, 170, 84, 2, 146, 176, 237, 138, 205, 211, 66, 55, 235, 32,
            248, 194, 163, 160, 3, 118, 68, 39, 255, 180, 245, 197, 18,
        ]
    );
    assert_eq!(
        common_credential_root_sha256_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        ),
        [
            247, 136, 75, 22, 92, 32, 125, 110, 4, 64, 3, 250, 125, 153, 26, 40, 240, 207, 150,
            186, 65, 121, 14, 80, 210, 233, 201, 11, 178, 7, 92, 112,
        ]
    );
    assert_eq!(
        common_credential_root_sha256_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        ),
        [
            167, 211, 234, 51, 16, 72, 218, 80, 106, 254, 225, 231, 160, 142, 36, 137, 239, 12,
            119, 35, 235, 168, 14, 253, 154, 65, 105, 53, 236, 0, 141, 206,
        ]
    );
}

#[test]
fn persona_transcripts_bind_mode_transaction_and_expiry() {
    let mut changed_request = REQUEST;
    changed_request.transaction_data_hash[0] ^= 1;
    assert_ne!(
        common_credential_root_sha256_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        ),
        common_credential_root_sha256_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            changed_request,
            EXPIRY_UNIX,
        )
    );
    assert_ne!(
        common_credential_root_sha256_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            REQUEST,
            EXPIRY_UNIX,
        ),
        common_credential_root_sha256_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            REQUEST,
            EXPIRY_UNIX + 1,
        )
    );
    assert_ne!(
        common_credential_root_sha256_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        ),
        common_credential_root_sha256_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        )
    );
}

#[test]
fn poseidon2_persona_transcripts_match_common_credential_root_fixture_oracle() -> Result<(), ZkError>
{
    assert_eq!(
        common_credential_root_poseidon2_subject_persona_link(PERSONA)?,
        [
            8, 104, 148, 88, 251, 255, 65, 61, 93, 168, 221, 247, 186, 255, 207, 212, 197, 124, 46,
            58, 214, 108, 217, 252, 245, 173, 72, 214, 212, 31, 129, 221,
        ]
    );
    assert_eq!(
        common_credential_root_poseidon2_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        [
            36, 226, 162, 115, 132, 247, 255, 68, 51, 235, 61, 141, 233, 127, 8, 30, 37, 173, 85,
            166, 17, 233, 104, 110, 87, 90, 133, 32, 166, 31, 212, 159,
        ]
    );
    assert_eq!(
        common_credential_root_poseidon2_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        [
            40, 162, 70, 126, 53, 4, 175, 81, 47, 8, 112, 244, 186, 217, 244, 223, 95, 239, 77,
            157, 131, 56, 179, 122, 199, 127, 226, 64, 82, 96, 213, 83,
        ]
    );
    assert_eq!(
        common_credential_root_poseidon2_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        [
            1, 231, 218, 127, 241, 105, 34, 122, 137, 58, 32, 226, 168, 231, 74, 203, 34, 102, 39,
            212, 131, 235, 160, 80, 180, 46, 159, 203, 144, 109, 37, 36,
        ]
    );
    assert_eq!(
        common_credential_root_poseidon2_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        [
            40, 43, 29, 222, 207, 219, 12, 214, 5, 164, 240, 17, 20, 14, 121, 234, 219, 90, 168,
            211, 203, 4, 138, 165, 252, 60, 221, 190, 32, 180, 168, 211,
        ]
    );
    Ok(())
}

#[test]
fn poseidon2_persona_transcripts_bind_mode_transaction_and_expiry() -> Result<(), ZkError> {
    let mut changed_request = REQUEST;
    changed_request.transaction_data_hash[0] ^= 1;
    assert_ne!(
        common_credential_root_poseidon2_subject_persona_link(PERSONA)?,
        common_credential_root_sha256_subject_persona_link(PERSONA),
    );
    assert_ne!(
        common_credential_root_poseidon2_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        common_credential_root_poseidon2_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            changed_request,
            EXPIRY_UNIX,
        )?
    );
    assert_ne!(
        common_credential_root_poseidon2_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        common_credential_root_poseidon2_persona_session_authorization(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            REQUEST,
            EXPIRY_UNIX + 1,
        )?
    );
    assert_ne!(
        common_credential_root_poseidon2_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        )?,
        common_credential_root_poseidon2_persona_session_binding(
            ZkCommonCredentialRootPersonaMode::PublicPersona,
            PERSONA,
            REQUEST,
            EXPIRY_UNIX,
        )?
    );
    Ok(())
}
