// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the sealed ProtoJSON surface, including the proving-transport guard.

#![no_main]

use core::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    ZkArtifactManifest, ZkCapabilityRegistry, ZkProviderOperationRequest,
    ZkProviderOperationResponse, ZkReleaseIndex,
};
use reallyme_zk_proto_codec::protojson::{zk_proto_from_json, zk_proto_to_json, ZkProtoJson};

fn round_trip_if_admitted<M>(data: &[u8])
where
    M: Debug + PartialEq + ZkProtoJson,
{
    let Ok(message) = zk_proto_from_json::<M>(data) else {
        return;
    };
    let Ok(encoded) = zk_proto_to_json(&message) else {
        return;
    };
    if zk_proto_from_json::<M>(encoded.as_bytes()).as_ref() != Ok(&message) {
        // An admitted value that cannot round-trip is a fuzzing invariant
        // violation. Abort without formatting untrusted input into diagnostics.
        std::process::abort();
    }
}

fuzz_target!(|data: &[u8]| {
    round_trip_if_admitted::<ZkProviderOperationRequest>(data);
    round_trip_if_admitted::<ZkProviderOperationResponse>(data);
    round_trip_if_admitted::<ZkArtifactManifest>(data);
    round_trip_if_admitted::<ZkCapabilityRegistry>(data);
    round_trip_if_admitted::<ZkReleaseIndex>(data);
});
