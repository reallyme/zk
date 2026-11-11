// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz canonical artifact, capability-registry, and release-index admission.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_zk_proto_codec::{
    artifact::decode_artifact_manifest, capability_registry::decode_capability_registry,
    release::decode_release_index,
};

fuzz_target!(|data: &[u8]| {
    let _manifest = decode_artifact_manifest(data);
    let _registry = decode_capability_registry(data);
    let _release = decode_release_index(data);
});
