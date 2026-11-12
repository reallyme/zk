// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emits explicit, hash-pinned static-link directives for native builds.

use std::{
    env, fs,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

const BARRETENBERG_LIB_DIR_ENV: &str = "REALLYME_BARRETENBERG_LIB_DIR";
const NATIVE_FEATURE_ENV: &str = "CARGO_FEATURE_NATIVE";
const LIBBB_FILE_NAME: &str = "libbb-external.a";
const TOOLCHAIN_LOCK_RELATIVE_PATH: &str = "toolchain-lock.json";

fn main() {
    println!("cargo:rerun-if-env-changed={BARRETENBERG_LIB_DIR_ENV}");
    println!("cargo:rerun-if-changed=native/reallyme_bbapi_shim.cc");
    println!("cargo:rerun-if-changed=native/reallyme_bbapi_shim.h");
    println!("cargo:rerun-if-changed={TOOLCHAIN_LOCK_RELATIVE_PATH}");

    if env::var_os(NATIVE_FEATURE_ENV).is_none() {
        return;
    }

    let manifest_dir = read_env_path("CARGO_MANIFEST_DIR");
    let target_os = read_env_string("CARGO_CFG_TARGET_OS");
    let target_key = target_static_library_key();
    let library_directory = read_env_path(BARRETENBERG_LIB_DIR_ENV);
    let library_path = library_directory.join(LIBBB_FILE_NAME);
    let output_directory = read_env_path("OUT_DIR");
    println!("cargo:rerun-if-changed={}", library_path.display());
    stage_pinned_barretenberg_library(&manifest_dir, &library_path, &output_directory, target_key);
    compile_shim_from_source(&manifest_dir);
    emit_static_link(&output_directory, "bb-external");
    emit_runtime_links(target_os.as_str());
}

fn read_env_path(name: &str) -> PathBuf {
    match env::var_os(name) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => fail(&["missing required environment variable ", name]),
    }
}

fn target_static_library_key() -> &'static str {
    let target = read_env_string("TARGET");
    let arch = read_env_string("CARGO_CFG_TARGET_ARCH");
    let os = read_env_string("CARGO_CFG_TARGET_OS");
    match (arch.as_str(), os.as_str()) {
        ("aarch64", "macos") => "darwinArm64",
        ("x86_64", "macos") => "darwinX86_64",
        ("x86_64", "linux") => "linuxAmd64",
        ("aarch64", "ios") if target.contains("ios-sim") => "iosSimulatorArm64",
        ("aarch64", "ios") => "iosArm64",
        ("aarch64", "android") => "androidArm64",
        ("x86_64", "android") => "androidX86_64",
        _ => fail(&["unsupported native Barretenberg target ", target.as_str()]),
    }
}

fn read_env_string(name: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => fail(&["missing required environment variable ", name]),
    }
}

fn stage_pinned_barretenberg_library(
    manifest_dir: &Path,
    library_path: &Path,
    output_directory: &Path,
    target_key: &str,
) {
    let metadata = match fs::symlink_metadata(library_path) {
        Ok(metadata) => metadata,
        Err(_) => fail(&["Barretenberg static library is unavailable"]),
    };
    if metadata.file_type().is_symlink() {
        fail(&["Barretenberg static library path must not be a symlink"]);
    }
    if !metadata.is_file() {
        fail(&["Barretenberg static library path is not a file"]);
    }

    let lock_path = manifest_dir.join(TOOLCHAIN_LOCK_RELATIVE_PATH);
    let lock = read_json(&lock_path);
    let expected = static_library_identity(&lock, target_key);
    if expected.file_name != LIBBB_FILE_NAME {
        fail(&["Barretenberg static library file name drifted"]);
    }
    if metadata.len() != expected.size {
        fail(&["Barretenberg static library size mismatch"]);
    }
    // The linker must read the exact bytes that passed the digest check. A
    // caller-controlled archive path can change after build-script admission.
    let staged_path = output_directory.join(LIBBB_FILE_NAME);
    match fs::remove_file(&staged_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => fail(&["unable to replace staged Barretenberg static library"]),
    }
    let source = match fs::File::open(library_path) {
        Ok(source) => source,
        Err(_) => fail(&["unable to open Barretenberg static library"]),
    };
    let opened_metadata = match source.metadata() {
        Ok(metadata) => metadata,
        Err(_) => fail(&["unable to inspect Barretenberg static library"]),
    };
    if !opened_metadata.is_file() || opened_metadata.len() != expected.size {
        fail(&["Barretenberg static library size mismatch"]);
    }
    let mut staged = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_path)
    {
        Ok(staged) => staged,
        Err(_) => fail(&["unable to create staged Barretenberg static library"]),
    };
    let copy_limit = match expected.size.checked_add(1) {
        Some(limit) => limit,
        None => fail(&["Barretenberg static library size overflow"]),
    };
    let copied = match io::copy(&mut source.take(copy_limit), &mut staged) {
        Ok(copied) => copied,
        Err(_) => fail(&["unable to stage Barretenberg static library"]),
    };
    if copied != expected.size || staged.sync_all().is_err() {
        fail(&["staged Barretenberg static library size mismatch"]);
    }
    drop(staged);
    let digest = sha256_file(&staged_path);
    if digest != expected.sha256 && expected.linux_source_sha256.as_deref() != Some(digest.as_str())
    {
        fail(&["Barretenberg static library SHA-256 mismatch"]);
    }
}

fn read_json(lock_path: &Path) -> Value {
    let bytes = match fs::read(lock_path) {
        Ok(bytes) => bytes,
        Err(_) => fail(&["unable to read toolchain lock"]),
    };
    match serde_json::from_slice(bytes.as_slice()) {
        Ok(value) => value,
        Err(_) => fail(&["toolchain lock is not valid JSON"]),
    }
}

struct StaticLibraryIdentity {
    file_name: String,
    size: u64,
    sha256: String,
    linux_source_sha256: Option<String>,
}

fn static_library_identity(lock: &Value, target_key: &str) -> StaticLibraryIdentity {
    let Some(barretenberg) = lock
        .get("candidateMatchedPair")
        .and_then(|value| value.get("barretenberg"))
    else {
        fail(&["toolchain lock is missing Barretenberg identity"]);
    };
    let Some(identity) = barretenberg
        .get("linkableStaticLibraries")
        .and_then(|value| value.get(target_key))
        .or_else(|| {
            barretenberg
                .get("extractedStaticLibraries")
                .and_then(|value| value.get(target_key))
        })
    else {
        fail(&["toolchain lock is missing linkable static library identity"]);
    };

    let file_name = json_string(identity, "fileName");
    let sha256 = json_string(identity, "sha256");
    let Some(size) = identity.get("size").and_then(Value::as_u64) else {
        fail(&["toolchain lock static library size is invalid"]);
    };
    // Android NDK host optimizations change compiler comments, while every
    // other byte matches the reviewed Darwin archive. Admit only the second
    // complete digest, never an archive with merely equivalent symbols.
    let linux_source_sha256 = match identity.get("linuxSourceBuild") {
        Some(linux) if target_key == "androidArm64" => {
            if linux.get("size").and_then(Value::as_u64) != Some(size) {
                fail(&["Linux Android static library size drifted"]);
            }
            Some(json_string(linux, "sha256"))
        }
        Some(_) => fail(&["unexpected Linux source archive identity"]),
        None => None,
    };
    StaticLibraryIdentity {
        file_name,
        size,
        sha256,
        linux_source_sha256,
    }
}

fn json_string(value: &Value, key: &str) -> String {
    match value.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => fail(&["toolchain lock string value is invalid"]),
    }
}

fn sha256_file(path: &Path) -> String {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => fail(&["unable to read Barretenberg static library"]),
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => fail(&["unable to hash Barretenberg static library"]),
        };
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    hex_lower(hasher.finalize().as_slice())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::new();
    let capacity = match bytes.len().checked_mul(2) {
        Some(capacity) => capacity,
        None => fail(&["digest text length overflow"]),
    };
    if encoded.try_reserve_exact(capacity).is_err() {
        fail(&["unable to allocate digest text"]);
    }
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn compile_shim_from_source(manifest_dir: &Path) {
    let source = manifest_dir.join("native/reallyme_bbapi_shim.cc");
    let include = manifest_dir.join("native");
    let mut build = cc::Build::new();
    // The pinned Linux archive uses LLVM's C++ ABI. Compile the exception
    // boundary with the same standard library so caught exceptions agree.
    if read_env_string("CARGO_CFG_TARGET_OS") == "linux" {
        build.cpp_set_stdlib("c++");
    }
    build
        .cpp(true)
        .std("c++17")
        .warnings(true)
        .warnings_into_errors(true)
        .flag_if_supported("-fvisibility=hidden")
        .include(include)
        .file(source)
        .compile("reallyme_bbapi_shim");
}

fn emit_static_link(path: &Path, library: &str) {
    println!("cargo:rustc-link-search=native={}", path.display());
    println!("cargo:rustc-link-lib=static={library}");
}

fn emit_runtime_links(target_os: &str) {
    match target_os {
        "android" => println!("cargo:rustc-link-lib=c++_shared"),
        "ios" | "macos" => println!("cargo:rustc-link-lib=c++"),
        "linux" => {
            println!("cargo:rustc-link-lib=c++");
            println!("cargo:rustc-link-lib=c++abi");
        }
        _ => fail(&["unsupported native Barretenberg runtime target"]),
    }
    println!("cargo:rustc-link-lib=z");
}

fn fail(parts: &[&str]) -> ! {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(b"reallyme-zk-backend-bb build failed: ");
    for part in parts {
        let _ = stderr.write_all(part.as_bytes());
    }
    let _ = stderr.write_all(b"\n");
    process::exit(1);
}
