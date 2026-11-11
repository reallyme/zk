// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Static policy checks for the native Barretenberg build script.

use std::{fs, io, path::PathBuf};

#[test]
fn native_build_script_uses_target_runtime_policy() -> io::Result<()> {
    let source = build_script_source()?;

    assert!(!source.contains("cfg!(target_os"));
    assert!(source.contains("emit_runtime_links(target_os.as_str())"));
    assert!(source.contains("\"android\" => println!(\"cargo:rustc-link-lib=c++_shared\")"));
    assert!(source.contains("\"ios\" | \"macos\" => println!(\"cargo:rustc-link-lib=c++\")"));
    assert!(source.contains("build.cpp_set_stdlib(\"c++\")"));
    assert!(source.contains("cargo:rustc-link-lib=c++abi"));
    assert!(!source.contains("cargo:rustc-link-lib=stdc++"));
    Ok(())
}

#[test]
fn native_build_script_streams_and_rejects_symlinked_archives() -> io::Result<()> {
    let source = build_script_source()?;

    assert!(source.contains("fs::symlink_metadata"));
    assert!(source.contains("is_symlink()"));
    assert!(source.contains("BufReader::new"));
    assert!(source.contains(".checked_mul(2)"));
    assert!(!source.contains("fs::read(path)"));
    assert!(!source.contains("saturating_mul(2)"));
    Ok(())
}

#[test]
fn native_build_script_names_android_emulator_lane_explicitly() -> io::Result<()> {
    let source = build_script_source()?;

    assert!(source.contains("(\"x86_64\", \"android\") => \"androidX86_64\""));
    assert!(source.contains("(\"aarch64\", \"android\") => \"androidArm64\""));
    assert!(source.contains("(\"x86_64\", \"macos\") => \"darwinX86_64\""));
    assert!(source.contains("(\"aarch64\", \"macos\") => \"darwinArm64\""));
    assert!(source.contains("(\"x86_64\", \"linux\") => \"linuxAmd64\""));
    Ok(())
}

fn build_script_source() -> io::Result<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("build.rs");
    fs::read_to_string(path)
}
