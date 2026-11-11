// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs::OpenOptions,
    io::{Error, ErrorKind, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    finish_new_secret_write, read_bounded_secret_utf8, read_secret_bytes, write_new_secret,
};
use crate::{CliError, CliErrorReason};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> PathBuf {
    let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "reallyme-zk-cli-secret-{}-{serial}",
        std::process::id()
    ))
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn secret_read_enforces_limit_without_buffer_growth() {
    let path = unused_path();
    std::fs::write(&path, b"abc").expect("test fixture write");
    let bytes = read_secret_bytes(&path, 3).expect("bounded secret read");
    assert_eq!(bytes.as_slice(), b"abc");
    assert!(bytes.capacity() >= 4);
    assert_eq!(
        read_secret_bytes(&path, 2),
        Err(CliError::new(CliErrorReason::InputTooLarge))
    );
    std::fs::remove_file(path).expect("test fixture cleanup");
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn secret_utf8_read_rejects_invalid_bytes() {
    let path = unused_path();
    std::fs::write(&path, [0xff]).expect("test fixture write");
    assert_eq!(
        read_bounded_secret_utf8(&path, 4),
        Err(CliError::new(CliErrorReason::InvalidInput))
    );
    std::fs::remove_file(path).expect("test fixture cleanup");
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn secret_output_is_exclusive_and_private() {
    let path = unused_path();
    write_new_secret(&path, b"first").expect("create secret output");
    assert_eq!(
        write_new_secret(&path, b"second"),
        Err(CliError::new(CliErrorReason::OutputAlreadyExists))
    );
    assert_eq!(std::fs::read(&path).expect("read test output"), b"first");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&path)
            .expect("secret output metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    std::fs::remove_file(path).expect("test fixture cleanup");
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn failed_secret_write_removes_owned_partial_output() {
    let path = unused_path();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create test output");
    let result = finish_new_secret_write(&path, file, |output| {
        output.write_all(b"partial")?;
        Err(Error::from(ErrorKind::BrokenPipe))
    });
    assert_eq!(result, Err(CliError::new(CliErrorReason::IoUnavailable)));
    #[cfg(unix)]
    assert!(!path.exists());
    #[cfg(not(unix))]
    {
        assert_eq!(
            std::fs::metadata(&path)
                .expect("empty output metadata")
                .len(),
            0
        );
        std::fs::remove_file(path).expect("test fixture cleanup");
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn failed_secret_write_preserves_replacement_path() {
    let path = unused_path();
    let moved = unused_path();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create test output");
    let result = finish_new_secret_write(&path, file, |output| {
        output.write_all(b"partial")?;
        std::fs::rename(&path, &moved)?;
        std::fs::write(&path, b"replacement")?;
        Err(Error::from(ErrorKind::BrokenPipe))
    });
    assert_eq!(result, Err(CliError::new(CliErrorReason::IoUnavailable)));
    assert_eq!(
        std::fs::read(&path).expect("read replacement"),
        b"replacement"
    );
    assert_eq!(
        std::fs::metadata(&moved).expect("read owned output").len(),
        0
    );
    std::fs::remove_file(path).expect("replacement cleanup");
    std::fs::remove_file(moved).expect("owned output cleanup");
}
