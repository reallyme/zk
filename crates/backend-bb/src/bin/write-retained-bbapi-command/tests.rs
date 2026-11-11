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
    finish_new_secret_write, read_bounded_zeroizing, write_new_secret, RetainedCommandErrorReason,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> PathBuf {
    let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "reallyme-zk-retained-command-{}-{serial}",
        std::process::id()
    ))
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn witness_read_is_bounded_before_and_after_io() {
    let path = unused_path();
    std::fs::write(&path, b"abc").expect("test fixture write");
    let bytes = read_bounded_zeroizing(path.clone(), 3).expect("bounded witness read");
    assert_eq!(bytes.as_slice(), b"abc");
    assert!(bytes.capacity() >= 4);
    let result = read_bounded_zeroizing(path.clone(), 2);
    assert!(matches!(
        result,
        Err(error) if error.reason == RetainedCommandErrorReason::InvalidArguments
    ));
    std::fs::remove_file(path).expect("test fixture cleanup");
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup failures must fail this test immediately.
fn command_output_is_exclusive_and_private() {
    let path = unused_path();
    write_new_secret(&path, b"first").expect("create secret output");
    let result = write_new_secret(&path, b"second");
    assert!(matches!(
        result,
        Err(error)
            if error.reason
                == RetainedCommandErrorReason::Filesystem(std::io::ErrorKind::AlreadyExists)
    ));
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
fn failed_command_write_clears_owned_partial_output() {
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
    assert!(matches!(
        result,
        Err(error)
            if error.reason == RetainedCommandErrorReason::Filesystem(ErrorKind::BrokenPipe)
    ));
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
fn failed_command_write_preserves_replacement_path() {
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
    assert!(matches!(
        result,
        Err(error)
            if error.reason == RetainedCommandErrorReason::Filesystem(ErrorKind::BrokenPipe)
    ));
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
