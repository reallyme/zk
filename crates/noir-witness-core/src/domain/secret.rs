// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

pub struct SecretInputs<T: Zeroize> {
    inner: SecretBox<T>,
}

impl<T: Zeroize> SecretInputs<T> {
    pub fn new(value: T) -> Self {
        Self {
            inner: SecretBox::new(Box::new(value)),
        }
    }

    pub(crate) fn expose(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize> std::fmt::Debug for SecretInputs<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretInputs([REDACTED])")
    }
}
