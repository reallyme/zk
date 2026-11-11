// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use super::SourceTree;
use crate::{ReleaseAssemblyError, ReleaseAssemblyErrorReason};

impl SourceTree {
    pub(crate) fn contains_path(&self, path: &Path) -> bool {
        self.files.iter().any(|file| file.relative_path == path)
    }

    pub(crate) fn mutate_first_byte(&mut self, path: &Path) -> Result<(), ReleaseAssemblyError> {
        let file = self
            .files
            .iter_mut()
            .find(|file| file.relative_path == path)
            .ok_or(ReleaseAssemblyError::new(
                ReleaseAssemblyErrorReason::InvalidPath,
            ))?;
        let first = file.contents.first_mut().ok_or(ReleaseAssemblyError::new(
            ReleaseAssemblyErrorReason::InvalidPath,
        ))?;
        *first ^= 1;
        Ok(())
    }
}
