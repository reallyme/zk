// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable publication boundary for one ReallyMe active-root status feed.

// Secure publication relies on Unix descriptor-relative filesystem operations.
// Keeping the complete surface target-gated prevents browser and non-Unix builds
// from exposing an authority API that cannot uphold the same filesystem policy.
#[cfg(unix)]
mod anchor;
#[cfg(unix)]
mod intent;
#[cfg(unix)]
mod publisher;
#[cfg(unix)]
mod secure_files;

#[cfg(unix)]
pub use anchor::{RootStatusAnchorValue, RootStatusFeedId, RootStatusSequenceAnchor};

#[cfg(unix)]
pub use publisher::{
    RootStatusPublicationStore, RootStatusPublisherError, RootStatusPublisherReason,
    RootStatusSigner,
};
