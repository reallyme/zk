// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_proto_codec::platform_abi::{
    ReallyMeZkPlatformStatus, REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
    REALLYME_ZK_PLATFORM_STATUS_OK,
};

use crate::{context::PlatformContext, ffi::ReallyMeZkPlatformContext};

pub(crate) struct ContextEntry {
    inner: PlatformContext,
}

impl ContextEntry {
    pub(crate) const fn inner(&self) -> &PlatformContext {
        &self.inner
    }
}

#[derive(Default)]
struct ContextRegistry {
    entries: HashMap<usize, Arc<ContextEntry>>,
}

static CONTEXT_REGISTRY: OnceLock<Mutex<ContextRegistry>> = OnceLock::new();
static NEXT_CONTEXT_ID: AtomicUsize = AtomicUsize::new(1);

pub(crate) fn insert_context(
    inner: PlatformContext,
) -> Result<*mut ReallyMeZkPlatformContext, ZkError> {
    let id = next_context_id()?;
    let entry = Arc::new(ContextEntry { inner });
    let mut registry = context_registry()
        .lock()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    registry
        .entries
        .try_reserve(1)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    if registry.entries.insert(id, entry).is_some() {
        return Err(ZkError::new(ZkErrorReason::BackendFailure));
    }
    Ok(id_to_context(id))
}

pub(crate) fn get_context(
    context: *mut ReallyMeZkPlatformContext,
) -> Result<Arc<ContextEntry>, ZkError> {
    if context.is_null() {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let id = context_id(context);
    let registry = context_registry()
        .lock()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    registry
        .entries
        .get(&id)
        .cloned()
        .ok_or(ZkError::new(ZkErrorReason::BackendUnavailable))
}

pub(crate) fn destroy_context(context: *mut ReallyMeZkPlatformContext) -> ReallyMeZkPlatformStatus {
    if context.is_null() {
        return status_ok();
    }
    let id = context_id(context);
    let registry = match context_registry().lock() {
        Ok(registry) => registry,
        Err(_) => {
            return ReallyMeZkPlatformStatus {
                status_code: REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
                error_reason_code: ZkErrorReason::BackendFailure.reason_code(),
            };
        }
    };
    remove_context(registry, id)
}

fn remove_context(
    mut registry: std::sync::MutexGuard<'static, ContextRegistry>,
    id: usize,
) -> ReallyMeZkPlatformStatus {
    if registry.entries.remove(&id).is_some() {
        status_ok()
    } else {
        ReallyMeZkPlatformStatus {
            status_code: REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT,
            error_reason_code: ZkErrorReason::BackendUnavailable.reason_code(),
        }
    }
}

fn context_registry() -> &'static Mutex<ContextRegistry> {
    CONTEXT_REGISTRY.get_or_init(|| Mutex::new(ContextRegistry::default()))
}

fn next_context_id() -> Result<usize, ZkError> {
    loop {
        let current = NEXT_CONTEXT_ID.load(Ordering::Relaxed);
        if current == 0 {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        let next = current
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::ResourceExhausted))?;
        if NEXT_CONTEXT_ID
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(current);
        }
    }
}

fn id_to_context(id: usize) -> *mut ReallyMeZkPlatformContext {
    id as *mut ReallyMeZkPlatformContext
}

fn context_id(context: *mut ReallyMeZkPlatformContext) -> usize {
    context as usize
}

const fn status_ok() -> ReallyMeZkPlatformStatus {
    ReallyMeZkPlatformStatus {
        status_code: REALLYME_ZK_PLATFORM_STATUS_OK,
        error_reason_code: 0,
    }
}
