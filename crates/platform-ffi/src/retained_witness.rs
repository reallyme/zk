// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkWitness,
};

pub(crate) const MAX_RETAINED_STAGE_WITNESSES: usize = 16;
static NEXT_WITNESS_HANDLE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct RetainedStageWitness {
    handle_id: u64,
    circuit_ref: ZkCircuitRef,
    witness: ZkWitness,
}

pub(crate) struct RetainedStageWitnessStore {
    witnesses: Mutex<Vec<RetainedStageWitness>>,
}

impl RetainedStageWitnessStore {
    pub(crate) const fn new() -> Self {
        Self {
            witnesses: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn retain(
        &self,
        circuit_ref: ZkCircuitRef,
        witness: ZkWitness,
    ) -> Result<u64, ZkError> {
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        if witnesses.len() >= MAX_RETAINED_STAGE_WITNESSES {
            return Err(ZkError::new(ZkErrorReason::ResourceExhausted));
        }
        let handle_id = NEXT_WITNESS_HANDLE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    None
                } else {
                    current.checked_add(1).filter(|next| *next != 0)
                }
            })
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        if handle_id == 0 {
            return Err(ZkError::new(ZkErrorReason::ResourceExhausted));
        }
        witnesses.push(RetainedStageWitness {
            handle_id,
            circuit_ref,
            witness,
        });
        Ok(handle_id)
    }

    pub(crate) fn take(
        &self,
        handle_id: u64,
        circuit_ref: ZkCircuitRef,
    ) -> Result<ZkWitness, ZkError> {
        if handle_id == 0 {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        let index = retained_witness_index(&witnesses, handle_id, circuit_ref)?;
        Ok(witnesses.remove(index).witness)
    }

    pub(crate) fn take_ordered(
        &self,
        handles: &[(u64, ZkCircuitRef)],
    ) -> Result<Vec<ZkWitness>, ZkError> {
        validate_requested_handles(handles)?;
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        let mut removal_indices = Vec::new();
        removal_indices
            .try_reserve_exact(handles.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        let mut removed = Vec::new();
        removed
            .try_reserve_exact(handles.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(handles.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;

        for (request_index, (handle_id, circuit_ref)) in handles.iter().copied().enumerate() {
            let retained_index = retained_witness_index(&witnesses, handle_id, circuit_ref)?;
            removal_indices.push((request_index, retained_index));
        }

        removal_indices
            .sort_by_key(|(_request_index, retained_index)| std::cmp::Reverse(*retained_index));
        for (request_index, retained_index) in removal_indices {
            removed.push((request_index, witnesses.remove(retained_index).witness));
        }
        removed.sort_by_key(|(request_index, _witness)| *request_index);
        for (_request_index, witness) in removed {
            ordered.push(witness);
        }
        Ok(ordered)
    }

    pub(crate) fn take_ordered_or_release_present(
        &self,
        handles: &[(u64, ZkCircuitRef)],
    ) -> Result<Vec<ZkWitness>, ZkError> {
        match self.take_ordered(handles) {
            Ok(witnesses) => Ok(witnesses),
            Err(error) => {
                let _cleanup_result = self.release_present(handles);
                Err(error)
            }
        }
    }

    pub(crate) fn release(&self, handle_id: u64, circuit_ref: ZkCircuitRef) -> Result<(), ZkError> {
        if handle_id == 0 {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        let index = retained_witness_index(&witnesses, handle_id, circuit_ref)?;
        let _released = witnesses.remove(index);
        Ok(())
    }

    pub(crate) fn release_present(&self, handles: &[(u64, ZkCircuitRef)]) -> Result<(), ZkError> {
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
        let mut index = 0_usize;
        while index < handles.len() {
            let (handle_id, circuit_ref) = handles[index];
            if handle_id != 0 {
                if let Some(retained_index) = witnesses.iter().position(|witness| {
                    witness.handle_id == handle_id && witness.circuit_ref == circuit_ref
                }) {
                    let _released = witnesses.remove(retained_index);
                }
            }
            index = index
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
        Ok(())
    }
}

fn validate_requested_handles(handles: &[(u64, ZkCircuitRef)]) -> Result<(), ZkError> {
    for (handle_id, _circuit_ref) in handles {
        if *handle_id == 0 {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }
    }
    let mut index = 0_usize;
    while index < handles.len() {
        let mut comparison = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        while comparison < handles.len() {
            if handles[index].0 == handles[comparison].0
                || handles[index].1 == handles[comparison].1
            {
                return Err(ZkError::new(ZkErrorReason::DuplicateStage));
            }
            comparison = comparison
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
        index = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    Ok(())
}

fn retained_witness_index(
    witnesses: &[RetainedStageWitness],
    handle_id: u64,
    circuit_ref: ZkCircuitRef,
) -> Result<usize, ZkError> {
    witnesses
        .iter()
        .position(|witness| witness.handle_id == handle_id && witness.circuit_ref == circuit_ref)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))
}
