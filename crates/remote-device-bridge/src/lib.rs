//! Safety coordinator for a single remote USB attachment.

pub mod usbredir;

use remote_device_protocol::{
    AttachmentState, MAX_OUTSTANDING, MAX_QUEUED_BYTES, UsbRequest, transition,
};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum BridgeError {
    #[error("attachment is not active")]
    NotActive,
    #[error("request id is already in use")]
    DuplicateRequest,
    #[error("request is stale")]
    StaleGeneration,
    #[error("queue limits exceeded")]
    QueueFull,
    #[error("invalid lifecycle transition: {0}")]
    Lifecycle(#[from] remote_device_protocol::ProtocolError),
}

pub struct Attachment {
    state: AttachmentState,
    generation: u64,
    outstanding: HashSet<u64>,
    queued_bytes: usize,
}

impl Attachment {
    pub fn new() -> Self {
        Self {
            state: AttachmentState::Reserved,
            generation: 1,
            outstanding: HashSet::new(),
            queued_bytes: 0,
        }
    }
    pub fn state(&self) -> AttachmentState {
        self.state
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn set_state(&mut self, next: AttachmentState) -> Result<(), BridgeError> {
        transition(self.state, next)?;
        self.state = next;
        Ok(())
    }
    pub fn submit(&mut self, request: &UsbRequest) -> Result<(), BridgeError> {
        request.validate().map_err(BridgeError::Lifecycle)?;
        if request.generation != self.generation {
            return Err(BridgeError::StaleGeneration);
        }
        if self.state != AttachmentState::Active {
            return Err(BridgeError::NotActive);
        }
        if self.outstanding.len() >= MAX_OUTSTANDING
            || self.queued_bytes.saturating_add(request.payload.len()) > MAX_QUEUED_BYTES
        {
            return Err(BridgeError::QueueFull);
        }
        if !self.outstanding.insert(request.request_id) {
            return Err(BridgeError::DuplicateRequest);
        }
        self.queued_bytes += request.payload.len();
        Ok(())
    }
    pub fn complete(&mut self, generation: u64, request_id: u64, bytes: usize) -> bool {
        if generation != self.generation || !self.outstanding.remove(&request_id) {
            return false;
        }
        self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
        true
    }
    /// Retire all work. Late browser completions are rejected by generation.
    pub fn retire(&mut self) -> Result<u64, BridgeError> {
        if matches!(
            self.state,
            AttachmentState::Active | AttachmentState::Connecting
        ) {
            self.set_state(AttachmentState::Draining)?;
        }
        self.outstanding.clear();
        self.queued_bytes = 0;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(BridgeError::StaleGeneration)?;
        Ok(self.generation)
    }
}

impl Default for Attachment {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_device_protocol::UsbTransferType;
    fn request(generation: u64, id: u64) -> UsbRequest {
        UsbRequest {
            attachment_id: "a".into(),
            generation,
            request_id: id,
            interface: 0,
            endpoint: 1,
            direction_in: false,
            transfer_type: UsbTransferType::Bulk,
            deadline_ms: 100,
            setup: None,
            payload: vec![1],
            in_length: 0,
        }
    }
    #[test]
    fn retirement_drops_late_completion_and_requires_fresh_generation() {
        let mut a = Attachment::new();
        a.set_state(AttachmentState::Connecting).unwrap();
        a.set_state(AttachmentState::Active).unwrap();
        a.submit(&request(1, 7)).unwrap();
        let generation = a.retire().unwrap();
        assert!(!a.complete(1, 7, 1));
        assert_eq!(a.submit(&request(1, 8)), Err(BridgeError::StaleGeneration));
        assert_eq!(a.state(), AttachmentState::Draining);
        assert_eq!(generation, 2);
    }
}
